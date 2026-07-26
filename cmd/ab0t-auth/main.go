// Command ab0t-auth is a command-line client for the ab0t Auth Service.
//
// It answers, from a terminal, the questions that otherwise need a Go program:
// is this token valid, who am I, can alice read this document, why not, is the
// service up, and what is wrong with my configuration.
//
//	go install github.com/ab0t-com/auth-sdk-go/cmd/ab0t-auth@latest
//
// # No dependencies, on purpose
//
// The SDK this ships from is standard-library-only, and that is enforced in CI
// because it gets embedded in other people's binaries. A CLI would normally reach
// for cobra; that would add cobra and pflag to the module and break the guarantee
// for every consumer, none of whom asked for a CLI. So subcommand dispatch is
// written by hand against the stdlib `flag` package. It costs about sixty lines
// and `go install` pulls exactly nothing else.
//
// # Accessibility
//
// Output rules live in output.go and are enforced there rather than at each call
// site. In short: NO_COLOR means no ANSI at all, colour is never the only signal,
// data goes to stdout and diagnostics to stderr, --json works everywhere, and
// there are no spinners, progress bars or redrawing anywhere — they are hostile
// to screen readers and turn a CI log into escape sequences.
//
// # Exit codes
//
//	0  success (for `can`, also: the answer was ALLOWED)
//	1  a general error — bad usage, network failure, service error
//	2  the answer was DENIED (so `if ab0t-auth can …; then` works in a script)
//	3  no credential, or the credential was rejected
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	auth "github.com/ab0t-com/auth-sdk-go"
)

const (
	exitOK       = 0
	exitError    = 1
	exitDenied   = 2
	exitNoAuth   = 3
	defaultTimeo = 30 * time.Second
)

// globals are the flags every subcommand accepts.
type globals struct {
	server  string
	token   string
	json    bool
	quiet   bool
	color   bool
	noColor bool
	timeout time.Duration
	profile string
}

func (g *globals) register(fs *flag.FlagSet) {
	fs.StringVar(&g.server, "server", "", "Auth service base URL (default: the production service)")
	fs.StringVar(&g.token, "token", "", "Credential to use; overrides $AB0T_AUTH_TOKEN and the stored one")
	fs.BoolVar(&g.json, "json", false, "Emit JSON instead of text (stable shape; use this in scripts)")
	fs.BoolVar(&g.quiet, "quiet", false, "Suppress non-essential output; errors still go to stderr")
	fs.BoolVar(&g.color, "color", false, "Force colour even when not a terminal")
	fs.BoolVar(&g.noColor, "no-color", false, "Disable colour entirely (same as NO_COLOR=1)")
	fs.DurationVar(&g.timeout, "timeout", defaultTimeo, "Overall timeout for the request")
	fs.StringVar(&g.profile, "profile", "", "Tenant profile to use (or $AB0T_PROFILE); see 'ab0t-auth profile'")
}

// command is one subcommand.
//
// flags lets a command register its OWN flags on the shared FlagSet and returns
// an opaque options value handed back to run. Parsing per-command flags by hand
// from the residual args does not work: flag.Parse rejects an unknown flag before
// the command ever sees it, which is exactly the bug the first end-to-end run
// found ("flag provided but not defined: -key").
type command struct {
	name    string
	summary string
	usage   string
	flags   func(fs *flag.FlagSet) any
	run     func(ctx context.Context, env *env, opts any, args []string) error
}

// env is everything a subcommand needs, resolved once.
type env struct {
	g    *globals
	out  *output
	cred Credential
	// client is built lazily so commands that need no network (help, version)
	// never construct one.
	client func() *auth.Client
}

// denied is returned by `can` when the answer is a legitimate DENY, so main can
// map it to exit code 2 without treating it as an error.
var errDenied = errors.New("denied")

// errNoCredential is returned when a command needs a credential and none exists.
var errNoCredential = errors.New("no credential")

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	// Hoist leading global flags FIRST, before the help/version special cases:
	// otherwise `ab0t-auth --json version` leaves `version` in a position those
	// cases never inspect, and it falls through to lookup(), which does not know
	// about it. Caught by the clean-room check at v0.7.0.
	args = hoistLeadingFlags(args)

	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		// `help <verb>` must answer about THAT verb. Printing the generic page
		// with exit 0 — which is what this did before the journey review — tells
		// the customer their question succeeded while answering a different one.
		// help --json: the capability list as data (UJ-A02).
		for _, a := range args {
			if a == "--json" || a == "-json" {
				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				if len(args) > 1 && lookup(args[1]) != nil {
					h := buildHelpJSON(auth.Version)
					for _, c := range h.Commands {
						if c.Name == args[1] {
							_ = enc.Encode(c)
							return exitOK
						}
					}
				}
				_ = enc.Encode(buildHelpJSON(auth.Version))
				return exitOK
			}
		}
		if len(args) > 1 {
			o := newOutput(stdout, stderr, false, false, false, false)
			if lookup(args[1]) == nil {
				o.errorf("unknown command %q", args[1])
				if sg := suggest(args[1]); sg != "" {
					o.hint("did you mean: ab0t-auth help " + sg)
				}
				return exitError
			}
			renderVerbHelp(stdout, args[1], o)
			return exitOK
		}
		usage(stdout, args)
		return exitOK
	}
	if args[0] == "version" || args[0] == "--version" {
		// --json is honoured here too: an agent pinning a version wants it
		// machine-readable without special-casing this one command.
		for _, a := range args[1:] {
			if a == "--json" || a == "-json" {
				fmt.Fprintf(stdout, "{\n  \"name\": \"ab0t-auth\",\n  \"version\": %q\n}\n", auth.Version)
				return exitOK
			}
		}
		fmt.Fprintf(stdout, "ab0t-auth %s\n", auth.Version)
		return exitOK
	}

	// Customers type `ab0t-auth --server X health`, because git, docker and kubectl
	// all accept global flags before the subcommand. The journey harness — written
	// by the same person who built this — made exactly that mistake on its first
	// run and got `unknown command "--server"`. If the author trips on it, a
	// customer certainly will. Hoist any leading flags so either order works.
	name := args[0]
	cmd := lookup(name)
	if cmd == nil {
		o := newOutput(stdout, stderr, false, false, false, false)
		if strings.HasPrefix(name, "-") {
			// Distinguish "you used a flag we do not have" from "you put a flag
			// where a command goes" — they need different corrections.
			o.errorf("%q is a flag, not a command", name)
			o.hint("global flags work before or after the command, but a command is required:")
			o.hint("  ab0t-auth <command> " + name + " …")
			o.hint("run 'ab0t-auth help' to see the commands")
			return exitError
		}
		o.errorf("unknown command %q", name)
		if s := suggest(name); s != "" {
			o.hint("did you mean: ab0t-auth " + s)
		}
		o.hint("run 'ab0t-auth help' for the list")
		return exitError
	}

	g := &globals{}
	fs := flag.NewFlagSet("ab0t-auth "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	g.register(fs)
	var opts any
	if cmd.flags != nil {
		opts = cmd.flags(fs)
	}
	// Both `help <verb>` and `<verb> --help` resolve to the same deep document.
	// Customers reach for both; neither is wrong, so neither may be worse.
	fs.Usage = func() {
		renderVerbHelp(stderr, name, newOutput(stderr, stderr, false, false, false, false))
		fmt.Fprintf(stderr, "\nFLAGS\n")
		fs.PrintDefaults()
	}
	// Go's flag package stops parsing at the first non-flag argument, so
	//     ab0t-auth can user:alice view doc:123 --store s1
	// would silently ignore --store. Every modern CLI accepts flags anywhere, and
	// requiring flags-first is both surprising and an accessibility cost: the
	// failure is silent and the recovery is non-obvious. Hoist flags to the front
	// before parsing.
	flags, positional := partitionArgs(fs, args[1:])
	if err := fs.Parse(flags); err != nil {
		return exitError
	}

	o := newOutput(stdout, stderr, g.color, g.noColor, g.json, g.quiet)
	cred := resolveCredential(g.token, g.profile)

	e := &env{g: g, out: o, cred: cred}
	e.client = func() *auth.Client {
		opts := []auth.Option{}
		if cred.Present() && cred.Kind == "api-key" {
			opts = append(opts, auth.WithAPIKey(cred.Value))
		}
		return auth.New(g.server, opts...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()

	switch err := cmd.run(ctx, e, opts, append(positional, fs.Args()...)); {
	case err == nil:
		nextSteps(o, name, true)
		return exitOK
	case errors.Is(err, errDenied):
		nextSteps(o, name, false)
		return exitDenied
	case errors.Is(err, errNoCredential):
		o.errorf("no credential")
		o.hint("run 'ab0t-auth login', or set $AB0T_AUTH_TOKEN, or pass --token")
		return exitNoAuth
	default:
		o.errorf("%v", err)
		explain(o, err)
		return exitError
	}
}

// explain turns a known error into a next step. An error that only says what
// failed leaves the user guessing; one that says what to do about it does not.
func explain(o *output, err error) {
	var apiErr *auth.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case 401:
			o.hint("the credential was rejected — run 'ab0t-auth login' to get a fresh one")
		case 403:
			o.hint("authenticated, but this credential lacks the required permission")
		case 404:
			o.hint("check the id in the command, and that --server points at the right service")
		case 429:
			o.hint("rate limited — wait and retry")
		case 500, 502, 503, 504:
			o.hint("the auth service is failing — run 'ab0t-auth health' to check, then retry")
		}
		if apiErr.RequestID != "" {
			o.hint("quote request id " + apiErr.RequestID + " in a bug report")
		}
		return
	}
	var untyped *auth.ErrUntypedID
	if errors.As(err, &untyped) {
		o.hint(`Zanzibar ids are "type:id" — try "user:alice" rather than "alice"`)
	}
	if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {
		o.hint("could not reach the auth service — check --server and your network")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		o.hint("timed out — raise it with --timeout, e.g. --timeout 60s")
	}
}

// suggest offers a correction for a mistyped command. Typo tolerance is a small
// kindness that matters most to people for whom typing is expensive.
func suggest(name string) string {
	best, bestD := "", 3 // only suggest if reasonably close
	for _, c := range commands {
		if d := editDistance(name, c.name); d < bestD {
			best, bestD = c.name, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(min(cur[j-1]+1, prev[j]+1), prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// partitionArgs splits argv into flags (with their values) and positionals, so
// flags may appear anywhere on the line.
//
// Whether a flag consumes the next argument is decided by asking the FlagSet
// itself: a boolean flag does not, everything else does. That keeps this correct
// automatically as flags are added, rather than depending on a hand-maintained
// list that will drift.
func partitionArgs(fs *flag.FlagSet, argv []string) (flags, positional []string) {
	// Boolean flags are self-contained ("-json"); others take a value ("-store s1").
	isBool := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			isBool[f.Name] = true
		}
	})

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			// Everything after "--" is positional, by convention.
			positional = append(positional, argv[i+1:]...)
			return flags, positional
		case strings.HasPrefix(a, "-") && len(a) > 1:
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				continue // "-store=s1" carries its own value
			}
			if !isBool[name] && i+1 < len(argv) {
				i++
				flags = append(flags, argv[i])
			}
		default:
			positional = append(positional, a)
		}
	}
	return flags, positional
}

// hoistLeadingFlags moves any flags that appear BEFORE the subcommand to after it,
// so `ab0t-auth --server X health` and `ab0t-auth health --server X` are the same
// command. Without this the first form fails with "unknown command", which is both
// wrong and unhelpful — the customer used a flag we do have, in a position we did
// not accept.
//
// Whether a leading flag consumes the next argument is decided from the globals
// FlagSet itself, so it stays correct as global flags are added.
func hoistLeadingFlags(args []string) []string {
	probe := flag.NewFlagSet("probe", flag.ContinueOnError)
	probe.SetOutput(io.Discard)
	(&globals{}).register(probe)
	isBool := map[string]bool{}
	probe.VisitAll(func(f *flag.Flag) {
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			isBool[f.Name] = true
		}
	})

	var leading []string
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") && len(args[i]) > 1 {
		name := strings.TrimLeft(args[i], "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		// Only hoist flags we recognise. An unknown leading flag is left in place
		// so it still produces an error rather than being silently swallowed.
		if _, known := isBool[name]; !known && probe.Lookup(name) == nil {
			break
		}
		leading = append(leading, args[i])
		if !isBool[name] && !strings.Contains(args[i], "=") && i+1 < len(args) {
			i++
			leading = append(leading, args[i])
		}
		i++
	}
	if len(leading) == 0 || i >= len(args) {
		return args
	}
	out := append([]string{args[i]}, args[i+1:]...)
	return append(out, leading...)
}

func lookup(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

// usage is the top-level page. It leads with WHAT THIS IS FOR and the ~10 things
// people actually do — not an alphabetical verb list.
//
// The journey review (pmm/02, UJ-01) found the old page answered "what can it do"
// and never "what is this for", so an evaluator who did not already know what an
// authorization service was learned nothing and left. Ordering is the teaching: a
// list sorted by name tells a first-time reader nothing about where to start.
func usage(w *os.File, args []string) {
	fmt.Fprintf(w, `ab0t-auth %s — ask and answer authorization questions from the command line.

Use it to check whether someone may do something ("can user:alice view doc:123"),
to see WHY that answer came back, to grant and revoke access, and to review who can
reach what. It talks to the ab0t Auth Service.

COMMON COMMANDS
`, auth.Version)
	cw := 0
	for _, c := range commonCommands {
		if len(c.cmd) > cw {
			cw = len(c.cmd)
		}
	}
	for _, c := range commonCommands {
		fmt.Fprintf(w, "  %-*s  %s\n", cw, c.cmd, c.why)
	}

	fmt.Fprintf(w, "\nNEW HERE?\n")
	fmt.Fprintf(w, "  1. ab0t-auth health              is the service up?  (no credential needed)\n")
	fmt.Fprintf(w, "  2. ab0t-auth login --key …       store a credential\n")
	fmt.Fprintf(w, "  3. ab0t-auth doctor              confirm everything is wired\n")
	fmt.Fprintf(w, "  4. ab0t-auth can user:alice view doc:123 --store S    ask your first question\n")
	fmt.Fprintf(w, "\n  Ids are typed: \"user:alice\", not \"alice\". A --store is the permissions\n")
	fmt.Fprintf(w, "  database for your app; set $AB0T_ZANZIBAR_STORE to avoid repeating it.\n")

	fmt.Fprintf(w, "\nALL COMMANDS\n")
	width := 0
	for _, c := range commands {
		if len(c.name) > width {
			width = len(c.name)
		}
	}
	for _, c := range commands {
		fmt.Fprintf(w, "  %-*s  %s\n", width, c.name, c.summary)
	}

	fmt.Fprintf(w, `
DEEP HELP
  ab0t-auth help <verb>     purpose, worked example, failure modes, what's next
  ab0t-auth <verb> --help   the same, plus the flag list

GLOBAL FLAGS (every command)
  --server URL   auth service base URL        --json      machine-readable output
  --token VALUE  credential to use            --quiet     suppress non-essential output
  --store STORE  Zanzibar store id            --no-color  disable colour (NO_COLOR=1 too)
  --timeout DUR  request timeout (30s)

CREDENTIAL PRECEDENCE
  --token  >  $AB0T_AUTH_TOKEN  >  $AUTH_SERVICE_KEY  >  stored file

EXIT CODES
  0 success (for 'can': ALLOWED)    2 DENIED
  1 error                           3 no credential, or it was rejected

Colour is never the only signal: every state is also a word, so piping, NO_COLOR
and screen readers lose nothing.
`)
}
