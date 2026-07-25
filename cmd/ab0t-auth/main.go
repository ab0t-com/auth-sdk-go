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
	"errors"
	"flag"
	"fmt"
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
}

func (g *globals) register(fs *flag.FlagSet) {
	fs.StringVar(&g.server, "server", "", "Auth service base URL (default: the production service)")
	fs.StringVar(&g.token, "token", "", "Credential to use; overrides $AB0T_AUTH_TOKEN and the stored one")
	fs.BoolVar(&g.json, "json", false, "Emit JSON instead of text (stable shape; use this in scripts)")
	fs.BoolVar(&g.quiet, "quiet", false, "Suppress non-essential output; errors still go to stderr")
	fs.BoolVar(&g.color, "color", false, "Force colour even when not a terminal")
	fs.BoolVar(&g.noColor, "no-color", false, "Disable colour entirely (same as NO_COLOR=1)")
	fs.DurationVar(&g.timeout, "timeout", defaultTimeo, "Overall timeout for the request")
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
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage(stdout, args)
		return exitOK
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintf(stdout, "ab0t-auth %s\n", auth.Version)
		return exitOK
	}

	name := args[0]
	cmd := lookup(name)
	if cmd == nil {
		o := newOutput(stdout, stderr, false, false, false, false)
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
	fs.Usage = func() {
		fmt.Fprintf(stderr, "%s\n\nUsage:\n  ab0t-auth %s\n\nFlags:\n", cmd.summary, cmd.usage)
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
	cred := resolveCredential(g.token)

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
		return exitOK
	case errors.Is(err, errDenied):
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

func lookup(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

func usage(w *os.File, args []string) {
	fmt.Fprintf(w, `ab0t-auth %s — command-line client for the ab0t Auth Service

Usage:
  ab0t-auth <command> [flags]

Commands:
`, auth.Version)
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
Global flags (accepted by every command):
  --server URL     auth service base URL (default: the production service)
  --token VALUE    credential to use; overrides $AB0T_AUTH_TOKEN and the stored one
  --json           emit JSON with a stable shape — use this in scripts
  --quiet          suppress non-essential output
  --no-color       disable colour (NO_COLOR=1 does the same)
  --timeout DUR    overall request timeout (default 30s)

Credential precedence:
  --token  >  $AB0T_AUTH_TOKEN  >  $AUTH_SERVICE_KEY  >  stored file

Exit codes:
  0 success (for 'can': ALLOWED)   2 DENIED
  1 error                          3 no credential, or it was rejected

Examples:
  ab0t-auth login --email you@example.com
  ab0t-auth whoami
  ab0t-auth can user:alice view doc:123 --store my-store
  ab0t-auth doctor

Colour is never the only signal: every state is also a word, so piping,
NO_COLOR and screen readers lose nothing.
`)
}
