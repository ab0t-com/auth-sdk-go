package main

// output.go — every byte this CLI prints goes through here.
//
// ACCESSIBILITY IS THE POINT OF THIS FILE, not a later pass.
//
// A terminal program is read by more than a sighted human at an interactive
// prompt. It is read by screen readers, by CI log viewers, by `grep`, by someone
// on an 80-column SSH session, and by people who cannot distinguish red from
// green. Each of those breaks differently, and all of them break if output is
// assembled ad hoc at the call sites.
//
// The rules enforced here:
//
//  1. NO_COLOR (https://no-color.org) means NO ANSI AT ALL — not "less colour".
//     Its whole point is that a user can guarantee clean output; honouring it
//     partially is the same as not honouring it.
//  2. Colour is NEVER the only signal. Every state that has a colour also has a
//     word: "ALLOWED", "DENIED", "error:". Remove the colour and nothing is lost.
//     This serves colourblind users, screen readers, pipes and logs identically.
//  3. Not a terminal => no colour. Detected without a dependency (this module is
//     stdlib-only): a character device is a terminal, a pipe or file is not.
//  4. Data to stdout, diagnostics to stderr. So `cmd > out.json` yields data and
//     the human still sees the errors.
//  5. No spinners, no progress bars, no cursor movement, no redrawing, no box
//     drawing. A screen reader announces a redrawing line over and over; a CI log
//     fills with escape sequences. Output is append-only and readable line by line.
//  6. --json on everything. It is the same feature for a script and for a screen
//     reader user: a stable shape you do not have to see to parse.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// ANSI codes. Deliberately a tiny set: bold and three colours. A richer palette
// buys nothing here and each addition is another thing to get wrong on a light
// background.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiDim    = "\033[2m"
)

type output struct {
	out   io.Writer
	errw  io.Writer
	color bool
	jsonM bool
	quiet bool
}

// newOutput decides once whether colour is allowed, so no call site has to.
//
// Precedence, most authoritative first:
//
//	--no-color        explicit user intent for this run
//	NO_COLOR set      the standard; any non-empty value disables colour
//	not a TTY         piped or redirected: colour would corrupt the data
//	--color           explicit opt-in, overrides TTY detection (for CI that
//	                  renders ANSI, e.g. GitHub Actions)
//	TERM=dumb         a terminal that cannot render escapes
func newOutput(stdout, stderr io.Writer, forceColor, noColor, jsonMode, quiet bool) *output {
	o := &output{out: stdout, errw: stderr, jsonM: jsonMode, quiet: quiet}

	switch {
	case noColor:
		o.color = false
	case os.Getenv("NO_COLOR") != "":
		o.color = false
	case forceColor:
		o.color = true
	case os.Getenv("TERM") == "dumb":
		o.color = false
	default:
		o.color = isTerminal(stdout)
	}
	// JSON is consumed by a parser. An escape sequence inside it is corruption.
	if jsonMode {
		o.color = false
	}
	return o
}

// isTerminal reports whether w is a character device.
//
// Done with os.Stat rather than golang.org/x/term or go-isatty because this
// module is stdlib-only and one dependency for one syscall is a bad trade. A
// character device is a terminal; a pipe, a file or a socket is not.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func (o *output) paint(code, s string) string {
	if !o.color {
		return s
	}
	return code + s + ansiReset
}

// ---- structured emission ----

// emit prints a result. In --json mode it writes v as JSON; otherwise it calls
// human, which renders the same information as plain lines.
//
// Both paths must carry the SAME facts. If a field only appears in one, someone
// is getting a worse answer for the mode they chose — and it is usually the
// person who needed the other one.
func (o *output) emit(v any, human func()) error {
	if o.jsonM {
		enc := json.NewEncoder(o.out)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	if !o.quiet {
		human()
	}
	return nil
}

// kv prints aligned "key: value" lines.
//
// Deliberately not a bordered table. Box-drawing characters are announced
// individually by some screen readers, wrap badly under 80 columns, and turn a
// grep result into noise. "key: value" survives all three.
func (o *output) kv(pairs ...[2]string) {
	width := 0
	for _, p := range pairs {
		if len(p[0]) > width {
			width = len(p[0])
		}
	}
	for _, p := range pairs {
		fmt.Fprintf(o.out, "%-*s  %s\n", width+1, p[0]+":", p[1])
	}
}

// list prints one item per line — greppable, and read one item at a time.
func (o *output) list(items []string) {
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	for _, s := range sorted {
		fmt.Fprintln(o.out, s)
	}
}

func (o *output) printf(format string, a ...any) {
	if !o.quiet {
		fmt.Fprintf(o.out, format, a...)
	}
}

// ---- states: colour is decoration, the word is the signal ----

// verdict renders an allow/deny decision.
//
// The WORD carries the meaning. Colour is added on top for people who benefit
// from it and removed for everyone else with nothing lost. A green tick alone
// would be unreadable to a screen reader and ambiguous to a red-green colourblind
// user — roughly 1 in 12 men.
func (o *output) verdict(allowed bool) string {
	if allowed {
		return o.paint(ansiGreen, "ALLOWED")
	}
	return o.paint(ansiRed, "DENIED")
}

func (o *output) ok(msg string) { o.printf("%s %s\n", o.paint(ansiGreen, "OK"), msg) }
func (o *output) warn(msg string) {
	fmt.Fprintf(o.errw, "%s %s\n", o.paint(ansiYellow, "warning:"), msg)
}

// errorf writes a diagnostic to STDERR, never stdout, so that redirecting output
// to a file still shows the human what went wrong.
func (o *output) errorf(format string, a ...any) {
	fmt.Fprintf(o.errw, "%s %s\n", o.paint(ansiRed, "error:"), fmt.Sprintf(format, a...))
}

// hint prints an actionable next step. An error that says what to do next is the
// difference between a support ticket and a fix.
func (o *output) hint(msg string) {
	fmt.Fprintf(o.errw, "  %s\n", o.paint(ansiDim, msg))
}

func (o *output) heading(s string) {
	if o.quiet {
		return
	}
	fmt.Fprintf(o.out, "%s\n", o.paint(ansiBold, s))
}

// mask reduces a secret to something safe to display. Never print a credential in
// full: terminal scrollback, screen sharing, CI logs and bug reports all outlive
// the moment.
func mask(s string) string {
	if s == "" {
		return "(none)"
	}
	// Keep a recognisable prefix so a user can tell WHICH credential it is.
	if i := strings.Index(s, "_"); i > 0 && i < 12 && strings.HasPrefix(s, "ab0t_") {
		if j := strings.Index(s[i+1:], "_"); j >= 0 {
			head := s[:i+1+j+1]
			return head + strings.Repeat("*", 8)
		}
	}
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 8) + s[len(s)-2:]
}
