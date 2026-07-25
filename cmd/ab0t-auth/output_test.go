package main

// output_test.go — the ACCESSIBILITY INVARIANTS.
//
// These are not happy-path tests. Each one pins a property that, if it silently
// broke, would degrade the CLI for a class of user who is unlikely to be in the
// room to complain: a screen-reader user, someone who cannot distinguish red from
// green, someone reading a CI log, or someone piping output into a script.
//
// A regression in any of them is invisible to a sighted developer at an
// interactive terminal — which is exactly why they need tests rather than care.

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// ansiRE matches any escape sequence. Used to assert the ABSENCE of all of them:
// "less colour" is not what NO_COLOR asks for.
func hasANSI(s string) bool { return strings.Contains(s, "\033[") }

func TestNoColor_MeansNoANSIAtAll(t *testing.T) {
	cases := map[string]func() *output{
		"--no-color flag": func() *output {
			return newOutput(&bytes.Buffer{}, &bytes.Buffer{}, false, true, false, false)
		},
		"NO_COLOR env": func() *output {
			t.Setenv("NO_COLOR", "1")
			return newOutput(&bytes.Buffer{}, &bytes.Buffer{}, false, false, false, false)
		},
		// no-color.org: ANY non-empty value disables colour. A CLI that only
		// accepts "1" fails the users who wrote "true".
		"NO_COLOR=anything": func() *output {
			t.Setenv("NO_COLOR", "yes-please")
			return newOutput(&bytes.Buffer{}, &bytes.Buffer{}, false, false, false, false)
		},
		"NO_COLOR beats --color": func() *output {
			t.Setenv("NO_COLOR", "1")
			return newOutput(&bytes.Buffer{}, &bytes.Buffer{}, true, false, false, false)
		},
		"TERM=dumb": func() *output {
			t.Setenv("TERM", "dumb")
			return newOutput(&bytes.Buffer{}, &bytes.Buffer{}, false, false, false, false)
		},
		"--json mode": func() *output {
			return newOutput(&bytes.Buffer{}, &bytes.Buffer{}, true, false, true, false)
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			o := mk()
			var b bytes.Buffer
			o.out, o.errw = &b, &b
			o.printf("%s\n", o.verdict(true))
			o.printf("%s\n", o.verdict(false))
			o.ok("fine")
			o.warn("careful")
			o.errorf("broken")
			o.hint("try this")
			o.heading("Section")
			if hasANSI(b.String()) {
				t.Errorf("emitted ANSI despite %s:\n%q", name, b.String())
			}
		})
	}
}

// A pipe or a file is not a terminal, so colour would be corruption — the bytes
// end up in the data, in the log, or read aloud as gibberish.
func TestNonTTY_GetsNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	var b bytes.Buffer
	o := newOutput(&b, &b, false, false, false, false) // bytes.Buffer is not a *os.File
	if o.color {
		t.Fatal("colour enabled for a non-terminal writer")
	}
	o.printf("%s\n", o.verdict(false))
	if hasANSI(b.String()) {
		t.Errorf("ANSI written to a non-terminal: %q", b.String())
	}
}

// TestColorIsNeverTheOnlySignal is the load-bearing one. Strip every escape
// sequence and the meaning must survive intact — that is what makes the output
// work for a screen reader, a colourblind user, a pipe and a log at once.
func TestColorIsNeverTheOnlySignal(t *testing.T) {
	var colored, plain bytes.Buffer

	c := newOutput(&colored, &colored, true, false, false, false)
	p := newOutput(&plain, &plain, false, true, false, false)

	for _, o := range []*output{c, p} {
		o.printf("%s\n", o.verdict(true))
		o.printf("%s\n", o.verdict(false))
		o.ok("saved")
		o.errorf("nope")
	}

	if !hasANSI(colored.String()) {
		t.Fatal("the coloured writer produced no colour; this test proves nothing")
	}

	// Remove every escape sequence from the coloured output and it must equal the
	// plain output exactly. Any difference is information carried by colour alone.
	stripped := stripANSI(colored.String())
	if stripped != plain.String() {
		t.Errorf("colour carries information that plain output loses:\n coloured(stripped): %q\n plain:              %q", stripped, plain.String())
	}
	for _, want := range []string{"ALLOWED", "DENIED", "error:"} {
		if !strings.Contains(plain.String(), want) {
			t.Errorf("plain output is missing the word %q — the state would only be visible as colour", want)
		}
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			i = j + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// Diagnostics must not land in stdout, or `cmd --json > out.json` produces a file
// that will not parse — and the user sees nothing explaining why.
func TestDiagnosticsGoToStderr(t *testing.T) {
	var out, errb bytes.Buffer
	o := newOutput(&out, &errb, false, true, false, false)

	o.errorf("something failed")
	o.hint("do this instead")
	o.warn("heads up")

	if out.Len() != 0 {
		t.Errorf("diagnostics leaked into stdout: %q", out.String())
	}
	for _, want := range []string{"something failed", "do this instead", "heads up"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr missing %q", want)
		}
	}
}

// JSON mode must emit ONLY parseable JSON on stdout.
func TestJSONMode_IsParseableAndUncontaminated(t *testing.T) {
	var out, errb bytes.Buffer
	o := newOutput(&out, &errb, true /*force colour, to prove json wins*/, false, true, false)

	type payload struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	if err := o.emit(payload{Allowed: false, Reason: "no relation"}, func() {
		t.Error("human renderer must not run in --json mode")
	}); err != nil {
		t.Fatalf("emit: %v", err)
	}

	var got payload
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not valid JSON (%v): %q", err, out.String())
	}
	if got.Reason != "no relation" {
		t.Errorf("round-trip lost data: %+v", got)
	}
	if hasANSI(out.String()) {
		t.Error("ANSI inside JSON output")
	}
}

// --quiet must silence chatter without silencing errors: a script that hides its
// failures is worse than a noisy one.
func TestQuiet_SilencesChatterNotErrors(t *testing.T) {
	var out, errb bytes.Buffer
	o := newOutput(&out, &errb, false, true, false, true)

	o.ok("did a thing")
	o.heading("Section")
	o.printf("chatter\n")
	o.errorf("the important part")

	if out.Len() != 0 {
		t.Errorf("--quiet still wrote to stdout: %q", out.String())
	}
	if !strings.Contains(errb.String(), "the important part") {
		t.Error("--quiet suppressed an ERROR; failures must always be visible")
	}
}

// No box drawing, no cursor movement, no carriage-return redraw. Screen readers
// announce a redrawing line repeatedly; CI logs fill with control characters.
func TestOutputIsAppendOnlyAndPlain(t *testing.T) {
	var b bytes.Buffer
	o := newOutput(&b, &b, true, false, false, false)
	o.kv([2]string{"user", "u1"}, [2]string{"org", "o1"})
	o.list([]string{"doc:2", "doc:1"})
	o.printf("%s\n", o.verdict(true))

	s := stripANSI(b.String())
	for _, bad := range []string{"\r", "\033[K", "\033[A", "┌", "─", "│", "└", "╔", "═"} {
		if strings.Contains(s, bad) {
			t.Errorf("output contains %q — no redrawing or box drawing allowed", bad)
		}
	}
	// list must be sorted so repeated runs diff cleanly.
	if i, j := strings.Index(s, "doc:1"), strings.Index(s, "doc:2"); i > j {
		t.Error("list output is not sorted; repeated runs will diff noisily")
	}
}

// A credential must never be printed in full: scrollback, screen shares, CI logs
// and pasted bug reports all outlive the moment.
func TestMask_NeverRevealsTheSecret(t *testing.T) {
	for _, secret := range []string{
		"ab0t_sk_live_abcdefghijklmnop",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
		"short",
		"",
	} {
		got := mask(secret)
		if secret != "" && strings.Contains(got, secret) {
			t.Errorf("mask(%q) = %q — leaks the whole secret", secret, got)
		}
		if len(secret) > 12 && !strings.Contains(got, "*") {
			t.Errorf("mask(%q) = %q — nothing was masked", secret, got)
		}
	}
	if mask("") != "(none)" {
		t.Errorf("mask(\"\") = %q, want (none)", mask(""))
	}
	// The prefix must survive so a user can tell WHICH credential is in play —
	// that is the whole diagnostic value of showing it at all.
	if !strings.HasPrefix(mask("ab0t_sk_live_abcdef"), "ab0t_sk_") {
		t.Errorf("mask dropped the identifying prefix: %q", mask("ab0t_sk_live_abcdef"))
	}
}

func TestIsTerminal(t *testing.T) {
	if isTerminal(&bytes.Buffer{}) {
		t.Error("a bytes.Buffer is not a terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Error("a regular file is not a terminal")
	}
}
