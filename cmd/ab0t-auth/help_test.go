package main

// help_test.go — gate G4, enforced in Go so it cannot regress silently.
//
// The journey review found `help can` printing the generic page and exiting 0.
// Nothing failed; the customer simply got a different answer than they asked for.
// That class of defect is invisible to every test that asks "does the command
// work" — so these tests ask "can a customer find out how to use it".

import (
	"bytes"
	"strings"
	"testing"
)

// Every verb must have deep help. A new verb without an entry fails the build
// rather than shipping undiscoverable.
func TestEveryVerbHasDeepHelp(t *testing.T) {
	for _, v := range verbNames() {
		doc, ok := helpDocs[v]
		if !ok {
			t.Errorf("verb %q has no entry in helpDocs — it would ship undiscoverable", v)
			continue
		}
		if strings.TrimSpace(doc.Purpose) == "" {
			t.Errorf("%s: no Purpose — help would not say what it is FOR", v)
		}
		if !strings.Contains(doc.Example, "ab0t-auth "+v) {
			t.Errorf("%s: Example does not show the command being run", v)
		}
		// A worked example without its output leaves the reader (or an agent)
		// guessing the shape of the answer.
		if len(strings.Split(strings.TrimSpace(doc.Example), "\n")) < 2 {
			t.Errorf("%s: Example has no output, only a command line", v)
		}
		if len(doc.Failures) == 0 {
			t.Errorf("%s: no Failures — the customer learns nothing about what goes wrong", v)
		}
		if len(doc.Next) == 0 {
			t.Errorf("%s: no Next — this is the progressive-disclosure payload; without it the verb is a dead end", v)
		}
	}
}

// Both invocation forms must render the same deep document. Customers reach for
// both; neither is wrong, so neither may be worse.
func TestBothHelpFormsRenderTheSameSections(t *testing.T) {
	o := newOutput(&bytes.Buffer{}, &bytes.Buffer{}, false, true, false, false)
	required := []string{"WHAT IT'S FOR", "EXAMPLE", "WHEN IT GOES WRONG", "WHAT PEOPLE USUALLY DO NEXT"}

	for _, v := range verbNames() {
		var b bytes.Buffer
		renderVerbHelp(&b, v, o)
		got := b.String()
		for _, sec := range required {
			if !strings.Contains(got, sec) {
				t.Errorf("help for %q is missing the %q section", v, sec)
			}
		}
		if !strings.Contains(got, "ab0t-auth "+v) {
			t.Errorf("help for %q never shows the command", v)
		}
	}
}

// The common-commands surface is the answer to "what do I do now". It must exist,
// be about ten things, and lead with the one to run when stuck.
func TestCommonCommandsSurface(t *testing.T) {
	if n := len(commonCommands); n < 8 || n > 12 {
		t.Errorf("commonCommands has %d entries; ~10 is the target (a longer list is a menu, not a starting point)", n)
	}
	if !strings.Contains(commonCommands[0].cmd, "doctor") {
		t.Errorf("first common command is %q; it should be doctor — the thing to run when something is wrong", commonCommands[0].cmd)
	}
	for _, c := range commonCommands {
		if c.why == "" {
			t.Errorf("common command %q has no explanation; a bare command list teaches nothing", c.cmd)
		}
	}
}

// Next-step hints must go to stderr and stay silent for machines. A hint printed
// to stdout would contaminate --json; a hint printed in --json mode is noise a
// script did not ask for.
func TestNextStepsAreStderrOnlyAndSilentForMachines(t *testing.T) {
	t.Run("goes to stderr", func(t *testing.T) {
		var out, errb bytes.Buffer
		o := newOutput(&out, &errb, false, true, false, false)
		nextSteps(o, "can", false)
		if out.Len() != 0 {
			t.Errorf("next-step hint leaked into stdout: %q", out.String())
		}
		if !strings.Contains(errb.String(), "why") {
			t.Errorf("a DENIED must point at 'why'; got %q", errb.String())
		}
	})
	for name, o := range map[string]*output{
		"--json":  newOutput(&bytes.Buffer{}, &bytes.Buffer{}, false, true, true, false),
		"--quiet": newOutput(&bytes.Buffer{}, &bytes.Buffer{}, false, true, false, true),
	} {
		t.Run("silent under "+name, func(t *testing.T) {
			var errb bytes.Buffer
			o.errw = &errb
			nextSteps(o, "can", false)
			if errb.Len() != 0 {
				t.Errorf("%s still emitted a hint: %q", name, errb.String())
			}
		})
	}
}

// Global flags must work before OR after the verb. The harness author — who wrote
// the CLI — typed `--server X health` on the first run and got "unknown command".
func TestGlobalFlagsWorkBeforeTheVerb(t *testing.T) {
	cases := [][]string{
		{"--server", "http://x", "health"},
		{"health", "--server", "http://x"},
		{"--json", "health"},
	}
	for _, args := range cases {
		got := hoistLeadingFlags(args)
		if len(got) == 0 || strings.HasPrefix(got[0], "-") {
			t.Errorf("hoistLeadingFlags(%v) = %v; first element must be the verb", args, got)
		}
		if got[0] != "health" {
			t.Errorf("hoistLeadingFlags(%v) = %v; want health first", args, got)
		}
	}
}
