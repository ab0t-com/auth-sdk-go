package authclient

// version_test.go — the release SOP, enforced.
//
// v0.1.0 shipped without a fix that was already on main: the fix was committed
// after the tag. Every local test passed, so nothing said otherwise. This test is
// the part of that failure that CAN be caught locally — a Version with no
// changelog entry behind it.
//
// See RELEASING.md.

import (
	"os"
	"strings"
	"testing"
)

func TestVersionMatchesChangelog(t *testing.T) {
	b, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		t.Fatalf("reading CHANGELOG.md: %v", err)
	}
	want := "## [" + Version + "]"
	if !strings.Contains(string(b), want) {
		t.Fatalf(`CHANGELOG.md has no %q section.

Version is %q but nothing in the changelog describes it. A consumer upgrading to
this version has no way to learn what changed or whether it breaks them.

Write the section first, then release with: make release VERSION=%s`, want, Version, Version)
	}
}

func TestVersionIsWellFormed(t *testing.T) {
	parts := strings.Split(Version, ".")
	if len(parts) != 3 {
		t.Fatalf("Version = %q, want three dot-separated numbers (it becomes the git tag v%s)", Version, Version)
	}
	for _, p := range parts {
		if p == "" || strings.TrimLeft(p, "0123456789") != "" {
			t.Fatalf("Version = %q has a non-numeric component %q", Version, p)
		}
	}
	// The User-Agent is how the service attributes traffic and identifies clients
	// running a contract it knows is bad. An empty version defeats that.
	if Version == "0.0.0" {
		t.Error("Version is still the placeholder")
	}
}
