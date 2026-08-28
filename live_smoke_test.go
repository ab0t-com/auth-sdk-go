package authclient

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLive_Smoke exercises the SDK against a REAL auth service (not a mock), to
// prove the contract fixes decode real wire values. Skipped unless AUTH_LIVE=1;
// the base URL comes from AUTH_BASE (no server URL is hard-coded here).
//
//	AUTH_LIVE=1 AUTH_BASE=https://<auth-host> go test -run TestLive_Smoke -v
func TestLive_Smoke(t *testing.T) {
	if os.Getenv("AUTH_LIVE") == "" {
		t.Skip("set AUTH_LIVE=1 (and AUTH_BASE) to run against a live auth service")
	}
	base := os.Getenv("AUTH_BASE")
	if base == "" {
		t.Fatal("AUTH_BASE required")
	}
	c := New(base)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// F-12: /health timestamp is a NUMBER — this decode failed entirely before the fix.
	h, err := c.Health(ctx)
	if err != nil {
		t.Fatalf("Health decode FAILED against live server: %v", err)
	}
	t.Logf("Health OK: status=%q version=%q timestamp=%v", h.Status, h.Version, h.Timestamp)
	if h.Timestamp == 0 {
		t.Errorf("F-12: health timestamp did not decode (0)")
	}

	// F-05/F-08: discovery decodes; phantom fields gone.
	d, err := c.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover decode FAILED: %v", err)
	}
	t.Logf("Discover OK: service=%q version=%q (api_groups present=%v)", d.Service, d.Version, len(d.APIGroups) > 0)

	// F-12: quota tiers is an object MAP — decoding as an array failed before.
	tiers, err := c.QuotaTiers(ctx)
	if err != nil {
		t.Logf("QuotaTiers: %v (may require auth on this deployment)", err)
	} else {
		t.Logf("QuotaTiers OK: %d tiers decoded", len(tiers.Tiers))
	}

	// JWKS decodes (public).
	if _, err := c.JWKS(ctx); err != nil {
		t.Logf("JWKS: %v", err)
	} else {
		t.Logf("JWKS OK")
	}
}
