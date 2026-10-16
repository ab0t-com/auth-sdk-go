// Package unreviewed is a v0.11.2 consumer snippet used ONLY to verify that
// migrate-check.sh flags every site to review for v0.12.0. It lives under testdata/,
// which the Go toolchain ignores. Run:
//
//	bash ../../migrate-check.sh .
//
// and expect a non-zero exit with R1, R2 and R3 findings.
package unreviewed

import (
	"context"

	auth "github.com/ab0t-com/auth-sdk-go"
)

func newClient() *auth.Client {
	// R1: no cache option -> default cache ON in v0.12.0.
	return auth.New("",
		auth.WithAPIKey("ab0t_sk_live_x"),
		auth.WithExpectedAudience("svc"),
	)
}

func handle(ctx context.Context, c *auth.Client, tok, key string) {
	_, _ = c.ValidateToken(ctx, tok)                                      // R2
	_, _ = c.ValidateAPIKey(ctx, auth.ValidateAPIKeyRequest{APIKey: key}) // R2
	_, _ = c.Authorize(ctx, tok, "billing.refund", auth.Resource{})       // R2
}
