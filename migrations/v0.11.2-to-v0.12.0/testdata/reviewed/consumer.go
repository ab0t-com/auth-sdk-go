// Package reviewed is the same consumer AFTER review for v0.12.0 — every site
// resolved one of the documented ways. migrate-check.sh must exit 0 on it:
//
//	bash ../../migrate-check.sh .
package reviewed

import (
	"context"

	auth "github.com/ab0t-com/auth-sdk-go"
)

func newClient() *auth.Client {
	// Reviewed: the hot path accepts the documented latency (60 s key / 15 s JWT, permission).
	// authsdk:cache-reviewed
	return auth.New("",
		auth.WithAPIKey("ab0t_sk_live_x"),
		auth.WithExpectedAudience("svc"),
	)
}

func newStrictClient() *auth.Client {
	return auth.New("", auth.WithValidationCache(0)) // explicit: unchanged behaviour
}

func handle(ctx context.Context, c *auth.Client, tok, key string) {
	_, _ = c.ValidateToken(ctx, tok) // authsdk:cache-reviewed — read path, 15 s is fine
	// authsdk:cache-reviewed
	_, _ = c.ValidateAPIKey(ctx, auth.ValidateAPIKeyRequest{APIKey: key})
	_, _ = c.Authorize(auth.WithFreshValidation(ctx), tok, "billing.refund", auth.Resource{}) // money: always ask
}
