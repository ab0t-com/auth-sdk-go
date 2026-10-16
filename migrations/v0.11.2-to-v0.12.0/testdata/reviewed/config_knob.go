package reviewed

import (
	"time"

	auth "github.com/ab0t-com/auth-sdk-go"
)

// newFromConfig after review: the option is passed unconditionally, so a
// configured 0 still means "off" (WithValidationCache(0)).
func newFromConfig(url string, ttl time.Duration) *auth.Client {
	opts := []auth.Option{auth.WithUserAgent("svc"), auth.WithValidationCache(ttl)}
	return auth.New(url, opts...) // authsdk:cache-reviewed — cache configured explicitly via opts
}
