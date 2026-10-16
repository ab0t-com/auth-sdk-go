package unreviewed

import (
	"time"

	auth "github.com/ab0t-com/auth-sdk-go"
)

// newFromConfig is the config-driven shape R4 exists for: "TTL 0 disables the
// cache" was true before v0.12.0 and silently stops being true after it.
func newFromConfig(url string, ttl time.Duration) *auth.Client {
	opts := []auth.Option{auth.WithUserAgent("svc")}
	if ttl > 0 {
		opts = append(opts, auth.WithValidationCache(ttl)) // R4
	}
	return auth.New(url, opts...) // R1 (the option is invisible here)
}
