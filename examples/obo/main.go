// Command obo is a runnable example of the RFC 8693 token-exchange
// (on-behalf-of) flow: an app/agent A holds end user U's access token and needs
// to call mesh service B *as U*, with audit + least privilege. It exchanges U's
// token for one minted for B, then would present that token to B.
//
// Two provisioning prerequisites must already be in place (see
// docs/OBO_TOKEN_EXCHANGE.md):
//   - B ("resource-service" below) is registered as U's org's service_audience;
//   - a read-only may_act delegation grant exists (A may act for U).
//
// Otherwise the exchange returns invalid_target (unregistered audience) or an
// empty-scope denial (no/insufficient delegation grant).
//
//	AUTH_URL=https://auth.service.ab0t.com \
//	SUBJECT_TOKEN=<end-user access token> \
//	go run ./examples/obo
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	auth "github.com/ab0t-com/auth-sdk-go"
)

func main() {
	baseURL := envOr("AUTH_URL", "http://localhost:8001")
	subjectToken := os.Getenv("SUBJECT_TOKEN") // the end user's access token
	if subjectToken == "" {
		log.Fatal("set SUBJECT_TOKEN to the end user's access token")
	}
	audience := envOr("AUDIENCE", "resource-service") // the target mesh service (its org service_audience)

	c := auth.New(baseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Exchange U's token for one minted for the target service, read-only.
	// WithScope narrows fail-closed against the delegation grant's ceiling; it
	// is never widened. Omit it to accept the grant's default scope.
	resp, err := c.ExchangeToken(ctx, subjectToken, audience,
		auth.WithScope("resource:read"),
	)
	if err != nil {
		var ae *auth.APIError
		if errors.As(err, &ae) && ae.Code == "invalid_target" {
			log.Fatalf("exchange rejected: %q is not this org's registered service_audience "+
				"(register it + create a read-only may_act grant first)", audience)
		}
		log.Fatalf("token exchange failed: %v", err)
	}

	// resp.AccessToken is the delegated token to present to the target service.
	// resp.IssuedTokenType is surfaced here (TokenResponse would drop it).
	fmt.Printf("issued_token_type: %s\n", resp.IssuedTokenType)
	fmt.Printf("token_type:        %s\n", resp.TokenType)
	fmt.Printf("expires_in:        %d\n", resp.ExpiresIn)
	fmt.Printf("scope:             %s\n", resp.Scope)
	fmt.Printf("access_token:      %s...(truncated)\n", head(resp.AccessToken, 12))

	// Next: call the target service with resp.AccessToken as the bearer; the
	// service sees a delegation token carrying act/may_act attributing the call
	// to "A acting for U".
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
