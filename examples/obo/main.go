// Command obo is a runnable example of getting a token for another mesh service
// with TokenFor — for a signed-in person (on-behalf-of), or for the service
// itself when no person is involved.
//
// App A holds person U's access token and needs to call service B *as U*, with
// the call attributed to "A acting for U" and limited to what U allowed. A's
// identity is its OAuth client (client_id + client_secret). TokenFor picks the
// pattern from the session argument:
//
//   - SUBJECT_TOKEN set   → for the person (RFC 8693 token exchange)
//   - SUBJECT_TOKEN empty → for the service itself (client credentials)
//
// Today's auth services exchange a person's token with the app's own token as
// the RFC 8693 actor_token, an audience naming B, and a delegation grant from
// the person to the app's identity (see docs/OBO_TOKEN_EXCHANGE.md for the
// one-time setup). WithLegacyActorExchange runs exactly that chain behind
// TokenFor; drop the option once the service accepts the client-authenticated
// exchange, and nothing else in this program changes.
//
//	AUTH_URL=http://localhost:8001 \
//	CLIENT_ID=<A's client_id> CLIENT_SECRET=<A's client_secret> \
//	AUDIENCE=<B's service audience, e.g. SELF:<org id>> \
//	SCOPE=<a permission U granted, e.g. users.read> \
//	SUBJECT_TOKEN=<U's access token> \
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
	clientID, clientSecret := os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("set CLIENT_ID and CLIENT_SECRET to your app's confidential client credentials")
	}
	audience := os.Getenv("AUDIENCE") // B's registered service audience (today's exchange names it)
	resource := envOr("RESOURCE", audience)
	scope := os.Getenv("SCOPE")

	c := auth.New(baseURL,
		auth.WithClientCredentials(clientID, clientSecret),
		auth.WithLegacyActorExchange(audience), // bridge: remove when the service supports the target exchange
	)

	var session auth.Session // nil = the service acts as itself
	if t := os.Getenv("SUBJECT_TOKEN"); t != "" {
		session = auth.StaticSession(t) // in a real app: the person's session with your app
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tok, err := c.TokenFor(ctx, resource, scope, session)
	var consent *auth.ConsentRequired
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrReauthenticate):
		log.Fatal("the person's token was not accepted (expired, wrong org, or no grant for this app) — sign them in again")
	case errors.As(err, &consent):
		_, challenge, _ := auth.NewPKCE() // keep the verifier (first value) for the code exchange at your redirect URI
		log.Fatalf("the person must approve access once: %s",
			consent.AuthorizationURL("https://your-app.example/callback", "state", challenge))
	case errors.Is(err, auth.ErrNoConnection):
		log.Fatalf("%q is not a target this app may reach (unknown audience/resource, or not approved)", resource)
	case errors.Is(err, auth.ErrScopeNotAllowed):
		log.Fatalf("scope %q is more than this app / grant allows", scope)
	case errors.Is(err, auth.ErrClientAuth):
		log.Fatal("the client credentials were rejected — check or rotate the secret")
	case errors.Is(err, auth.ErrClientNotEnabled):
		log.Fatal("the client is not registered for this grant type")
	case errors.Is(err, auth.ErrUnavailable):
		log.Fatalf("auth could not answer — back off and retry: %v", err)
	default:
		log.Fatalf("TokenFor: %v", err)
	}

	pattern := "service (client credentials)"
	if session != nil {
		pattern = "person (token exchange)"
	}
	fmt.Printf("pattern:    %s\n", pattern)
	fmt.Printf("resource:   %s\n", tok.Resource)
	fmt.Printf("scope:      %s\n", tok.Scope)
	fmt.Printf("token_type: %s\n", tok.TokenType)
	fmt.Printf("expires_in: ~%ds\n", int(time.Until(tok.ExpiresAt).Seconds()))
	// Next: call B with "Authorization: Bearer "+tok.AccessToken. Call TokenFor
	// again for every request — it serves the cached token until shortly before
	// it expires; there is no refresh token to manage.
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
