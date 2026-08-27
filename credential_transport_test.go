package authclient

import (
	"context"
	"net/http"
	"testing"
)

// The auth service keeps its two credential systems on SEPARATE transports, and
// it is strict in opposite directions on different routes:
//
//   - `Authorization: Bearer <ab0t_sk_…>` is rejected 401 at the forward-auth
//     edge (an asserted anti-credential-confusion invariant, service-side
//     UJ-694), even though the ordinary API routes accept it.
//   - a bare `Authorization: <ab0t_sk_…>` is invisible to the API routes,
//     because FastAPI's HTTPBearer only populates credentials for the Bearer
//     scheme — even though forward-auth accepts it.
//
// `X-API-Key` is the ONE transport every API-key-accepting surface reads, so it
// is what the SDK sends for keys. JWTs keep `Authorization: Bearer`.
//
// These tests exist because the SDK previously sent EVERY credential as a
// bearer, which made API-key auth impossible at the edge and produced a real
// integrator bug report. Do not "simplify" this back to one header.

func TestLooksLikeJWT(t *testing.T) {
	cases := []struct {
		cred string
		want bool
	}{
		{"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1MSJ9.sig", true},
		{"a.b.c", true},
		{"", false},
		{"ab0t_sk_live_abc", false},
		{"a.b", false},          // too few segments
		{"a.b.c.d", false},      // too many segments
		{"a..c", false},         // empty segment
		{".b.c", false},         // empty leading segment
		{"a.b.", false},         // empty trailing segment
		{"a.b c", false},        // whitespace
		{"Bearer a.b.c", false}, // scheme included = not a bare credential
	}
	for _, tc := range cases {
		if got := LooksLikeJWT(tc.cred); got != tc.want {
			t.Errorf("LooksLikeJWT(%q) = %v, want %v", tc.cred, got, tc.want)
		}
	}
}

func TestCredentialHeader(t *testing.T) {
	const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1MSJ9.sig"
	cases := []struct {
		name, cred, wantName, wantValue string
	}{
		{"api key -> X-API-Key", "ab0t_sk_live_abc", "X-API-Key", "ab0t_sk_live_abc"},
		{"jwt -> bearer", jwt, "Authorization", "Bearer " + jwt},
		{"opaque token -> bearer (back-compat)", "opaque-token", "Authorization", "Bearer opaque-token"},
		{"empty -> no header", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, value := CredentialHeader(tc.cred)
			if name != tc.wantName || value != tc.wantValue {
				t.Errorf("CredentialHeader(%q) = (%q, %q), want (%q, %q)",
					tc.cred, name, value, tc.wantName, tc.wantValue)
			}
		})
	}
}

// The prefix wins over the JWT shape. A key whose random tail happens to contain
// two dots must still go out as an API key, never as a bearer.
func TestCredentialHeaderPrefixBeatsShape(t *testing.T) {
	const dotty = "ab0t_sk_live_a.b.c"
	if !LooksLikeJWT(dotty) {
		t.Fatalf("fixture no longer JWT-shaped; the precedence this test guards is untested")
	}
	name, value := CredentialHeader(dotty)
	if name != "X-API-Key" || value != dotty {
		t.Errorf("CredentialHeader(%q) = (%q, %q), want (X-API-Key, %q)", dotty, name, value, dotty)
	}
}

// End-to-end through the real transport: the credential's shape must pick the
// header on the wire, for both the per-call credential and the client default.
func TestTransportRoutesCredentialByShape(t *testing.T) {
	const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1MSJ9.sig"

	t.Run("per-call API key goes out as X-API-Key only", func(t *testing.T) {
		var gotAuth, gotKey string
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			gotAuth, gotKey = r.Header.Get("Authorization"), r.Header.Get("X-API-Key")
			writeJSON(w, 200, []APIKey{})
		})
		if _, err := c.ListAPIKeys(context.Background(), "ab0t_sk_live_abc"); err != nil {
			t.Fatalf("ListAPIKeys: %v", err)
		}
		if gotKey != "ab0t_sk_live_abc" {
			t.Errorf("X-API-Key = %q, want the key", gotKey)
		}
		if gotAuth != "" {
			t.Errorf("Authorization = %q, want empty (a key must not be sent as a bearer)", gotAuth)
		}
	})

	t.Run("per-call JWT goes out as Authorization: Bearer only", func(t *testing.T) {
		var gotAuth, gotKey string
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			gotAuth, gotKey = r.Header.Get("Authorization"), r.Header.Get("X-API-Key")
			writeJSON(w, 200, []APIKey{})
		})
		if _, err := c.ListAPIKeys(context.Background(), jwt); err != nil {
			t.Fatalf("ListAPIKeys: %v", err)
		}
		if gotAuth != "Bearer "+jwt {
			t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer "+jwt)
		}
		if gotKey != "" {
			t.Errorf("X-API-Key = %q, want empty (a JWT must not be sent as an api key)", gotKey)
		}
	})

	t.Run("client-default API key (WithAPIKey) also goes out as X-API-Key", func(t *testing.T) {
		var gotAuth, gotKey string
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			gotAuth, gotKey = r.Header.Get("Authorization"), r.Header.Get("X-API-Key")
			writeJSON(w, 200, []APIKey{})
		}, WithAPIKey("ab0t_sk_live_svc"))
		if _, err := c.ListAPIKeys(context.Background(), ""); err != nil {
			t.Fatalf("ListAPIKeys: %v", err)
		}
		if gotKey != "ab0t_sk_live_svc" {
			t.Errorf("X-API-Key = %q, want the configured key", gotKey)
		}
		if gotAuth != "" {
			t.Errorf("Authorization = %q, want empty", gotAuth)
		}
	})
}

// The regression that started this: ForwardAuth with an API key could never
// succeed, because the SDK sent it as a bearer and the edge rejects that shape.
func TestForwardAuthSendsAPIKeyAsXAPIKey(t *testing.T) {
	var gotAuth, gotKey string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotKey = r.Header.Get("Authorization"), r.Header.Get("X-API-Key")
		w.WriteHeader(200)
	})
	d, err := c.ForwardAuth(context.Background(), http.MethodGet, "ab0t_sk_live_edge")
	if err != nil {
		t.Fatalf("ForwardAuth: %v", err)
	}
	if !d.Allowed {
		t.Errorf("Allowed = false, want true")
	}
	if gotKey != "ab0t_sk_live_edge" {
		t.Errorf("X-API-Key = %q, want the key", gotKey)
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q — this is the exact shape the edge 401s", gotAuth)
	}
}
