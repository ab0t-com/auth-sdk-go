package authclient

// jwt_audience_test.go — WithExpectedJWTAudience asserts an audience on user JWTs
// only; API keys (mesh service keys carry no audience) are never asked for it.
// WithExpectedAudience is unchanged: it still applies to both.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// audienceRecorder answers every validation as valid and records, per request,
// the path and the expected_audience it carried ("" when absent).
type audienceRecorder struct {
	mu   sync.Mutex
	seen []string // "path aud"
}

func (a *audienceRecorder) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ExpectedAudience string `json:"expected_audience"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		a.mu.Lock()
		a.seen = append(a.seen, r.URL.Path+" "+body.ExpectedAudience)
		a.mu.Unlock()
		switch r.URL.Path {
		case pToken, pKey:
			writeJSON(w, 200, map[string]any{"valid": true, "user_id": "u1", "org_id": "o1"})
		case pCheck:
			writeJSON(w, 200, map[string]any{"allowed": true})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}
}

func (a *audienceRecorder) take() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.seen
	a.seen = nil
	return out
}

func TestWithExpectedJWTAudience_AssertsJWTsOnlyNeverAPIKeys(t *testing.T) {
	ctx := context.Background()
	doc := Resource{Type: "doc", ID: "d1"}
	calls := []struct {
		name string
		run  func(*Client) error
	}{
		{"ValidateToken(JWT)", func(c *Client) error { _, err := c.ValidateToken(ctx, testJWT); return err }},
		{"ValidateToken(key)", func(c *Client) error { _, err := c.ValidateToken(ctx, tKey); return err }},
		{"ValidateAPIKey", func(c *Client) error {
			_, err := c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{APIKey: tKey})
			return err
		}},
		{"ValidateTokenWith(JWT)", func(c *Client) error {
			_, err := c.ValidateTokenWith(ctx, TokenValidationRequest{Token: testJWT})
			return err
		}},
		{"Authorize(JWT)", func(c *Client) error { _, err := c.Authorize(ctx, testJWT, "a.read", Resource{}); return err }},
		{"Authorize(key)", func(c *Client) error { _, err := c.Authorize(ctx, tKey, "a.read", Resource{}); return err }},
		{"Authorize(JWT, resource)", func(c *Client) error { _, err := c.Authorize(ctx, testJWT, "a.read", doc); return err }},
		{"Authorize(key, resource)", func(c *Client) error { _, err := c.Authorize(ctx, tKey, "a.read", doc); return err }},
	}
	// want: the audience sent on the validation request of each call above.
	cases := []struct {
		name string
		opts []Option
		want []string
	}{
		{"JWT audience only", []Option{WithExpectedJWTAudience("svc-jwt")},
			[]string{"svc-jwt", "", "", "svc-jwt", "svc-jwt", "", "svc-jwt", ""}},
		{"both: JWT audience wins for JWTs, the other stays on keys",
			[]Option{WithExpectedAudience("svc-all"), WithExpectedJWTAudience("svc-jwt")},
			[]string{"svc-jwt", "svc-all", "svc-all", "svc-jwt", "svc-jwt", "svc-all", "svc-jwt", "svc-all"}},
		{"WithExpectedAudience alone is unchanged (applies to both)", []Option{WithExpectedAudience("svc-all")},
			[]string{"svc-all", "svc-all", "svc-all", "svc-all", "svc-all", "svc-all", "svc-all", "svc-all"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &audienceRecorder{}
			c, _ := newTestClient(t, rec.handler(t), append([]Option{WithValidationCache(0), WithMaxRetries(0)}, tc.opts...)...)
			for i, call := range calls {
				if err := call.run(c); err != nil {
					t.Fatalf("%s: %v", call.name, err)
				}
				var got string
				for _, s := range rec.take() {
					// The validation request (not the PDP check) carries the audience.
					if p, aud, _ := strings.Cut(s, " "); p == pToken || p == pKey {
						got = aud
					}
				}
				if got != tc.want[i] {
					t.Errorf("%s: expected_audience sent = %q, want %q", call.name, got, tc.want[i])
				}
			}
		})
	}

	// An explicit per-call audience still overrides the client defaults.
	rec := &audienceRecorder{}
	c, _ := newTestClient(t, rec.handler(t), WithValidationCache(0), WithExpectedJWTAudience("svc-jwt"))
	if _, err := c.ValidateTokenWith(ctx, TokenValidationRequest{Token: testJWT, ExpectedAudience: "explicit"}); err != nil {
		t.Fatal(err)
	}
	if got := rec.take(); len(got) != 1 || got[0] != pToken+" explicit" {
		t.Errorf("explicit audience: sent %v", got)
	}
}

// VerifyAccessTokenLocal only ever sees JWTs, so the JWT audience is its default.
func TestWithExpectedJWTAudience_IsTheLocalVerifyDefault(t *testing.T) {
	ctx := context.Background()
	c, _, clock := lvSetup(t, WithExpectedJWTAudience("svc-b"))
	tok := signRS(lvKey1, stdHeader(), stdClaims("")) // aud: svc-a, LOCAL:org-1
	_, err := c.VerifyAccessTokenLocal(ctx, tok, lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "audience")

	c2, _, clock2 := lvSetup(t, WithExpectedAudience("svc-b"), WithExpectedJWTAudience("svc-a"))
	if _, err := c2.VerifyAccessTokenLocal(ctx, tok, lvOpts(clock2, LocalVerifyOptions{})); err != nil {
		t.Fatalf("the JWT audience must take precedence over WithExpectedAudience for a JWT: %v", err)
	}
	if _, err := c.VerifyAccessTokenLocal(ctx, tok, lvOpts(clock, LocalVerifyOptions{Audience: "svc-a"})); err != nil {
		t.Fatalf("opts.Audience still overrides the client default: %v", err)
	}
}
