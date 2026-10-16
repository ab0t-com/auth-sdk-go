//go:build integration

package authmw_test

// integration_gate_options_test.go — the documented JSON-API setup
// (RequireIdentity + IncludePermissions + JSONDenial) against a REAL, LOCAL auth
// service, with a real user token:
//
//	AUTH_SDK_IT_BASE_URL=http://localhost:8001 go test -tags integration -run TestIntegrationAuthmw -v ./authmw/

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/ab0t-com/auth-sdk-go"
	"github.com/ab0t-com/auth-sdk-go/authmw"
)

func TestIntegrationAuthmw_RequireIdentityWithARealToken(t *testing.T) {
	base := itBase(t)
	engine := itEngine(t, base)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	setup := auth.New(base, auth.WithValidationCache(0), auth.WithMaxRetries(1))
	ts := time.Now().UnixNano()
	reg, err := setup.Register(ctx, auth.RegisterRequest{
		Email:    fmt.Sprintf("sdkit_authmw_%d@test-uj.example.com", ts),
		Password: fmt.Sprintf("Authmw!Aa%d", ts),
		Name:     "SDK IT authmw",
	})
	if err != nil || reg.AccessToken == "" {
		t.Skipf("VOID: registration failed on %s: %v", base, err)
	}

	vc := &validateCounter{}
	client := auth.New(base, auth.WithMaxRetries(0), auth.WithObserver(vc.observe))
	gate := &authmw.Gate{V: client, A: client, IncludePermissions: true, WriteDenial: authmw.JSONDenial}
	var seen *auth.Actor
	h := gate.RequireIdentity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = authmw.Identity(r.Context())
		w.WriteHeader(200)
	}))

	if code := send(h, ""); code != http.StatusUnauthorized {
		t.Errorf("[%s] no credential: %d, want 401", base, code)
	}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+garbageJWT(t))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("Content-Type") != "application/json" ||
		strings.TrimSpace(rec.Body.String()) != `{"error":"invalid token"}` {
		t.Errorf("[%s] garbage JWT: %d %q %q, want 401 application/json {\"error\":\"invalid token\"}",
			base, rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}

	before, _ := vc.count()
	const n = 5
	for i := 0; i < n; i++ {
		seen = nil
		if code := send(h, "bearer "+reg.AccessToken); code != 200 { // lower-case scheme on purpose
			t.Fatalf("[%s] valid token, request %d: %d, want 200", base, i, code)
		}
		if seen == nil || !seen.Valid || seen.UserID == "" {
			t.Fatalf("[%s] valid token: identity %+v", base, seen)
		}
	}
	after, statuses := vc.count()
	t.Logf("[%s %s] valid token x%d -> 200, user=%s org=%s permissions=%v; validate calls for them = %d (statuses %v)",
		base, engine, n, seen.UserID, seen.OrgID, seen.Permissions, after-before, statuses)
	if after-before > 1 {
		t.Errorf("[%s] %d auth calls for %d requests with one valid token, want <= 1 (cached)", base, after-before, n)
	}
}
