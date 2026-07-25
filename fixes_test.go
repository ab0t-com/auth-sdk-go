package authclient

// fixes_test.go — tests for the surfaces added/corrected in v0.1.0 after a
// re-read of the live OpenAPI spec (2026-07-25):
//
//	F-1  DELETE /users/me      — was entirely missing
//	F-2  bulk check            — decoded the wrong wire shape (see domains_test.go)
//	F-3  authorization-model   — client methods with no server route
//	F-5  JWKS cache            — was unbounded, keyed by tenant
//	F-6  /mesh/providers       — was entirely missing

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// recorder captures the last request and replies with a canned body.
type recorder struct {
	method, path, body string
	auth               string
}

func serve(t *testing.T, rec *recorder, status int, reply string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec.method, rec.path, rec.body = r.Method, r.URL.Path, string(b)
		rec.auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, WithMaxRetries(0))
}

// ---- F-1: self-delete ----

func TestDeleteCurrentUser(t *testing.T) {
	var rec recorder
	c := serve(t, &rec, 200, `{"success":true,"message":"account deleted","user_id":"u1"}`)

	out, err := c.DeleteCurrentUser(context.Background(), "me@example.com", "caller-jwt")
	if err != nil {
		t.Fatalf("DeleteCurrentUser: %v", err)
	}
	if rec.method != http.MethodDelete || rec.path != "/users/me" {
		t.Fatalf("hit %s %s, want DELETE /users/me", rec.method, rec.path)
	}
	// The confirm-email guard is the whole safety mechanism of this endpoint.
	// If it stopped being sent, the server would reject — but if it were ever
	// auto-filled or defaulted, an accidental call would destroy an account.
	var body SelfDeleteRequest
	if err := json.Unmarshal([]byte(rec.body), &body); err != nil {
		t.Fatalf("body not JSON: %q", rec.body)
	}
	if body.ConfirmEmail != "me@example.com" {
		t.Errorf("confirm_email = %q, want the caller-supplied address", body.ConfirmEmail)
	}
	// It must carry the CALLER's token; a service key must not be able to delete
	// someone else's account through this path.
	if !strings.Contains(rec.auth, "caller-jwt") {
		t.Errorf("caller token not forwarded: %q", rec.auth)
	}
	if !out.Success {
		t.Errorf("response not decoded: %+v", out)
	}
}

func TestDeleteCurrentUser_MismatchIsAnError(t *testing.T) {
	var rec recorder
	c := serve(t, &rec, 422, `{"detail":"confirm_email does not match"}`)

	if _, err := c.DeleteCurrentUser(context.Background(), "wrong@example.com", "caller-jwt"); err == nil {
		t.Fatal("a rejected confirmation must surface as an error, never as a silent success")
	}
}

// ---- F-6: mesh ----

func TestMeshProviders(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		var rec recorder
		c := serve(t, &rec, 200, `{"providers":[{"service_id":"svc-a","display_name":"Service A","connect_prompt":"connect to A"}]}`)
		out, err := c.ListMeshProviders(context.Background(), nil, "")
		if err != nil {
			t.Fatalf("ListMeshProviders: %v", err)
		}
		if rec.method != http.MethodGet || rec.path != "/mesh/providers" {
			t.Fatalf("hit %s %s", rec.method, rec.path)
		}
		if len(out.Providers) != 1 || out.Providers[0].ServiceID != "svc-a" {
			t.Fatalf("providers not decoded: %+v", out)
		}
	})

	t.Run("get by service id, path-escaped", func(t *testing.T) {
		var rec recorder
		c := serve(t, &rec, 200, `{"service_id":"a/b","display_name":"Weird"}`)
		if _, err := c.GetMeshProvider(context.Background(), "a/b", ""); err != nil {
			t.Fatalf("GetMeshProvider: %v", err)
		}
		if rec.path != "/mesh/providers/a/b" && rec.path != "/mesh/providers/a%2Fb" {
			t.Fatalf("service id not escaped into the path: %q", rec.path)
		}
	})

	t.Run("publish sends the required fields", func(t *testing.T) {
		var rec recorder
		c := serve(t, &rec, 200, `{"valid":true,"service_id":"svc-a","listed":true}`)
		out, err := c.PublishMeshProvider(context.Background(), MeshProviderPublishRequest{
			ServiceID:   "svc-a",
			DisplayName: "Service A",
			RegisterURL: "https://example.invalid/register",
			OrgSlug:     "acme",
			Tiers:       []MeshProviderTierInput{{Name: "free", Default: true}},
		}, "svc-token")
		if err != nil {
			t.Fatalf("PublishMeshProvider: %v", err)
		}
		if rec.method != http.MethodPost || rec.path != "/mesh/providers" {
			t.Fatalf("hit %s %s", rec.method, rec.path)
		}
		for _, want := range []string{`"service_id":"svc-a"`, `"display_name":"Service A"`, `"register_url"`, `"org_slug":"acme"`} {
			if !strings.Contains(rec.body, want) {
				t.Errorf("required field missing from body (%s): %s", want, rec.body)
			}
		}
		if !out.Valid || !out.Listed {
			t.Errorf("publish result not decoded: %+v", out)
		}
	})

	t.Run("valid=false is not an error but IS a failure to publish", func(t *testing.T) {
		var rec recorder
		c := serve(t, &rec, 200, `{"valid":false,"reason":"docs_url unreachable","listed":false,"docs_url_warning":true}`)
		out, err := c.PublishMeshProvider(context.Background(), MeshProviderPublishRequest{ServiceID: "x", DisplayName: "X", RegisterURL: "u", OrgSlug: "o"}, "tok")
		if err != nil {
			t.Fatalf("a 200 with valid=false is a well-formed answer, not a transport error: %v", err)
		}
		// This is the trap the doc comment warns about: nil error, not published.
		if out.Valid || out.Listed {
			t.Fatal("valid=false / listed=false must decode as such")
		}
		if out.Reason == "" || !out.DocsURLWarning {
			t.Errorf("diagnostics dropped: %+v", out)
		}
	})
}

// ---- F-5: the JWKS cache is bounded ----

func TestJWKSCache_IsBounded(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"keys":[]}`)
	}))
	defer srv.Close()
	c := New(srv.URL, WithMaxRetries(0))

	j := c.jwks
	j.maxEntries = 8

	// Walk far more distinct orgs than the bound allows. Before this fix the map
	// grew by one entry per distinct org, forever.
	for i := 0; i < 200; i++ {
		if _, err := c.OrgJWKS(context.Background(), "org-"+string(rune('a'+i%26))+string(rune('a'+i/26))); err != nil {
			t.Fatalf("OrgJWKS: %v", err)
		}
	}

	j.mu.Lock()
	n := len(j.entries)
	j.mu.Unlock()

	if n > j.maxEntries {
		t.Fatalf("cache holds %d entries, bound is %d — the per-tenant leak is back", n, j.maxEntries)
	}
	if n == 0 {
		t.Fatal("cache evicted everything; it should still be caching")
	}
}

func TestJWKSCache_StillCachesWithinTTL(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"keys":[]}`)
	}))
	defer srv.Close()
	c := New(srv.URL, WithMaxRetries(0))
	c.jwks.ttl = time.Minute

	for i := 0; i < 5; i++ {
		if _, err := c.OrgJWKS(context.Background(), "org-1"); err != nil {
			t.Fatalf("OrgJWKS: %v", err)
		}
	}
	// Bounding the cache must not have broken caching itself.
	if hits != 1 {
		t.Fatalf("fetched %d times for one org within the TTL, want 1", hits)
	}
}

// ---- F-3: the authorization-model methods have no server route ----

// TestAuthorizationModel_IsStillAServerGap documents, executably, that these four
// methods target routes the auth service does not expose. They are shipped
// deliberately as forward-looking stubs and every one carries a SERVER-GAP godoc
// note — but a comment does not stop anyone calling them, so this test records
// what actually happens: a 404 from the server, surfaced as an error.
//
// If this test ever fails because the server started answering, that is GOOD
// news: the gap closed, and the SERVER-GAP notes should be removed.
func TestAuthorizationModel_IsStillAServerGap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"Not Found"}`, http.StatusNotFound)
	}))
	defer srv.Close()
	c := New(srv.URL, WithMaxRetries(0))
	ctx := context.Background()

	if _, err := c.ReadAuthorizationModel(ctx, "s1", "m1", "tok"); err == nil {
		t.Error("ReadAuthorizationModel: a 404 must surface as an error")
	}
	if _, err := c.ListAuthorizationModels(ctx, "s1", "", "tok"); err == nil {
		t.Error("ListAuthorizationModels: a 404 must surface as an error")
	}
	if _, err := c.WriteAuthorizationModel(ctx, "s1", WriteAuthorizationModelRequest{}, "tok"); err == nil {
		t.Error("WriteAuthorizationModel: a 404 must surface as an error")
	}
	if _, err := c.WriteAndDeleteRelationships(ctx, "s1", TransactRelationshipsRequest{}, "tok"); err == nil {
		t.Error("WriteAndDeleteRelationships: a 404 must surface as an error")
	}
}

// ---- Version is wired into the User-Agent ----

func TestUserAgentCarriesVersion(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"keys":[]}`)
	}))
	defer srv.Close()

	if _, err := New(srv.URL, WithMaxRetries(0)).JWKS(context.Background()); err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if !strings.Contains(ua, Version) {
		t.Errorf("User-Agent %q does not carry Version %q — the service cannot attribute traffic or spot a known-bad client", ua, Version)
	}
	// The User-Agent must identify the SDK, not whichever service happens to be
	// using it. An earlier release named one particular consumer.
	if !strings.HasPrefix(ua, "ab0t-auth-sdk-go/") {
		t.Errorf("User-Agent %q should identify this SDK, not a specific consumer", ua)
	}
}

// ---- Typed-id validation (PMM finding P-2) ----

// TestZanzibarCheck_RejectsUntypedIDs pins the guard against the failure this SDK's
// Zanzibar surface was rewritten to fix.
//
// Every combined id is a plain Go string, so nothing in the type system stops a
// caller passing "alice" where "user:alice" is meant. The server cannot tell that
// apart from an id it has simply never seen — it answers allowed:false, and the
// caller reads a legitimate DENY. A silent wrong deny is expensive to debug and
// indistinguishable from a real authorization decision.
func TestZanzibarCheck_RejectsUntypedIDs(t *testing.T) {
	var rec recorder
	c := serve(t, &rec, 200, `{"allowed":true}`)

	for name, req := range map[string]CheckPermissionRequest{
		"bare subject":  {Subject: "alice", Permission: "view", Object: Object("doc", "1")},
		"bare object":   {Subject: Subject("user", "alice"), Permission: "view", Object: "doc1"},
		"empty subject": {Subject: "", Permission: "view", Object: Object("doc", "1")},
		"empty type":    {Subject: ":alice", Permission: "view", Object: Object("doc", "1")},
		"empty id":      {Subject: "user:", Permission: "view", Object: Object("doc", "1")},
	} {
		t.Run(name, func(t *testing.T) {
			rec.path = ""
			_, err := c.ZanzibarCheck(context.Background(), "s1", req, "tok")
			if err == nil {
				t.Fatal("an untyped id must be an error, not a silent wrong DENY from the server")
			}
			var e *ErrUntypedID
			if !errors.As(err, &e) {
				t.Errorf("error is %T (%v), want *ErrUntypedID so callers can branch on it", err, err)
			}
			// It must fail BEFORE the request: a round trip that can only return
			// the wrong answer is worse than no round trip.
			if rec.path != "" {
				t.Errorf("request was sent anyway (hit %s)", rec.path)
			}
		})
	}
}

func TestZanzibarCheck_AcceptsValidTypedIDs(t *testing.T) {
	var rec recorder
	c := serve(t, &rec, 200, `{"allowed":true}`)

	for name, req := range map[string]CheckPermissionRequest{
		"plain":           {Subject: Subject("user", "alice"), Permission: "view", Object: Object("doc", "1")},
		"userset subject": {Subject: Subject("group", "eng") + "#member", Permission: "view", Object: Object("doc", "1")},
		"id containing :": {Subject: Subject("user", "a:b"), Permission: "view", Object: Object("doc", "1")},
		"uuid-ish id":     {Subject: Subject("user", "0d9f-4c1e"), Permission: "view", Object: Object("doc", "x/y")},
	} {
		t.Run(name, func(t *testing.T) {
			ok, err := c.ZanzibarCheck(context.Background(), "s1", req, "tok")
			if err != nil {
				t.Fatalf("valid typed ids rejected: %v", err)
			}
			if !ok.Allowed {
				t.Error("response not decoded")
			}
		})
	}
}

// TestZanzibarCheckBulk_NamesTheOffendingCheck — a bulk request is built in a loop,
// so "check 7 is wrong" is the difference between a one-minute fix and an afternoon.
func TestZanzibarCheckBulk_NamesTheOffendingCheck(t *testing.T) {
	var rec recorder
	c := serve(t, &rec, 200, `[]`)

	_, err := c.ZanzibarCheckBulk(context.Background(), "s1", BulkCheckRequest{Checks: []CheckPermissionRequest{
		{Subject: Subject("user", "a"), Permission: "view", Object: Object("doc", "1")},
		{Subject: Subject("user", "b"), Permission: "view", Object: Object("doc", "2")},
		{Subject: "c", Permission: "view", Object: Object("doc", "3")}, // index 2 is bad
	}}, "tok")
	if err == nil {
		t.Fatal("an untyped id anywhere in a bulk request must be an error")
	}
	if !strings.Contains(err.Error(), "check 2") {
		t.Errorf("error %q does not name the offending index", err)
	}
	var e *ErrUntypedID
	if !errors.As(err, &e) {
		t.Error("the wrapped error must still unwrap to *ErrUntypedID")
	}
	if rec.path != "" {
		t.Error("bulk request was sent despite a bad element")
	}
}
