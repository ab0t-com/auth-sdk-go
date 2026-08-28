package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// Tests for the 2026-08-27 contract-drift fixes (ticket
// tickets/20260827_sdk_contract_drift). Each maps to a finding id.

// F-01: a resource-scoped Authorize must ask the resource-aware PDP and must NOT
// be answerable by a backend whose validate-token ignores the resource. This
// simulates goauth: validate-token allows on the permission alone (ignores the
// resource), while /permissions/check enforces the resource. A correct
// Authorize must deny on a different resource.
func TestAuthorize_ResourceScoped_RoutesToPDP_AndFailsClosed(t *testing.T) {
	var validateHits, checkHits int
	h := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/validate-token":
			validateHits++
			// Backend that ignores resource fields: valid, resolves subject.
			writeJSON(w, http.StatusOK, Actor{Valid: true, UserID: "u1", OrgID: "o1"})
		case "/permissions/check":
			checkHits++
			var req PermissionCheckRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			// Only w1 is granted; w2 is not. The PDP honors the resource.
			allowed := req.ResourceID == "w1" && req.Permission == "world.write"
			writeJSON(w, http.StatusOK, PermissionDecision{Allowed: allowed, Scope: "object"})
		default:
			http.NotFound(w, r)
		}
	}
	c, _ := newTestClient(t, h)
	ctx := context.Background()

	ok, err := c.Authorize(ctx, "header.body.sig", "world.write", Resource{Type: "world", ID: "w1"})
	if err != nil || !ok {
		t.Fatalf("expected allow on w1, got ok=%v err=%v", ok, err)
	}
	ok, err = c.Authorize(ctx, "header.body.sig", "world.write", Resource{Type: "world", ID: "w2"})
	if err != nil {
		t.Fatalf("unexpected error on w2: %v", err)
	}
	if ok {
		t.Fatalf("F-01 regression: resource-scoped Authorize allowed on w2 (a resource the subject was not granted)")
	}
	if checkHits == 0 {
		t.Fatalf("expected the resource-scoped check to route to /permissions/check; it did not")
	}
}

// F-01: a resource-LESS Authorize stays a single validate-token capability check
// and must not touch the PDP.
func TestAuthorize_Unscoped_UsesValidateTokenOnly(t *testing.T) {
	var checkHits int
	h := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/validate-token":
			writeJSON(w, http.StatusOK, Actor{Valid: true, UserID: "u1"})
		case "/permissions/check":
			checkHits++
			writeJSON(w, http.StatusOK, PermissionDecision{Allowed: true})
		default:
			http.NotFound(w, r)
		}
	}
	c, _ := newTestClient(t, h)
	ok, err := c.Authorize(context.Background(), "header.body.sig", "admin.read", Resource{})
	if err != nil || !ok {
		t.Fatalf("expected unscoped allow, got ok=%v err=%v", ok, err)
	}
	if checkHits != 0 {
		t.Fatalf("resource-less Authorize must not call the PDP; got %d calls", checkHits)
	}
}

// F-01: an invalid token fails closed on the resource-scoped path.
func TestAuthorize_ResourceScoped_InvalidToken_Denies(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/validate-token" {
			writeJSON(w, http.StatusOK, Actor{Valid: false, Error: "expired"})
			return
		}
		t.Errorf("PDP must not be consulted for an invalid token; hit %s", r.URL.Path)
		http.NotFound(w, r)
	}
	c, _ := newTestClient(t, h)
	ok, err := c.Authorize(context.Background(), "header.body.sig", "world.write", Resource{Type: "world", ID: "w1"})
	if err != nil || ok {
		t.Fatalf("expected fail-closed deny with nil error, got ok=%v err=%v", ok, err)
	}
}

// F-02: the delegation fields both backends return must survive decode into Actor.
func TestActor_DecodesDelegationFields(t *testing.T) {
	body := `{"valid":true,"user_id":"u1","org_id":"o1","is_delegation":true,` +
		`"acting_as":"u2","delegation_scope":["world.read"],"delegation_chain":["u2","u1"]}`
	var a Actor
	if err := json.Unmarshal([]byte(body), &a); err != nil {
		t.Fatal(err)
	}
	if !a.IsDelegation || a.ActingAs != "u2" ||
		len(a.DelegationScope) != 1 || len(a.DelegationChain) != 2 {
		t.Fatalf("F-02 regression: delegation fields lost on decode: %+v", a)
	}
}

// F-02: TokenUserInfo must surface the embedded actor object.
func TestTokenUserInfo_DecodesActor(t *testing.T) {
	body := `{"id":"u1","email":"u1@x","actor":{"id":"u2","email":"u2@x","name":"Svc"}}`
	var u TokenUserInfo
	if err := json.Unmarshal([]byte(body), &u); err != nil {
		t.Fatal(err)
	}
	if u.Actor == nil || u.Actor.ID != "u2" || u.Actor.Email != "u2@x" {
		t.Fatalf("F-02 regression: actor object lost: %+v", u)
	}
}

// F-04: the event-subscription create body must carry the server-required
// name and endpoint (and must not send the old url).
func TestEventSubscriptionCreate_MarshalsRequiredFields(t *testing.T) {
	b, _ := json.Marshal(EventSubscriptionCreate{
		Name: "hook", Endpoint: "https://x/y", EventTypes: []string{"user.created"},
	})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"name", "endpoint", "event_types"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("F-04 regression: missing required %q in %s", k, b)
		}
	}
	if _, ok := m["url"]; ok {
		t.Fatalf("F-04 regression: obsolete 'url' still sent: %s", b)
	}
}

// F-04: the network-policy create body must carry org_id, action, networks.
func TestCreateNetworkPolicyRequest_MarshalsRequiredFields(t *testing.T) {
	b, _ := json.Marshal(CreateNetworkPolicyRequest{
		OrgID: "o1", Name: "p", Action: "deny", Networks: []string{"10.0.0.0/8"},
	})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"org_id", "action", "networks", "name"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("F-04 regression: missing required %q in %s", k, b)
		}
	}
	for _, k := range []string{"cidrs", "mode"} {
		if _, ok := m[k]; ok {
			t.Fatalf("F-04 regression: obsolete %q still sent: %s", k, b)
		}
	}
}

// F-05/F-08: /health fields the server returns must survive decode, and the
// phantom 'components' must be gone from the type.
func TestHealthCheckResponse_DecodesServerFields(t *testing.T) {
	// timestamp is a real numeric epoch — the value both backends actually send.
	body := `{"status":"ok","version":"1","timestamp":1787879913.98,"checks":{"db":"ok"},` +
		`"uptime_sec":12.5,"service":"auth","dependencies":{"redis":"ok"}}`
	var hr HealthCheckResponse
	if err := json.Unmarshal([]byte(body), &hr); err != nil {
		t.Fatal(err)
	}
	if hr.Status != "ok" || hr.Service != "auth" || hr.UptimeSec != 12.5 ||
		hr.Timestamp == 0 || len(hr.Checks) == 0 || len(hr.Dependencies) == 0 {
		t.Fatalf("F-05 regression: health fields lost: %+v", hr)
	}
}

// F-09: /auth/validate-api-key returns TokenValidationResponse on both backends,
// so APIKeyValidation must surface the failure reason from the "error" wire field
// (previously read from a "reason" field the server never sends, so it was always
// empty) and must model delegation (a service account can act on another's behalf).
func TestValidateAPIKey_DecodesErrorAndDelegation(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/validate-api-key" {
			http.NotFound(w, r)
			return
		}
		// The shared TokenValidationResponse shape, as both backends emit it.
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":            true,
			"user_id":          "svc1",
			"org_id":           "o1",
			"email":            "svc@x",
			"audience":         []string{"engine"},
			"expires_at":       "2026-01-01T00:00:00Z",
			"error":            "",
			"is_delegation":    true,
			"acting_as":        "u9",
			"delegation_chain": []string{"svc1", "u9"},
		})
	}
	c, _ := newTestClient(t, h)
	v, err := c.ValidateAPIKey(context.Background(), ValidateAPIKeyRequest{APIKey: "ab0t_sk_x"})
	if err != nil {
		t.Fatal(err)
	}
	if !v.IsDelegation || v.ActingAs != "u9" || v.Email != "svc@x" || len(v.Audience) != 1 {
		t.Fatalf("F-09: delegation/email/audience stripped from APIKeyValidation: %+v", v)
	}

	// And the failure reason must come through from the "error" field.
	h2 := func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": "revoked"})
	}
	c2, _ := newTestClient(t, h2)
	v2, err := c2.ValidateAPIKey(context.Background(), ValidateAPIKeyRequest{APIKey: "ab0t_sk_x"})
	if err != nil {
		t.Fatal(err)
	}
	if v2.Reason != "revoked" {
		t.Fatalf("F-09: APIKeyValidation.Reason not read from the \"error\" field: %q", v2.Reason)
	}
}

// F-12 (value/type contract): the server returns `timestamp` as a NUMBER and
// quota `usage`/`tiers` as OBJECT MAPS. Modeling these as string/array made
// encoding/json fail the whole decode. These bodies mirror the real wire shape.
func TestHealth_DecodesNumericTimestamp(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","version":"1","timestamp":1787879913.98,"dependencies":{"redis":"ok"}}`))
	}
	c, _ := newTestClient(t, h)
	hc, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("F-12: /health failed to decode a numeric timestamp: %v", err)
	}
	if hc.Timestamp == 0 || hc.Status != "ok" {
		t.Fatalf("F-12: health decoded wrong: %+v", hc)
	}
}

func TestQuotaUsage_DecodesObjectMaps(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user_id":"u1","tier":"pro","usage":{"api_calls":42},"limits":{"api_calls":1000},"percentages":{"api_calls":4.2}}`))
	}
	c, _ := newTestClient(t, h)
	u, err := c.MyQuotaUsage(context.Background(), "t")
	if err != nil {
		t.Fatalf("F-12: /quotas/my-usage failed to decode object maps: %v", err)
	}
	if u.Usage["api_calls"] != 42 || u.Limits["api_calls"] != 1000 || u.Tier != "pro" {
		t.Fatalf("F-12: quota usage decoded wrong: %+v", u)
	}
}
