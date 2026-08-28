package authclient

import (
	"encoding/json"
	"testing"
)

// F-10: response structs previously dropped most server fields. These decode
// realistic bodies (real values, not placeholders) and assert the newly-added
// fields survive across the type kinds involved (string/bool/int/[]string/object).
func TestResponseFields_DecodeAddedFields(t *testing.T) {
	t.Run("APIKey rich fields", func(t *testing.T) {
		var k APIKey
		mustJSON(t, `{"id":"k1","name":"ci","is_active":true,"last_used":"2026-01-01T00:00:00Z","rate_limit":1000}`, &k)
		if !k.IsActive || k.LastUsed == "" || k.RateLimit != 1000 {
			t.Fatalf("APIKey lost fields: %+v", k)
		}
	})
	t.Run("Provider rich fields", func(t *testing.T) {
		var p Provider
		mustJSON(t, `{"id":"p1","provider_type":"google","is_active":true,"is_default":false,"status":"enabled","org_id":"o1","metadata":{"k":"v"}}`, &p)
		if p.ProviderType != "google" || !p.IsActive || p.Status != "enabled" || len(p.Metadata) == 0 {
			t.Fatalf("Provider lost fields: %+v", p)
		}
	})
	t.Run("SSODomainConfigResponse arrays+bools", func(t *testing.T) {
		var d SSODomainConfigResponse
		mustJSON(t, `{"active":true,"entity_id":"e1","allowed_auth_methods":["saml","oidc"],"require_mfa":true,"session_timeout":3600}`, &d)
		if !d.Active || d.EntityID != "e1" || len(d.AllowedAuthMethods) != 2 || !d.RequireMFA {
			t.Fatalf("SSODomainConfigResponse lost fields: %+v", d)
		}
	})
	t.Run("NetworkPolicyCreateResponse", func(t *testing.T) {
		var n NetworkPolicyCreateResponse
		mustJSON(t, `{"policy_id":"np1","action":"deny","name":"block-eu","org_id":"o1","status":"active"}`, &n)
		if n.Action != "deny" || n.Name != "block-eu" || n.OrgID != "o1" {
			t.Fatalf("NetworkPolicyCreateResponse lost fields: %+v", n)
		}
	})
	t.Run("ElevatePrivilegesResponse", func(t *testing.T) {
		var e ElevatePrivilegesResponse
		mustJSON(t, `{"new_role":"admin","password_reset_required":true,"stricter_policy_applied":true,"elevation_expires_at":"2026-01-01T00:00:00Z"}`, &e)
		if e.NewRole != "admin" || !e.PasswordResetRequired || !e.StricterPolicyApplied {
			t.Fatalf("ElevatePrivilegesResponse lost fields: %+v", e)
		}
	})
	t.Run("EmailStatsResponse", func(t *testing.T) {
		var s EmailStatsResponse
		mustJSON(t, `{"org_id":"o1","total":10,"by_status":{"sent":8,"failed":2},"by_type":{"welcome":10}}`, &s)
		if s.OrgID != "o1" || s.Total != 10 || len(s.ByStatus) == 0 {
			t.Fatalf("EmailStatsResponse lost fields: %+v", s)
		}
	})
}

func mustJSON(t *testing.T, body string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), v); err != nil {
		t.Fatalf("decode failed (real value rejected): %v", err)
	}
}
