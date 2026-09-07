package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// These tests decode REAL API-shaped JSON bodies (copied from the goauth
// handler encode sites, not from SDK structs) to prove the SDK request/response
// structs match the wire shape the auth API actually produces/accepts. They are
// the regression guard for CLASS-34 ("Silent Unknown-Field Drop"): a struct that
// under-exposes or type-mismatches an API field will fail one of these.

// P0-1: GET /organizations/{org_id}/users returns a BARE array of member
// objects (goauth orgs/members.go ListMembers -> WriteJSON(out []orgUserResponse)).
func TestWireShape_ListOrgUsers_BareArray(t *testing.T) {
	body := `[
	  {"id":"usr_1","user_id":"usr_1","email":"a@b.com","name":"A B","provider_type":"internal",
	   "role":"admin","status":"active","email_verified":true,"timezone":"UTC","language":"en",
	   "org_id":"org1","team_id":"team_1","joined_at":"2026-01-02T03:04:05Z",
	   "org_permissions":["users.read","users.write"],"metadata":{"k":"v"}}
	]`
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		expect(t, r, "GET", "/organizations/org1/users")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	got, err := c.ListOrgUsers(context.Background(), "org1", "tok")
	if err != nil {
		t.Fatalf("ListOrgUsers hard-errored decoding bare array: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 member, got %d", len(got))
	}
	m := got[0]
	if m.UserID != "usr_1" || m.Role != "admin" || m.TeamID != "team_1" ||
		m.JoinedAt != "2026-01-02T03:04:05Z" || len(m.OrgPermissions) != 2 || m.Metadata["k"] != "v" {
		t.Fatalf("member fields not decoded from wire: %+v", m)
	}
}

// P0-2: GET/PUT /organizations/{org_id}/login-config uses five nested sections
// at the TOP LEVEL; PUT 400-rejects unknown top-level keys. Prove the merged GET
// body decodes and a partial PUT marshals to section-nested keys only.
func TestWireShape_LoginConfig_NestedSections(t *testing.T) {
	// A real merged GET body (goauth loginConfigDefaults deep-merged).
	body := `{
	  "branding":{"logo_url":"https://x/y.png","primary_color":"#2563EB","hide_powered_by":false,
	              "security_badge":{"ssl":true,"soc2":true}},
	  "content":{"welcome_message":"Hi","trust_logos":[]},
	  "auth_methods":{"email_password":true,"signup_enabled":true,"invitation_only":false},
	  "registration":{"default_role":"end_user","default_landing":"parent",
	                  "org_structure":{"pattern":"flat","config":{}}},
	  "security":{"remember_me_enabled":true,"accept_invite_allowed_origins":["https://app.example.com"]}
	}`
	var cfg LoginConfig
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("decode merged login-config: %v", err)
	}
	if cfg.Branding == nil || cfg.Branding.LogoURL == nil || *cfg.Branding.LogoURL != "https://x/y.png" {
		t.Fatalf("branding not decoded: %+v", cfg.Branding)
	}
	if cfg.Registration == nil || cfg.Registration.DefaultLanding == nil || *cfg.Registration.DefaultLanding != "parent" {
		t.Fatalf("registration.default_landing not decoded: %+v", cfg.Registration)
	}
	if cfg.Security == nil || len(cfg.Security.AcceptInviteAllowedOrigins) != 1 {
		t.Fatalf("security.accept_invite_allowed_origins not decoded: %+v", cfg.Security)
	}

	// A partial PUT must serialize to nested sections ONLY (no flat top-level keys
	// like logo_url, which the API rejects with 400 "Unknown config section").
	on := true
	upd := LoginConfigUpdate{AuthMethods: &LoginConfigAuthMethods{SignupEnabled: &on}}
	keys := mustMarshalKeys(t, upd)
	if _, ok := keys["auth_methods"]; !ok {
		t.Fatalf("partial PUT missing auth_methods section: %v", keys)
	}
	for _, forbidden := range []string{"logo_url", "signup_enabled", "primary_color", "allow_signup"} {
		if _, bad := keys[forbidden]; bad {
			t.Fatalf("partial PUT leaked flat top-level key %q (API would 400): %v", forbidden, keys)
		}
	}
}

// P0-3: POST authorization-models body must be FLAT {schema_version,
// type_definitions} — never a {model:{...}} envelope, never a phantom dsl.
func TestWireShape_WriteAuthorizationModel_FlatBody(t *testing.T) {
	req := WriteAuthorizationModelRequest{Model: AuthorizationModel{
		SchemaVersion:   "1.1",
		DSL:             "type document", // must NOT be sent
		TypeDefinitions: []map[string]any{{"type": "document"}},
	}}
	keys := mustMarshalKeys(t, req)
	if _, ok := keys["type_definitions"]; !ok {
		t.Fatalf("missing top-level type_definitions: %v", keys)
	}
	if _, ok := keys["schema_version"]; !ok {
		t.Fatalf("missing top-level schema_version: %v", keys)
	}
	for _, bad := range []string{"model", "dsl"} {
		if _, present := keys[bad]; present {
			t.Fatalf("body leaked %q (server would 400 or ignore): %v", bad, keys)
		}
	}
}

// P0-4: GET .../hierarchy nests the ROOT under "organization" but FLATTENS each
// child (org fields inline + recursive "children"). Prove children decode with
// their org fields intact.
func TestWireShape_OrgHierarchy_FlattenedChildren(t *testing.T) {
	body := `{
	  "organization":{"id":"org1","name":"Acme","slug":"acme"},
	  "teams":[],"user_count":2,"team_count":0,
	  "children":[
	     {"id":"org2","name":"Acme EU","slug":"acme-eu","parent_id":"org1",
	      "children":[{"id":"org3","name":"Acme DE","parent_id":"org2","children":[]}]}
	  ]
	}`
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		expect(t, r, "GET", "/organizations/org1/hierarchy")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	h, err := c.GetOrgHierarchy(context.Background(), "org1", "tok")
	if err != nil {
		t.Fatalf("GetOrgHierarchy: %v", err)
	}
	if h.Organization == nil || h.Organization.ID != "org1" {
		t.Fatalf("root org not decoded: %+v", h.Organization)
	}
	if len(h.Children) != 1 || h.Children[0].ID != "org2" || h.Children[0].ParentID != "org1" {
		t.Fatalf("child org fields dropped (flattened shape not modelled): %+v", h.Children)
	}
	if len(h.Children[0].Children) != 1 || h.Children[0].Children[0].ID != "org3" {
		t.Fatalf("grandchild not decoded: %+v", h.Children[0].Children)
	}
	var ids []string
	h.WalkOrgTree(func(org *OrgInfo, d int) { ids = append(ids, org.ID) })
	if len(ids) != 3 || ids[0] != "org1" || ids[1] != "org2" || ids[2] != "org3" {
		t.Fatalf("WalkOrgTree = %v, want [org1 org2 org3]", ids)
	}
}

// P0-5: GET .../sessions uses session_id/last_accessed/total_sessions (NOT
// id/last_seen_at/total) and carries user_email/user_name.
func TestWireShape_OrgSessions_Keys(t *testing.T) {
	body := `{"organization_id":"org1","total_sessions":1,"sessions":[
	  {"session_id":"sess_1","user_id":"u1","user_email":"a@b.com","user_name":"A",
	   "created_at":"t0","last_accessed":"t1","ip_address":"1.2.3.4","user_agent":"curl"}]}`
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		expect(t, r, "GET", "/organizations/org1/sessions")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	s, err := c.ListOrgSessions(context.Background(), "org1", "tok")
	if err != nil {
		t.Fatalf("ListOrgSessions: %v", err)
	}
	if s.TotalSessions != 1 || s.OrganizationID != "org1" || len(s.Sessions) != 1 {
		t.Fatalf("envelope not decoded: %+v", s)
	}
	m := s.Sessions[0]
	if m.SessionID != "sess_1" || m.LastAccessed != "t1" || m.UserEmail != "a@b.com" {
		t.Fatalf("session fields not decoded (wrong keys?): %+v", m)
	}
}

// P1: register bodies must carry invitation_code (invite-join) and must NOT leak
// phantom fields the API ignores.
func TestWireShape_RegisterBodies(t *testing.T) {
	rk := mustMarshalKeys(t, RegisterRequest{Email: "a@b.com", Password: "x", InvitationCode: "inv_1"})
	if _, ok := rk["invitation_code"]; !ok {
		t.Fatalf("RegisterRequest missing invitation_code: %v", rk)
	}
	if _, bad := rk["provider_type"]; bad {
		t.Fatalf("RegisterRequest leaks phantom provider_type: %v", rk)
	}
	ok := mustMarshalKeys(t, OrgRegisterRequest{Email: "a@b.com", Password: "x", ClientID: "c1", InvitationCode: "inv_1"})
	for _, want := range []string{"invitation_code", "client_id"} {
		if _, present := ok[want]; !present {
			t.Fatalf("OrgRegisterRequest missing %q: %v", want, ok)
		}
	}
	for _, bad := range []string{"first_name", "last_name"} {
		if _, present := ok[bad]; present {
			t.Fatalf("OrgRegisterRequest leaks phantom %q: %v", bad, ok)
		}
	}
}

// P1: APIKeyCreate must be able to set rate_limit and must not leak ignored
// org_id/audience.
func TestWireShape_APIKeyCreate(t *testing.T) {
	rl := int64(100)
	keys := mustMarshalKeys(t, APIKeyCreate{Name: "ci", RateLimit: &rl})
	if _, ok := keys["rate_limit"]; !ok {
		t.Fatalf("APIKeyCreate cannot set rate_limit: %v", keys)
	}
	for _, bad := range []string{"org_id", "audience"} {
		if _, present := keys[bad]; present {
			t.Fatalf("APIKeyCreate leaks ignored %q: %v", bad, keys)
		}
	}
}

// P1: provider create/update use provider_type + is_active (not type/enabled) and
// never leak top-level client_id/issuer_url/domain (those live in config).
func TestWireShape_ProviderConfig(t *testing.T) {
	ck := mustMarshalKeys(t, ProviderConfigCreate{Name: "g", ProviderType: "google", IsDefault: true})
	if _, ok := ck["provider_type"]; !ok {
		t.Fatalf("ProviderConfigCreate missing provider_type: %v", ck)
	}
	for _, bad := range []string{"type", "enabled", "client_id", "client_secret", "issuer_url", "domain"} {
		if _, present := ck[bad]; present {
			t.Fatalf("ProviderConfigCreate leaks ignored top-level %q: %v", bad, ck)
		}
	}
	on := false
	uk := mustMarshalKeys(t, ProviderConfigUpdate{IsActive: &on})
	if _, ok := uk["is_active"]; !ok {
		t.Fatalf("ProviderConfigUpdate cannot toggle is_active: %v", uk)
	}
	if _, bad := uk["enabled"]; bad {
		t.Fatalf("ProviderConfigUpdate leaks ignored enabled: %v", uk)
	}
}

// P1: OrganizationInvite uses a single team_id + permissions (not team_ids/resend),
// and InviteResult exposes the invitation_code.
func TestWireShape_OrganizationInvite(t *testing.T) {
	keys := mustMarshalKeys(t, OrganizationInvite{Email: "a@b.com", TeamID: "t1", Permissions: []string{"users.read"}})
	if _, ok := keys["team_id"]; !ok {
		t.Fatalf("OrganizationInvite missing team_id: %v", keys)
	}
	if _, ok := keys["permissions"]; !ok {
		t.Fatalf("OrganizationInvite missing permissions: %v", keys)
	}
	for _, bad := range []string{"team_ids", "resend"} {
		if _, present := keys[bad]; present {
			t.Fatalf("OrganizationInvite leaks %q: %v", bad, keys)
		}
	}
	var res InviteResult
	if err := json.Unmarshal([]byte(`{"message":"ok","invitation_id":"i1","invitation_code":"c1","expires_at":"t"}`), &res); err != nil {
		t.Fatalf("decode InviteResult: %v", err)
	}
	if res.InvitationCode != "c1" {
		t.Fatalf("InviteResult dropped invitation_code: %+v", res)
	}
}

// P1: ClientRegistration (DCR) can now SET the RFC-7591 metadata the response
// already returned.
func TestWireShape_ClientRegistration_Metadata(t *testing.T) {
	keys := mustMarshalKeys(t, ClientRegistration{
		ClientName: "app", ClientURI: "https://a", TOSURI: "https://a/tos",
		SoftwareID: "sid", SoftwareVersion: "1.2.3",
	})
	for _, want := range []string{"client_uri", "tos_uri", "software_id", "software_version"} {
		if _, ok := keys[want]; !ok {
			t.Fatalf("ClientRegistration cannot set %q: %v", want, keys)
		}
	}
}

// P1: TeamMember exposes team_id/permissions/joined_at (not added_at/email/name);
// TeamPermissionsResponse exposes inherited_permissions.
func TestWireShape_TeamMemberAndPermissions(t *testing.T) {
	var m []TeamMember
	if err := json.Unmarshal([]byte(`[{"user_id":"u1","team_id":"t1","role":"lead","permissions":["a","b"],"joined_at":"t0"}]`), &m); err != nil {
		t.Fatalf("decode members: %v", err)
	}
	if len(m) != 1 || m[0].TeamID != "t1" || len(m[0].Permissions) != 2 || m[0].JoinedAt != "t0" {
		t.Fatalf("TeamMember fields not decoded: %+v", m)
	}
	var p TeamPermissionsResponse
	if err := json.Unmarshal([]byte(`{"team_id":"t1","permissions":["a"],"inherited_permissions":["parent.x"]}`), &p); err != nil {
		t.Fatalf("decode perms: %v", err)
	}
	if len(p.InheritedPermissions) != 1 || p.InheritedPermissions[0] != "parent.x" {
		t.Fatalf("inherited_permissions dropped: %+v", p)
	}
}

// P1: org create/update expose profile fields + slug/parent_id, and never send
// billing_type (create ignores it, update 400s on it) or a phantom status.
func TestWireShape_OrganizationCreateUpdate(t *testing.T) {
	ck := mustMarshalKeys(t, OrganizationCreate{Name: "Acme", LogoURL: "l", Website: "w", Industry: "i", Size: "s"})
	for _, want := range []string{"logo_url", "website", "industry", "size"} {
		if _, ok := ck[want]; !ok {
			t.Fatalf("OrganizationCreate missing %q: %v", want, ck)
		}
	}
	if _, bad := ck["billing_type"]; bad {
		t.Fatalf("OrganizationCreate leaks ignored billing_type: %v", ck)
	}
	slug := "acme-eu"
	pid := "org1"
	uk := mustMarshalKeys(t, OrganizationUpdate{Slug: &slug, ParentID: &pid})
	for _, want := range []string{"slug", "parent_id"} {
		if _, ok := uk[want]; !ok {
			t.Fatalf("OrganizationUpdate missing %q: %v", want, uk)
		}
	}
	for _, bad := range []string{"billing_type", "status"} {
		if _, present := uk[bad]; present {
			t.Fatalf("OrganizationUpdate leaks %q (update 400s/ignores it): %v", bad, uk)
		}
	}
	// audience_status decodes on the response.
	var org Organization
	if err := json.Unmarshal([]byte(`{"id":"o1","name":"Acme","audience_status":"local_fallback"}`), &org); err != nil {
		t.Fatalf("decode Organization: %v", err)
	}
	if org.AudienceStatus != "local_fallback" {
		t.Fatalf("Organization dropped audience_status: %+v", org)
	}
}

// P1: POST .../read tuples carry expires_at; ReadRelationshipsForSubject exposes
// it (break-glass/GDPR lapse visibility).
func TestWireShape_ReadRelationshipsForSubject_ExpiresAt(t *testing.T) {
	body := `{"tuples":[
	  {"key":{"object":"doc:1","relation":"viewer","user":"user:alice"},"timestamp":"t0","expires_at":"2026-12-31T00:00:00Z"},
	  {"key":{"object":"doc:2","relation":"editor","user":"user:alice"},"timestamp":"t1","expires_at":null}
	],"continuation_token":""}`
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		expect(t, r, "POST", "/zanzibar/stores/s1/read")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	got, err := c.ReadRelationshipsForSubject(context.Background(), "s1", "user", "alice", "tok")
	if err != nil {
		t.Fatalf("ReadRelationshipsForSubject: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 tuples, got %d", len(got))
	}
	if got[0].Object != "doc:1" || got[0].ExpiresAt != "2026-12-31T00:00:00Z" {
		t.Fatalf("expires_at dropped: %+v", got[0])
	}
	if got[1].ExpiresAt != "" {
		t.Fatalf("null expires_at should be empty: %+v", got[1])
	}
}

// P1: admin AdminUserUpdate can set status (suspend/pending); self UserUpdate can't.
func TestWireShape_AdminUserUpdate_Status(t *testing.T) {
	st := "suspended"
	nm := "New"
	keys := mustMarshalKeys(t, AdminUserUpdate{UserUpdate: UserUpdate{Name: &nm}, Status: &st})
	if _, ok := keys["status"]; !ok {
		t.Fatalf("AdminUserUpdate cannot set status: %v", keys)
	}
	if _, ok := keys["name"]; !ok {
		t.Fatalf("embedded UserUpdate fields not promoted: %v", keys)
	}
	// Self update must NOT carry status (the /users/me handler ignores it).
	selfKeys := mustMarshalKeys(t, UserUpdate{Name: &nm})
	if _, present := selfKeys["status"]; present {
		t.Fatalf("self UserUpdate leaks status: %v", selfKeys)
	}
}

// P3 (over-exposure/footguns): TokenValidationRequest must NOT carry resource_type/
// resource_id (the endpoint ignores them → silent-unscoped hazard); OrgRoleUpdate
// must NOT carry permissions (ignored by the role-update handler).
func TestWireShape_OverExposure_FootgunsClosed(t *testing.T) {
	tk := mustMarshalKeys(t, TokenValidationRequest{Token: "t", RequiredPermissions: []string{"a"}})
	for _, bad := range []string{"resource_type", "resource_id"} {
		if _, present := tk[bad]; present {
			t.Fatalf("TokenValidationRequest leaks ignored %q (silent-unscoped footgun): %v", bad, tk)
		}
	}
	rk := mustMarshalKeys(t, OrgRoleUpdate{Role: "admin"})
	if _, present := rk["permissions"]; present {
		t.Fatalf("OrgRoleUpdate leaks ignored permissions: %v", rk)
	}
}

// P4: GET .../clients returns a BARE array of safe client views.
func TestWireShape_ListOrgClients_BareArray(t *testing.T) {
	body := `[{"client_id":"c1","client_name":"App","client_type":"web","client_uri":"https://a",
	           "redirect_uris":["https://a/cb"],"response_types":["code"],"grant_types":["authorization_code"],
	           "scope":"openid","status":"active","org_id":"org1"}]`
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		expect(t, r, "GET", "/organizations/org1/clients")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	got, err := c.ListOrgClients(context.Background(), "org1", "tok")
	if err != nil {
		t.Fatalf("ListOrgClients hard-errored on bare array: %v", err)
	}
	if len(got) != 1 || got[0].ClientID != "c1" || got[0].ClientType != "web" || got[0].Scope != "openid" {
		t.Fatalf("client fields not decoded: %+v", got)
	}
}

// P4: WriteAndDeleteRelationships targets .../write with {object,relation,subject}
// tuples (transact request MarshalJSON drops context/expires_at).
func TestWireShape_TransactWriteBody(t *testing.T) {
	future := time.Now().Add(time.Hour)
	b, err := json.Marshal(TransactRelationshipsRequest{
		Writes:  []RelationshipRequest{{Object: "doc:1", Relation: "parent", Subject: "folder:a", ExpiresAt: &future, Context: map[string]any{"x": 1}}},
		Deletes: nil,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, bad := range []string{"expires_at", "context"} {
		if strings.Contains(s, bad) {
			t.Fatalf("transact body leaked %q: %s", bad, s)
		}
	}
	if !strings.Contains(s, `"object":"doc:1"`) || !strings.Contains(s, `"writes"`) {
		t.Fatalf("transact body wrong shape: %s", s)
	}
}

// P4: zanzibar model-assertions surface (put/get/run) round-trips the real shapes.
func TestWireShape_ModelAssertions(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "PUT" && r.URL.Path == "/zanzibar/stores/s1/assertions/m1":
			var body PutAssertionsRequest
			readBody(t, r, &body)
			if len(body.Assertions) != 1 || body.Assertions[0].TupleKey.Object != "doc:1" || !body.Assertions[0].Expectation {
				t.Errorf("put body wrong: %+v", body)
			}
			writeJSON(w, 200, MessageResponse{Message: "assertions stored"})
		case r.Method == "GET" && r.URL.Path == "/zanzibar/stores/s1/assertions/m1":
			_, _ = w.Write([]byte(`{"authorization_model_id":"m1","assertions":[{"tuple_key":{"object":"doc:1","relation":"viewer","user":"user:a"},"expectation":true}]}`))
		case r.Method == "POST" && r.URL.Path == "/zanzibar/stores/s1/assertions/m1/run":
			_, _ = w.Write([]byte(`{"authorization_model_id":"m1","passed":false,"results":[{"tuple_key":{"object":"doc:1","relation":"viewer","user":"user:a"},"expectation":true,"got":false,"passed":false,"reason":"no path"}]}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	ctx := context.Background()
	if _, err := c.PutModelAssertions(ctx, "s1", "m1", PutAssertionsRequest{Assertions: []ModelAssertion{{TupleKey: AssertionTupleKey{Object: "doc:1", Relation: "viewer", User: "user:a"}, Expectation: true}}}, "tok"); err != nil {
		t.Fatalf("PutModelAssertions: %v", err)
	}
	g, err := c.GetModelAssertions(ctx, "s1", "m1", "tok")
	if err != nil || g.AuthorizationModelID != "m1" || len(g.Assertions) != 1 {
		t.Fatalf("GetModelAssertions: %v %+v", err, g)
	}
	run, err := c.RunModelAssertions(ctx, "s1", "m1", "tok")
	if err != nil || run.Passed || len(run.Results) != 1 || run.Results[0].Got {
		t.Fatalf("RunModelAssertions: %v %+v", err, run)
	}
	if run.Results[0].Reason != "no path" {
		t.Fatalf("assertion result reason not decoded: %+v", run.Results[0])
	}
}

// helper: assert a value marshals to JSON containing exactly the given key paths
// at top level (used to prove request structs emit the keys the API decodes).
func mustMarshalKeys(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	return m
}
