package authclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// readBody is a small helper to decode a request body into v.
func readBody(t *testing.T, r *http.Request, v any) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && err != io.EOF {
		t.Fatalf("decode body: %v", err)
	}
}

// expect asserts method + path on the incoming request.
func expect(t *testing.T, r *http.Request, method, path string) {
	t.Helper()
	if r.Method != method || r.URL.Path != path {
		t.Errorf("got %s %s, want %s %s", r.Method, r.URL.Path, method, path)
	}
}

// ===================== Users domain =====================

func TestUserSelfService(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && r.URL.Path == "/users/me":
			var upd UserUpdate
			readBody(t, r, &upd)
			if upd.Name == nil || *upd.Name != "Neo" {
				t.Errorf("name not forwarded: %+v", upd)
			}
			writeJSON(w, 200, User{ID: "u1", Name: "Neo"})
		case r.Method == "POST" && r.URL.Path == "/users/me/change-password":
			writeJSON(w, 200, MessageResponse{Success: true, Message: "changed"})
		default:
			expect(t, r, "GET", "/users/me")
			writeJSON(w, 200, User{ID: "u1", Email: "a@b.com"})
		}
	})

	if _, err := c.GetMyProfile(context.Background(), "tok"); err != nil {
		t.Fatalf("GetMyProfile: %v", err)
	}
	name := "Neo"
	u, err := c.UpdateMyProfile(context.Background(), "tok", UserUpdate{Name: &name})
	if err != nil || u.Name != "Neo" {
		t.Fatalf("UpdateMyProfile: %v %+v", err, u)
	}
	m, err := c.ChangeMyPassword(context.Background(), "tok", ChangePassword{CurrentPassword: "x", NewPassword: "y"})
	if err != nil || !m.Success {
		t.Fatalf("ChangeMyPassword: %v %+v", err, m)
	}
}

func TestUserAdminLifecycle(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// service API key fallback must authenticate admin ops.
		if r.Header.Get("Authorization") != "Bearer ab0t_sk_admin" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/users/u9/deactivate":
			writeJSON(w, 200, MessageDetailResponse{Success: true, Status: "inactive", UserID: "u9"})
		case "/users/u9/activate":
			writeJSON(w, 200, MessageDetailResponse{Success: true, Status: "active", UserID: "u9"})
		case "/users/u9/verify-email":
			writeJSON(w, 200, MessageResponse{Success: true})
		case "/users/u9":
			writeJSON(w, 200, MessageResponse{Message: "updated"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}, WithAPIKey("ab0t_sk_admin"))

	if _, err := c.DeactivateUser(context.Background(), "u9", ""); err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}
	if _, err := c.ActivateUser(context.Background(), "u9", ""); err != nil {
		t.Fatalf("ActivateUser: %v", err)
	}
	if _, err := c.VerifyUserEmail(context.Background(), "u9", ""); err != nil {
		t.Fatalf("VerifyUserEmail: %v", err)
	}
	nm := "X"
	if _, err := c.UpdateUser(context.Background(), "u9", UserUpdate{Name: &nm}, ""); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
}

func TestPasswordResetPublic(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("public endpoint should not send auth: %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/users/request-password-reset":
			writeJSON(w, 200, PasswordResetResponse{Success: true})
		case "/users/reset-password":
			writeJSON(w, 200, PasswordResetConfirmResponse{Success: true})
		}
	})
	if _, err := c.RequestPasswordReset(context.Background(), PasswordReset{Email: "a@b.com"}); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if _, err := c.ResetPassword(context.Background(), PasswordResetConfirm{Token: "t", NewPassword: "n"}); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
}

// ===================== Orgs + teams domain =====================

func TestOrganizationLifecycle(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/organizations/":
			var req OrganizationCreate
			readBody(t, r, &req)
			if req.Name != "Acme" {
				t.Errorf("name = %q", req.Name)
			}
			writeJSON(w, 200, Organization{ID: "org1", Name: "Acme"})
		case r.Method == "PUT" && r.URL.Path == "/organizations/org1":
			writeJSON(w, 200, MessageResponse{Message: "ok"})
		case r.Method == "DELETE" && r.URL.Path == "/organizations/org1":
			writeJSON(w, 200, MessageResponse{Message: "deleted"})
		case r.URL.Path == "/organizations/org1/hierarchy":
			// The real contract: {organization, teams, children, counts}. The
			// old test asserted a shape the service never returns, so it passed
			// while the SDK could only ever have decoded zeros.
			writeJSON(w, 200, OrgHierarchyResponse{
				Organization: &OrgInfo{ID: "org1", Slug: "acme"},
				TeamCount:    1, UserCount: 2,
				Children: []OrgHierarchyResponse{{
					Organization: &OrgInfo{ID: "org2", Slug: "acme-eu", ParentID: "org1"},
				}},
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	org, err := c.CreateOrganization(context.Background(), OrganizationCreate{Name: "Acme"}, "tok")
	if err != nil || org.ID != "org1" {
		t.Fatalf("CreateOrganization: %v %+v", err, org)
	}
	nm := "Acme2"
	if _, err := c.UpdateOrganization(context.Background(), "org1", OrganizationUpdate{Name: &nm}, "tok"); err != nil {
		t.Fatalf("UpdateOrganization: %v", err)
	}
	if _, err := c.DeleteOrganization(context.Background(), "org1", "tok"); err != nil {
		t.Fatalf("DeleteOrganization: %v", err)
	}
	h, err := c.GetOrgHierarchy(context.Background(), "org1", "tok")
	if err != nil || h.Organization == nil || h.Organization.ID != "org1" {
		t.Fatalf("GetOrgHierarchy: %v %+v", err, h)
	}
	if h.TeamCount != 1 || h.UserCount != 2 {
		t.Errorf("counts not decoded: teams=%d users=%d", h.TeamCount, h.UserCount)
	}
	// Companies of companies: the child must decode, and carry its parent link.
	if len(h.Children) != 1 || h.Children[0].Organization.ParentID != "org1" {
		t.Fatalf("sub-organization not decoded: %+v", h.Children)
	}
	// WalkOrgTree must visit root and children, in order, with depth.
	var seen []string
	var depths []int
	h.WalkOrgTree(func(n *OrgHierarchyResponse, d int) {
		seen = append(seen, n.Organization.ID)
		depths = append(depths, d)
	})
	if len(seen) != 2 || seen[0] != "org1" || seen[1] != "org2" {
		t.Errorf("WalkOrgTree visited %v, want [org1 org2]", seen)
	}
	if depths[0] != 0 || depths[1] != 1 {
		t.Errorf("WalkOrgTree depths = %v, want [0 1]", depths)
	}
}

func TestOrgMembershipAndInvites(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/organizations/org1/users":
			writeJSON(w, 200, OrgUserResponse{Users: []OrgMember{{UserID: "u1", Role: "member"}}, Total: 1})
		case "/organizations/org1/users/u1":
			if r.Method == "PUT" {
				var req OrgRoleUpdate
				readBody(t, r, &req)
				if req.Role != "admin" {
					t.Errorf("role = %q", req.Role)
				}
				writeJSON(w, 200, RoleUpdateResponse{Role: "admin", UserID: "u1"})
			} else {
				writeJSON(w, 200, MessageResponse{Message: "removed"})
			}
		case "/organizations/org1/invite":
			writeJSON(w, 200, MessageResponse{Message: "invited"})
		case "/organizations/org1/invitations":
			writeJSON(w, 200, []InvitationListItem{{ID: "i1", Email: "x@y.com"}})
		case "/organizations/org1/invitations/i1":
			writeJSON(w, 200, MessageResponse{Message: "cancelled"})
		case "/organizations/org1/sessions":
			if r.Method == "GET" {
				writeJSON(w, 200, OrgSessionsResponse{Sessions: []OrgSession{{ID: "s1"}}})
			} else {
				writeJSON(w, 200, MessageResponse{Message: "revoked"})
			}
		case "/organizations/org1/users/u1/sessions":
			writeJSON(w, 200, SessionRevokeResponse{RevokedCount: 2})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	ctx := context.Background()
	if u, err := c.ListOrgUsers(ctx, "org1", "tok"); err != nil || u.Total != 1 {
		t.Fatalf("ListOrgUsers: %v %+v", err, u)
	}
	if r, err := c.UpdateOrgUserRole(ctx, "org1", "u1", OrgRoleUpdate{Role: "admin"}, "tok"); err != nil || r.Role != "admin" {
		t.Fatalf("UpdateOrgUserRole: %v %+v", err, r)
	}
	if _, err := c.RemoveOrgUser(ctx, "org1", "u1", "tok"); err != nil {
		t.Fatalf("RemoveOrgUser: %v", err)
	}
	if _, err := c.InviteToOrganization(ctx, "org1", OrganizationInvite{Email: "x@y.com"}, "tok"); err != nil {
		t.Fatalf("InviteToOrganization: %v", err)
	}
	if inv, err := c.ListInvitations(ctx, "org1", "tok"); err != nil || len(inv) != 1 {
		t.Fatalf("ListInvitations: %v %+v", err, inv)
	}
	if _, err := c.RevokeInvitation(ctx, "org1", "i1", "tok"); err != nil {
		t.Fatalf("RevokeInvitation: %v", err)
	}
	if s, err := c.ListOrgSessions(ctx, "org1", "tok"); err != nil || len(s.Sessions) != 1 {
		t.Fatalf("ListOrgSessions: %v %+v", err, s)
	}
	if _, err := c.RevokeOrgSessions(ctx, "org1", "tok"); err != nil {
		t.Fatalf("RevokeOrgSessions: %v", err)
	}
	if r, err := c.RevokeUserSessions(ctx, "org1", "u1", "tok"); err != nil || r.RevokedCount != 2 {
		t.Fatalf("RevokeUserSessions: %v %+v", err, r)
	}
}

func TestTeamsDomain(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/organizations/org1/teams":
			if r.Method == "POST" {
				writeJSON(w, 200, Team{ID: "t1", Name: "Eng"})
			} else {
				writeJSON(w, 200, []Team{{ID: "t1", Name: "Eng"}})
			}
		case "/teams/t1":
			switch r.Method {
			case "GET":
				writeJSON(w, 200, Team{ID: "t1", Name: "Eng"})
			default:
				writeJSON(w, 200, MessageResponse{Message: "ok"})
			}
		case "/teams/t1/members":
			if r.Method == "POST" {
				var req TeamMemberAdd
				readBody(t, r, &req)
				if req.UserID != "u1" {
					t.Errorf("member = %q", req.UserID)
				}
				writeJSON(w, 200, MessageResponse{Message: "added"})
			} else {
				writeJSON(w, 200, []TeamMember{{UserID: "u1"}})
			}
		case "/teams/t1/members/u1":
			writeJSON(w, 200, MessageResponse{Message: "ok"})
		case "/teams/t1/permissions":
			writeJSON(w, 200, TeamPermissionsResponse{Permissions: []string{"teams.read"}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	ctx := context.Background()
	if tm, err := c.CreateTeam(ctx, "org1", TeamCreate{Name: "Eng"}, "tok"); err != nil || tm.ID != "t1" {
		t.Fatalf("CreateTeam: %v %+v", err, tm)
	}
	if ts, err := c.ListTeams(ctx, "org1", "tok"); err != nil || len(ts) != 1 {
		t.Fatalf("ListTeams: %v", err)
	}
	if _, err := c.GetTeam(ctx, "t1", "tok"); err != nil {
		t.Fatalf("GetTeam: %v", err)
	}
	desc := "d"
	if _, err := c.UpdateTeam(ctx, "t1", TeamUpdate{Description: &desc}, "tok"); err != nil {
		t.Fatalf("UpdateTeam: %v", err)
	}
	if _, err := c.AddTeamMember(ctx, "t1", TeamMemberAdd{UserID: "u1", Role: "lead"}, "tok"); err != nil {
		t.Fatalf("AddTeamMember: %v", err)
	}
	if mm, err := c.ListTeamMembers(ctx, "t1", "tok"); err != nil || len(mm) != 1 {
		t.Fatalf("ListTeamMembers: %v", err)
	}
	if _, err := c.UpdateTeamMemberRole(ctx, "t1", "u1", TeamMemberRoleUpdate{Role: "lead"}, "tok"); err != nil {
		t.Fatalf("UpdateTeamMemberRole: %v", err)
	}
	if _, err := c.RemoveTeamMember(ctx, "t1", "u1", "tok"); err != nil {
		t.Fatalf("RemoveTeamMember: %v", err)
	}
	if p, err := c.GetTeamPermissions(ctx, "t1", "tok"); err != nil || len(p.Permissions) != 1 {
		t.Fatalf("GetTeamPermissions: %v", err)
	}
	if _, err := c.DeleteTeam(ctx, "t1", "tok"); err != nil {
		t.Fatalf("DeleteTeam: %v", err)
	}
}

// ===================== Roles / permissions registry =====================

func TestRolesGrantAndRegistry(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/permissions/grant":
			if got := r.URL.Query().Get("permission"); got != "world.write" {
				t.Errorf("perm = %q", got)
			}
			if got := r.URL.Query().Get("user_id"); got != "u1" {
				t.Errorf("user_id = %q", got)
			}
			writeJSON(w, 200, MessageResponse{Message: "granted"})
		case "/permissions/revoke":
			writeJSON(w, 200, MessageResponse{Message: "revoked"})
		case "/permissions/registry/services":
			writeJSON(w, 200, RegisteredServicesResponse{Services: []RegisteredService{{Service: "world"}}})
		case "/permissions/registry/valid-permissions":
			writeJSON(w, 200, ValidPermissionsResponse{Permissions: []string{"world.read"}})
		case "/permissions/registry/validate":
			writeJSON(w, 200, PermissionValidationResponse{Valid: true})
		case "/permissions/registry/stats":
			writeJSON(w, 200, RegistryStatsResponse{TotalServices: 3})
		case "/permissions/registry/register":
			var req ServicePermissionRegister
			readBody(t, r, &req)
			if req.Service != "world" {
				t.Errorf("service = %q", req.Service)
			}
			writeJSON(w, 200, ServicePermissionResponse{Service: "world"})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}, WithAPIKey("ab0t_sk_svc"))
	ctx := context.Background()
	if _, err := c.GrantPermission(ctx, "u1", "org1", "world.write", ""); err != nil {
		t.Fatalf("GrantPermission: %v", err)
	}
	if _, err := c.RevokePermission(ctx, "u1", "org1", "world.write", ""); err != nil {
		t.Fatalf("RevokePermission: %v", err)
	}
	if s, err := c.ListRegisteredServices(ctx, ""); err != nil || len(s.Services) != 1 {
		t.Fatalf("ListRegisteredServices: %v", err)
	}
	if _, err := c.ListValidPermissions(ctx); err != nil {
		t.Fatalf("ListValidPermissions: %v", err)
	}
	if v, err := c.ValidatePermissions(ctx, []string{"world.read"}); err != nil || !v.Valid {
		t.Fatalf("ValidatePermissions: %v", err)
	}
	if st, err := c.RegistryStats(ctx); err != nil || st.TotalServices != 3 {
		t.Fatalf("RegistryStats: %v", err)
	}
	if _, err := c.RegisterServicePermissions(ctx, ServicePermissionRegister{Service: "world", Permissions: []string{"world.read"}}, ""); err != nil {
		t.Fatalf("RegisterServicePermissions: %v", err)
	}
}

// ===================== Zanzibar =====================

func TestZanzibarCheckExpandList(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/zanzibar/stores/s1/check":
			var req CheckPermissionRequest
			readBody(t, r, &req)
			if req.Subject != "user:1" || req.Permission != "read" || req.Object != "doc:1" {
				t.Errorf("check body = %+v", req)
			}
			writeJSON(w, 200, CheckPermissionResponse{Allowed: true, Reason: "direct"})
		case "/zanzibar/stores/s1/check/bulk":
			// The live contract is a bare JSON ARRAY of CheckPermissionResponse,
			// one per requested check, in request order.
			writeJSON(w, 200, []CheckPermissionResponse{{Allowed: true, Reason: "direct"}, {Allowed: false, Reason: "no relation"}})
		case "/zanzibar/stores/s1/expand":
			var req ExpandRequest
			readBody(t, r, &req)
			if req.Permission != "read" || req.Object != "doc:1" {
				t.Errorf("expand body = %+v", req)
			}
			writeJSON(w, 200, ExpandResponse{Object: "doc:1", Permission: "read", Subjects: []string{"user:1"}})
		case "/zanzibar/stores/s1/list-objects":
			var req ListObjectsRequest
			readBody(t, r, &req)
			if req.Subject != "user:1" || req.Permission != "read" || req.ObjectType != "doc" {
				t.Errorf("list-objects body = %+v", req)
			}
			writeJSON(w, 200, ListObjectsResponse{Objects: []string{"doc:1"}, Subject: "user:1", Permission: "read", ObjectType: "doc", ResultCount: 1})
		case "/zanzibar/stores/s1/list-users":
			var req ListUsersRequest
			readBody(t, r, &req)
			if req.Object != "doc:1" || req.Permission != "read" {
				t.Errorf("list-users body = %+v", req)
			}
			writeJSON(w, 200, ListUsersResponse{Users: []string{"user:1"}, Object: "doc:1", Permission: "read", ResultCount: 1})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}, WithAPIKey("ab0t_sk_svc"))
	ctx := context.Background()
	if d, err := c.ZanzibarCheck(ctx, "s1", CheckPermissionRequest{Subject: Subject("user", "1"), Permission: "read", Object: Object("doc", "1")}, ""); err != nil || !d.Allowed {
		t.Fatalf("ZanzibarCheck: %v %+v", err, d)
	}
	// Bulk check: results come back as an ordered array, one per requested check.
	// This pins the shape that an earlier release got wrong (it decoded into a
	// struct, so every successful call returned an UnmarshalTypeError).
	if d, err := c.ZanzibarCheckBulk(ctx, "s1", BulkCheckRequest{Checks: []CheckPermissionRequest{
		{Subject: "user:1", Permission: "read", Object: "doc:1"},
		{Subject: "user:2", Permission: "read", Object: "doc:1"},
	}}, ""); err != nil || len(d) != 2 {
		t.Fatalf("ZanzibarCheckBulk: err=%v results=%+v", err, d)
	} else {
		if !d.Allowed(0) || d.Allowed(1) {
			t.Errorf("bulk results out of order or misread: %+v", d)
		}
		if d.Allowed(99) || d.Allowed(-1) {
			t.Error("an out-of-range bulk index must fail CLOSED (false), never allow")
		}
		if d.AllAllowed() {
			t.Error("AllAllowed must be false when any check was denied")
		}
		if (BulkCheckResults{}).AllAllowed() {
			t.Error("an EMPTY bulk result must not report AllAllowed — nothing checked is not everything permitted")
		}
	}
	if e, err := c.ZanzibarExpand(ctx, "s1", ExpandRequest{Permission: "read", Object: Object("doc", "1")}, ""); err != nil || len(e.Subjects) != 1 {
		t.Fatalf("ZanzibarExpand: %v", err)
	}
	if o, err := c.ZanzibarListObjects(ctx, "s1", ListObjectsRequest{Subject: "user:1", Permission: "read", ObjectType: "doc"}, ""); err != nil || len(o.Objects) != 1 {
		t.Fatalf("ZanzibarListObjects: %v", err)
	}
	if u, err := c.ZanzibarListUsers(ctx, "s1", ListUsersRequest{Object: "doc:1", Permission: "read"}, ""); err != nil || len(u.Users) != 1 {
		t.Fatalf("ZanzibarListUsers: %v", err)
	}
}

func TestZanzibarTuplesAndNamespaces(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/zanzibar/stores/s1/relationships":
			var req RelationshipRequest
			readBody(t, r, &req)
			if req.Object != "doc:1" || req.Relation != "viewer" || req.Subject != "user:1" {
				t.Errorf("tuple = %+v", req)
			}
			if r.Method == "POST" {
				writeJSON(w, 200, WriteOperationResponse{Success: true, Message: "written", ConsistencyToken: "zk-1"})
			} else {
				writeJSON(w, 200, WriteOperationResponse{Success: true, Message: "deleted"})
			}
		case "/zanzibar/stores/s1/relationships/doc/1":
			if got := r.URL.Query().Get("relation"); got != "" && got != "viewer" {
				t.Errorf("relation filter = %q", got)
			}
			writeJSON(w, 200, RelationshipsResponse{Object: "doc:1", Relationships: []RelationshipEntry{{Relation: "viewer", Subject: "user:1"}}})
		case "/zanzibar/stores/s1/namespaces":
			if r.Method == "POST" {
				writeJSON(w, 200, ZanzibarMessageResponse{Message: "created"})
			} else {
				writeJSON(w, 200, NamespaceListResponse{Namespaces: []NamespaceSummary{{Name: "doc"}}})
			}
		case "/zanzibar/stores/s1/namespaces/doc":
			writeJSON(w, 200, NamespaceDetailResponse{Name: "doc"})
		case "/zanzibar/stores/s1/permissions/grant":
			var req PermissionGrantRequest
			readBody(t, r, &req)
			if req.Subject != "user:u1" || req.Resource != "doc:1" || req.Permission != "view" {
				t.Errorf("grant body = %+v", req)
			}
			writeJSON(w, 200, WriteOperationResponse{Success: true, Message: "granted"})
		case "/zanzibar/stores/s1/permissions/revoke":
			writeJSON(w, 200, WriteOperationResponse{Success: true, Message: "revoked"})
		case "/zanzibar/stores/s1/hierarchy/setup":
			writeJSON(w, 200, ZanzibarMessageResponse{Message: "ok"})
		case "/zanzibar/stores/s1/teams/membership":
			var req TeamMembershipRequest
			readBody(t, r, &req)
			if req.UserID != "u1" || req.TeamID != "t1" {
				t.Errorf("membership body = %+v", req)
			}
			writeJSON(w, 200, ZanzibarMessageResponse{Message: "ok"})
		case "/zanzibar/stores/s1/visualize/hierarchy":
			writeJSON(w, 200, HierarchyVisualizationResponse{ID: "org1", Type: "organization"})
		case "/zanzibar/stores/s1/visualize/permissions":
			if got := r.URL.Query().Get("user_id"); got != "u1" {
				t.Errorf("visualize user_id = %q", got)
			}
			writeJSON(w, 200, PermissionsVisualizationResponse{UserID: "u1"})
		case "/zanzibar/stores/s1/migrate/setup-defaults":
			writeJSON(w, 200, ZanzibarMessageResponse{Message: "ok"})
		case "/zanzibar/stores/s1/migrate/permissions":
			if got := r.URL.Query().Get("user_id"); got != "u1" {
				t.Errorf("migrate user_id = %q", got)
			}
			if got := r.URL.Query()["permissions"]; len(got) != 1 || got[0] != "doc.view" {
				t.Errorf("migrate permissions = %v", got)
			}
			writeJSON(w, 200, ZanzibarMessageResponse{Message: "ok"})
		case "/zanzibar/stores/s1/watch/status":
			writeJSON(w, 200, WatchStatusResponse{Available: true, Message: "watching"})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	ctx := context.Background()
	tup := RelationshipRequest{Object: Object("doc", "1"), Relation: "viewer", Subject: Subject("user", "1")}
	if w, err := c.WriteRelationships(ctx, "s1", tup, "tok"); err != nil || !w.Success || w.ConsistencyToken != "zk-1" {
		t.Fatalf("WriteRelationships: %v %+v", err, w)
	}
	if w, err := c.DeleteRelationships(ctx, "s1", tup, "tok"); err != nil || !w.Success {
		t.Fatalf("DeleteRelationships: %v", err)
	}
	if rs, err := c.ListRelationships(ctx, "s1", "doc", "1", "", "tok"); err != nil || len(rs.Relationships) != 1 {
		t.Fatalf("ListRelationships: %v", err)
	}
	if _, err := c.CreateNamespace(ctx, "s1", NamespaceRequest{Name: "doc", Relations: map[string]any{}, Permissions: map[string]any{}}, "tok"); err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	if ns, err := c.ListNamespaces(ctx, "s1", "tok"); err != nil || len(ns.Namespaces) != 1 {
		t.Fatalf("ListNamespaces: %v", err)
	}
	if _, err := c.GetNamespace(ctx, "s1", "doc", "tok"); err != nil {
		t.Fatalf("GetNamespace: %v", err)
	}
	if _, err := c.ZanzibarGrant(ctx, "s1", PermissionGrantRequest{Subject: "user:u1", Permission: "view", Resource: "doc:1"}, "tok"); err != nil {
		t.Fatalf("ZanzibarGrant: %v", err)
	}
	if _, err := c.ZanzibarRevoke(ctx, "s1", PermissionGrantRequest{Subject: "user:u1", Permission: "view", Resource: "doc:1"}, "tok"); err != nil {
		t.Fatalf("ZanzibarRevoke: %v", err)
	}
	if _, err := c.SetupOrgHierarchy(ctx, "s1", OrgHierarchyRequest{OrgID: "org1"}, "tok"); err != nil {
		t.Fatalf("SetupOrgHierarchy: %v", err)
	}
	if _, err := c.SetupTeamMembership(ctx, "s1", TeamMembershipRequest{UserID: "u1", TeamID: "t1", Role: "member"}, "tok"); err != nil {
		t.Fatalf("SetupTeamMembership: %v", err)
	}
	if _, err := c.VisualizeHierarchy(ctx, "s1", VisualizationRequest{OrgID: "org1"}, "tok"); err != nil {
		t.Fatalf("VisualizeHierarchy: %v", err)
	}
	if _, err := c.VisualizePermissions(ctx, "s1", "u1", "tok"); err != nil {
		t.Fatalf("VisualizePermissions: %v", err)
	}
	if _, err := c.MigrateSetupDefaults(ctx, "s1", "tok"); err != nil {
		t.Fatalf("MigrateSetupDefaults: %v", err)
	}
	if _, err := c.MigratePermissions(ctx, "s1", "u1", []string{"doc.view"}, "tok"); err != nil {
		t.Fatalf("MigratePermissions: %v", err)
	}
	if ws, err := c.WatchStatus(ctx, "s1", "tok"); err != nil || !ws.Available {
		t.Fatalf("WatchStatus: %v", err)
	}
}

func TestCheckPermissionPublic(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		expect(t, r, "POST", "/auth/check-permission")
		if r.Header.Get("Authorization") != "" {
			t.Errorf("public endpoint sent auth")
		}
		writeJSON(w, 200, PermissionDecision{Allowed: true})
	})
	d, err := c.CheckPermissionPublic(context.Background(), PermissionCheckRequest{UserID: "u1", Permission: "x.read"})
	if err != nil || !d.Allowed {
		t.Fatalf("CheckPermissionPublic: %v %+v", err, d)
	}
}

// ===================== Providers / federation =====================

func TestProvidersDomain(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/providers/":
			if r.Method == "POST" {
				writeJSON(w, 200, Provider{ID: "p1", Type: "oidc"})
			} else {
				writeJSON(w, 200, []Provider{{ID: "p1"}})
			}
		case "/providers/p1":
			switch r.Method {
			case "GET":
				writeJSON(w, 200, Provider{ID: "p1"})
			default:
				writeJSON(w, 200, MessageResponse{Message: "ok"})
			}
		case "/providers/test":
			writeJSON(w, 200, ProviderTestResponse{Success: true})
		case "/providers/types/supported":
			writeJSON(w, 200, map[string]any{"types": []string{"oidc", "saml"}})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}, WithAPIKey("ab0t_sk_admin"))
	ctx := context.Background()
	if p, err := c.CreateProvider(ctx, ProviderConfigCreate{Name: "g", Type: "oidc"}, ""); err != nil || p.ID != "p1" {
		t.Fatalf("CreateProvider: %v", err)
	}
	if ps, err := c.ListProviders(ctx, ""); err != nil || len(ps) != 1 {
		t.Fatalf("ListProviders: %v", err)
	}
	if _, err := c.GetProvider(ctx, "p1", ""); err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	en := false
	if _, err := c.UpdateProvider(ctx, "p1", ProviderConfigUpdate{Enabled: &en}, ""); err != nil {
		t.Fatalf("UpdateProvider: %v", err)
	}
	if _, err := c.DeleteProvider(ctx, "p1", ""); err != nil {
		t.Fatalf("DeleteProvider: %v", err)
	}
	if tr, err := c.TestProvider(ctx, ProviderTestRequest{Type: "oidc"}, ""); err != nil || !tr.Success {
		t.Fatalf("TestProvider: %v", err)
	}
	if _, err := c.SupportedProviderTypes(ctx); err != nil {
		t.Fatalf("SupportedProviderTypes: %v", err)
	}
}

func TestFederationDomain(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/federation/sso/sessions":
			if r.Method == "POST" {
				writeJSON(w, 200, SSOSessionCreateResponse{SessionID: "ss1"})
			} else {
				writeJSON(w, 200, SSOSessionListResponse{Sessions: []SSOSession{{ID: "ss1"}}})
			}
		case "/federation/sso/create-token":
			writeJSON(w, 200, DomainTokenResponse{Token: "dt"})
		case "/federation/sso/sessions/ss1":
			if r.Method == "GET" {
				writeJSON(w, 200, SSOSessionDetailResponse{Session: SSOSession{ID: "ss1"}})
			} else {
				writeJSON(w, 200, MessageResponse{Message: "deleted"})
			}
		case "/federation/sso/propagate":
			writeJSON(w, 200, SSOPropagateResponse{Success: true})
		case "/federation/sso/propagate-logout":
			writeJSON(w, 200, LogoutPropagationResponse{Success: true})
		case "/federation/sso/config":
			if r.Method == "GET" {
				writeJSON(w, 200, SSOConfigResponse{Enabled: true})
			} else {
				writeJSON(w, 200, SSOConfigUpdateResponse{Message: "ok"})
			}
		case "/federation/sso/domains":
			writeJSON(w, 200, SSODomainListResponse{Domains: []SSODomainConfigResponse{{Domain: "acme.com"}}})
		case "/federation/sso/domains/acme.com":
			switch r.Method {
			case "DELETE":
				writeJSON(w, 200, MessageResponse{Message: "deleted"})
			default:
				writeJSON(w, 200, SSODomainConfigResponse{Domain: "acme.com", Enabled: true})
			}
		case "/federation/attribute-mappings":
			if r.Method == "POST" {
				writeJSON(w, 200, AttributeMappingCreateResponse{Mapping: AttributeMapping{SourceAttr: "email"}})
			} else {
				writeJSON(w, 200, AttributeMappingListResponse{Mappings: []AttributeMapping{{SourceAttr: "email"}}})
			}
		case "/federation/jit/config":
			if r.Method == "GET" {
				writeJSON(w, 200, JITConfigResponse{Enabled: true})
			} else {
				writeJSON(w, 200, MessageResponse{Message: "ok"})
			}
		case "/federation/stats":
			writeJSON(w, 200, FederationStatsResponse{ActiveSessions: 5})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}, WithAPIKey("ab0t_sk_admin"))
	ctx := context.Background()
	if s, err := c.ListSSOSessions(ctx, "tok"); err != nil || len(s.Sessions) != 1 {
		t.Fatalf("ListSSOSessions: %v", err)
	}
	if s, err := c.CreateSSOSession(ctx, "tok"); err != nil || s.SessionID != "ss1" {
		t.Fatalf("CreateSSOSession: %v", err)
	}
	if d, err := c.CreateDomainToken(ctx, "tok"); err != nil || d.Token != "dt" {
		t.Fatalf("CreateDomainToken: %v", err)
	}
	if _, err := c.GetSSOSession(ctx, "ss1", "tok"); err != nil {
		t.Fatalf("GetSSOSession: %v", err)
	}
	if _, err := c.DeleteSSOSession(ctx, "ss1", "tok"); err != nil {
		t.Fatalf("DeleteSSOSession: %v", err)
	}
	if _, err := c.PropagateSSO(ctx, ""); err != nil {
		t.Fatalf("PropagateSSO: %v", err)
	}
	if _, err := c.PropagateLogout(ctx, "tok"); err != nil {
		t.Fatalf("PropagateLogout: %v", err)
	}
	if cfg, err := c.GetSSOConfig(ctx, ""); err != nil || !cfg.Enabled {
		t.Fatalf("GetSSOConfig: %v", err)
	}
	if _, err := c.UpdateSSOConfig(ctx, map[string]any{"x": 1}, ""); err != nil {
		t.Fatalf("UpdateSSOConfig: %v", err)
	}
	if dl, err := c.ListSSODomains(ctx, ""); err != nil || len(dl.Domains) != 1 {
		t.Fatalf("ListSSODomains: %v", err)
	}
	if _, err := c.GetSSODomain(ctx, "acme.com", ""); err != nil {
		t.Fatalf("GetSSODomain: %v", err)
	}
	if _, err := c.CreateSSODomain(ctx, "acme.com", SSODomainConfigRequest{Enabled: true}, ""); err != nil {
		t.Fatalf("CreateSSODomain: %v", err)
	}
	if _, err := c.UpdateSSODomain(ctx, "acme.com", SSODomainConfigRequest{Enabled: true}, ""); err != nil {
		t.Fatalf("UpdateSSODomain: %v", err)
	}
	if _, err := c.DeleteSSODomain(ctx, "acme.com", ""); err != nil {
		t.Fatalf("DeleteSSODomain: %v", err)
	}
	if am, err := c.ListAttributeMappings(ctx, ""); err != nil || len(am.Mappings) != 1 {
		t.Fatalf("ListAttributeMappings: %v", err)
	}
	if _, err := c.CreateAttributeMapping(ctx, AttributeMapping{SourceAttr: "email", TargetAttr: "email"}, ""); err != nil {
		t.Fatalf("CreateAttributeMapping: %v", err)
	}
	if j, err := c.GetJITConfig(ctx, ""); err != nil || !j.Enabled {
		t.Fatalf("GetJITConfig: %v", err)
	}
	if _, err := c.UpdateJITConfig(ctx, map[string]any{"enabled": true}, ""); err != nil {
		t.Fatalf("UpdateJITConfig: %v", err)
	}
	if fs, err := c.FederationStats(ctx, ""); err != nil || fs.ActiveSessions != 5 {
		t.Fatalf("FederationStats: %v", err)
	}
}

// ===================== API keys + delegation =====================

func TestAPIKeysDomain(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api-keys/":
			if r.Method == "POST" {
				writeJSON(w, 200, APIKeyWithToken{APIKey: APIKey{ID: "k1"}, Token: "ab0t_sk_new"})
			} else {
				writeJSON(w, 200, []APIKey{{ID: "k1"}})
			}
		case "/api-keys/k1":
			switch r.Method {
			case "GET":
				writeJSON(w, 200, APIKey{ID: "k1", Name: "ci"})
			default:
				writeJSON(w, 200, MessageResponse{Message: "ok"})
			}
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	ctx := context.Background()
	if ks, err := c.ListAPIKeys(ctx, "tok"); err != nil || len(ks) != 1 {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	wk, err := c.CreateAPIKey(ctx, APIKeyCreate{Name: "ci"}, "tok")
	if err != nil || wk.Token != "ab0t_sk_new" {
		t.Fatalf("CreateAPIKey: %v %+v", err, wk)
	}
	if !IsAPIKey(wk.Token) {
		t.Errorf("minted token not an api key: %q", wk.Token)
	}
	if k, err := c.GetAPIKey(ctx, "k1", "tok"); err != nil || k.Name != "ci" {
		t.Fatalf("GetAPIKey: %v", err)
	}
	en := false
	if _, err := c.UpdateAPIKey(ctx, "k1", APIKeyUpdate{Enabled: &en}, "tok"); err != nil {
		t.Fatalf("UpdateAPIKey: %v", err)
	}
	if _, err := c.DeleteAPIKey(ctx, "k1", "tok"); err != nil {
		t.Fatalf("DeleteAPIKey: %v", err)
	}
}

func TestDelegationDomain(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/delegation/grant":
			var req DelegationGrant
			readBody(t, r, &req)
			if req.ActorID != "svc" {
				t.Errorf("actor = %q", req.ActorID)
			}
			writeJSON(w, 200, DelegationResponse{ID: "d1"})
		case "/delegation/revoke/svc":
			writeJSON(w, 200, MessageResponse{Message: "revoked"})
		case "/delegation/check/u2":
			writeJSON(w, 200, DelegationCheckResponse{CanDelegate: true})
		case "/delegation/list/u1":
			writeJSON(w, 200, []DelegationEntry{{ID: "d1"}})
		case "/auth/delegate":
			writeJSON(w, 200, TokenSet{AccessToken: "deleg", User: TokenUserInfo{IsDelegated: true}})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	ctx := context.Background()
	if d, err := c.GrantDelegation(ctx, DelegationGrant{ActorID: "svc", TargetUserID: "u2"}, "tok"); err != nil || d.ID != "d1" {
		t.Fatalf("GrantDelegation: %v", err)
	}
	if _, err := c.RevokeDelegation(ctx, "svc", "tok"); err != nil {
		t.Fatalf("RevokeDelegation: %v", err)
	}
	if ch, err := c.CheckDelegation(ctx, "u2", "tok"); err != nil || !ch.CanDelegate {
		t.Fatalf("CheckDelegation: %v", err)
	}
	if l, err := c.ListDelegations(ctx, "u1", "tok"); err != nil || len(l) != 1 {
		t.Fatalf("ListDelegations: %v", err)
	}
	if ts, err := c.Delegate(ctx, DelegateTokenRequest{TargetUserID: "u2"}, "tok"); err != nil || !ts.User.IsDelegated {
		t.Fatalf("Delegate: %v", err)
	}
}

// ===================== Admin + super-admin =====================

func TestAdminDomain(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ab0t_sk_admin" {
			t.Errorf("admin op missing auth: %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/admin/password-policy":
			writeJSON(w, 200, PasswordPolicySetResponse{Message: "set"})
		case "/admin/password-policy/org1":
			writeJSON(w, 200, PasswordPolicyGetResponse{OrgID: "org1"})
		case "/admin/password-policy/force-reset":
			writeJSON(w, 200, ForcePasswordResetResponse{AffectedCount: 3})
		case "/admin/reports/password-compliance":
			writeJSON(w, 200, PasswordComplianceResponse{Compliant: 10})
		case "/admin/users/password-age":
			writeJSON(w, 200, PasswordAgeUpdateResponse{UserID: "u1"})
		case "/admin/audit/password-events":
			writeJSON(w, 200, PasswordAuditEventsResponse{Events: []map[string]any{{"e": 1}}})
		case "/admin/jwks/revoke/k1":
			writeJSON(w, 200, KeyRevocationResponse{Revoked: true})
		case "/admin/jwks/revoked":
			writeJSON(w, 200, RevokedKeysListResponse{Total: 1})
		case "/admin/jwks/rotate":
			writeJSON(w, 200, KeyRotationResponse{NewKid: "k2"})
		case "/admin/jwks/rotation-status":
			writeJSON(w, 200, RotationStatusResponse{CurrentKid: "k1"})
		case "/admin/jwks/next-rotation":
			writeJSON(w, 200, NextRotationResponse{NextRotation: "soon"})
		case "/admin/jwks/generate":
			writeJSON(w, 200, KeyGenerateResponse{Kid: "k3"})
		case "/admin/jwks/activate/k3":
			writeJSON(w, 200, KeyActivateResponse{Kid: "k3", Active: true})
		case "/admin/jwks/cleanup":
			writeJSON(w, 200, KeyCleanupResponse{RemovedCount: 2})
		case "/admin/users/create-service-account":
			writeJSON(w, 200, ServiceAccountResponse{UserID: "svc1", APIKey: "ab0t_sk_sa"})
		case "/admin/users/elevate-privileges":
			writeJSON(w, 200, ElevatePrivilegesResponse{UserID: "u1"})
		case "/admin/circuit-breakers/status":
			writeJSON(w, 200, CircuitBreakerStatusResponse{Breakers: map[string]any{"db": "closed"}})
		case "/admin/circuit-breakers/db/reset":
			writeJSON(w, 200, CircuitBreakerResetResponse{Reset: true})
		case "/admin/circuit-breakers/reset-all":
			writeJSON(w, 200, CircuitBreakerResetAllResponse{ResetCount: 4})
		case "/admin/audit/revocations":
			writeJSON(w, 200, []RevocationAuditEntry{{ID: "r1"}})
		case "/admin/api-keys/emergency-revoke":
			writeJSON(w, 200, EmergencyRevokeResponse{RevokedCount: 7})
		case "/admin/providers/status":
			writeJSON(w, 200, ProviderStatusUpdateResponse{Enabled: false})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}, WithAPIKey("ab0t_sk_admin"))
	ctx := context.Background()
	if _, err := c.SetPasswordPolicy(ctx, PasswordPolicyRequest{MinLength: 12}, ""); err != nil {
		t.Fatalf("SetPasswordPolicy: %v", err)
	}
	if _, err := c.GetPasswordPolicy(ctx, "org1", ""); err != nil {
		t.Fatalf("GetPasswordPolicy: %v", err)
	}
	if r, err := c.ForcePasswordReset(ctx, ForcePasswordResetRequest{AllUsers: true}, ""); err != nil || r.AffectedCount != 3 {
		t.Fatalf("ForcePasswordReset: %v", err)
	}
	if _, err := c.PasswordComplianceReport(ctx, ""); err != nil {
		t.Fatalf("PasswordComplianceReport: %v", err)
	}
	if _, err := c.UpdatePasswordAge(ctx, PasswordAgeUpdate{UserID: "u1", AgeDays: 99}, ""); err != nil {
		t.Fatalf("UpdatePasswordAge: %v", err)
	}
	if _, err := c.PasswordAuditEvents(ctx, ""); err != nil {
		t.Fatalf("PasswordAuditEvents: %v", err)
	}
	if r, err := c.RevokeSigningKey(ctx, "k1", KeyRevocationRequest{Reason: "leak"}, ""); err != nil || !r.Revoked {
		t.Fatalf("RevokeSigningKey: %v", err)
	}
	if _, err := c.ListRevokedKeys(ctx, ""); err != nil {
		t.Fatalf("ListRevokedKeys: %v", err)
	}
	if r, err := c.RotateSigningKeys(ctx, KeyRotationRequest{Force: true}, ""); err != nil || r.NewKid != "k2" {
		t.Fatalf("RotateSigningKeys: %v", err)
	}
	if _, err := c.JWKSRotationStatus(ctx, ""); err != nil {
		t.Fatalf("JWKSRotationStatus: %v", err)
	}
	if _, err := c.JWKSNextRotation(ctx, ""); err != nil {
		t.Fatalf("JWKSNextRotation: %v", err)
	}
	if r, err := c.GenerateSigningKey(ctx, KeyGenerationRequest{}, ""); err != nil || r.Kid != "k3" {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	if r, err := c.ActivateSigningKey(ctx, "k3", ""); err != nil || !r.Active {
		t.Fatalf("ActivateSigningKey: %v", err)
	}
	if r, err := c.CleanupSigningKeys(ctx, KeyCleanupRequest{OlderThanDays: 30}, ""); err != nil || r.RemovedCount != 2 {
		t.Fatalf("CleanupSigningKeys: %v", err)
	}
	if r, err := c.CreateServiceAccount(ctx, ServiceAccountCreate{Name: "ci"}, ""); err != nil || !IsAPIKey(r.APIKey) {
		t.Fatalf("CreateServiceAccount: %v %+v", err, r)
	}
	if _, err := c.ElevatePrivileges(ctx, ElevatePrivilegesRequest{UserID: "u1", Permissions: []string{"x"}}, ""); err != nil {
		t.Fatalf("ElevatePrivileges: %v", err)
	}
	if _, err := c.CircuitBreakerStatus(ctx, ""); err != nil {
		t.Fatalf("CircuitBreakerStatus: %v", err)
	}
	if r, err := c.ResetCircuitBreaker(ctx, "db", ""); err != nil || !r.Reset {
		t.Fatalf("ResetCircuitBreaker: %v", err)
	}
	if r, err := c.ResetAllCircuitBreakers(ctx, ""); err != nil || r.ResetCount != 4 {
		t.Fatalf("ResetAllCircuitBreakers: %v", err)
	}
	if l, err := c.RevocationAuditLog(ctx, ""); err != nil || len(l) != 1 {
		t.Fatalf("RevocationAuditLog: %v", err)
	}
	if r, err := c.EmergencyRevokeAPIKeys(ctx, EmergencyRevokeRequest{AllKeys: true}, ""); err != nil || r.RevokedCount != 7 {
		t.Fatalf("EmergencyRevokeAPIKeys: %v", err)
	}
	if _, err := c.UpdateProviderStatus(ctx, ProviderStatusUpdateRequest{ProviderID: "p1"}, ""); err != nil {
		t.Fatalf("UpdateProviderStatus: %v", err)
	}
}

func TestSuperAdminDomain(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/super-admin/grant":
			writeJSON(w, 200, SuperAdminGrantResponse{GrantID: "g1", Status: "pending"})
		case "/super-admin/revoke":
			writeJSON(w, 200, SuperAdminRevokeResponse{Revoked: true})
		case "/super-admin/extend":
			writeJSON(w, 200, SuperAdminExtendResponse{GrantID: "g1"})
		case "/super-admin/active-grants":
			writeJSON(w, 200, SuperAdminActiveGrantsResponse{Total: 2})
		case "/super-admin/approve":
			writeJSON(w, 200, MessageResponse{Message: "approved"})
		case "/super-admin/cleanup-expired":
			writeJSON(w, 200, SuperAdminCleanupResponse{CleanedCount: 5})
		case "/super-admin/audit-log":
			writeJSON(w, 200, MessageResponse{Message: "log"})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}, WithAPIKey("ab0t_sk_TEST_FAKE_sysadmin"))
	ctx := context.Background()
	if g, err := c.SuperAdminGrant(ctx, SuperAdminGrantRequestModel{UserID: "u1", Permissions: []string{"system.admin"}}, ""); err != nil || g.GrantID != "g1" {
		t.Fatalf("SuperAdminGrant: %v", err)
	}
	if r, err := c.SuperAdminRevoke(ctx, SuperAdminRevokeRequestModel{GrantID: "g1"}, ""); err != nil || !r.Revoked {
		t.Fatalf("SuperAdminRevoke: %v", err)
	}
	if _, err := c.SuperAdminExtend(ctx, SuperAdminExtendRequestModel{GrantID: "g1", AdditionalSeconds: 60}, ""); err != nil {
		t.Fatalf("SuperAdminExtend: %v", err)
	}
	if g, err := c.SuperAdminActiveGrants(ctx, ""); err != nil || g.Total != 2 {
		t.Fatalf("SuperAdminActiveGrants: %v", err)
	}
	if _, err := c.SuperAdminApprove(ctx, ApprovalRequestModel{GrantID: "g1", Approve: true}, ""); err != nil {
		t.Fatalf("SuperAdminApprove: %v", err)
	}
	if r, err := c.SuperAdminCleanupExpired(ctx, ""); err != nil || r.CleanedCount != 5 {
		t.Fatalf("SuperAdminCleanupExpired: %v", err)
	}
	if _, err := c.SuperAdminAuditLog(ctx, ""); err != nil {
		t.Fatalf("SuperAdminAuditLog: %v", err)
	}
}
