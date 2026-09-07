// Package beforefixture is a v0.10.2 (pre-migration) consumer snippet used ONLY to
// verify migrate-check.sh flags every break. It lives under testdata/, which the Go
// toolchain ignores, so it is never compiled (its symbols are intentionally the OLD,
// now-removed ones). Do not import it. Run:
//
//	bash ../migrate-check.sh testdata
//
// and expect a non-zero exit with one finding block per break below.
package beforefixture

import (
	"context"

	auth "github.com/ab0t-com/auth-sdk-go"
)

func old(c *auth.Client, ctx context.Context, tok string) {
	// 1 return type: bare-array endpoints decoded into envelopes.
	users, _ := c.ListOrgUsers(ctx, "org1", tok)
	_ = users.Users
	_ = users.Total
	clients, _ := c.ListOrgClients(ctx, "org1", tok)
	_ = clients.Clients

	// 2 login config: wrapper + flat body.
	cfg, _ := c.GetLoginConfig(ctx, "org1", tok)
	_ = cfg.Config
	logo := "https://x/y.png"
	_, _ = c.UpdateLoginConfig(ctx, "org1", auth.LoginConfigUpdate{LogoURL: &logo}, tok)

	// 4 invite: MessageResponse + TeamIDs + Resend.
	_, _ = c.InviteToOrganization(ctx, "org1", auth.OrganizationInvite{
		Email: "a@b.com", TeamIDs: []string{"t1"}, Resend: true,
	}, tok)

	// 5 transact: old return type.
	_, _ = c.WriteAndDeleteRelationships(ctx, "s1", auth.TransactRelationshipsRequest{}, tok)

	// 6 hierarchy callback.
	h, _ := c.GetOrgHierarchy(ctx, "org1", tok)
	h.WalkOrgTree(func(n *auth.OrgHierarchyResponse, d int) { _ = n.Organization.ID })
	var kids []auth.OrgHierarchyResponse
	_ = kids

	// 7 admin user update.
	nm := "New"
	_, _ = c.UpdateUser(ctx, "u1", auth.UserUpdate{Name: &nm}, tok)

	// 8/9 session + team member renames.
	sess, _ := c.ListOrgSessions(ctx, "org1", tok)
	_ = sess.Total
	for _, s := range sess.Sessions {
		_ = s.ID
		_ = s.LastSeenAt
	}
	rev, _ := c.RevokeUserSessions(ctx, "org1", "u1", tok)
	_ = rev.RevokedCount
	members, _ := c.ListTeamMembers(ctx, "team1", tok)
	for _, m := range members {
		_ = m.AddedAt
	}

	// 10 providers.
	_, _ = c.CreateProvider(ctx, auth.ProviderConfigCreate{Name: "g", Type: "oidc", Enabled: true, IssuerURL: "https://i"}, tok)
	en := false
	_, _ = c.UpdateProvider(ctx, "p1", auth.ProviderConfigUpdate{Enabled: &en}, tok)

	// 11 removed request fields.
	_, _ = c.ValidateTokenWith(ctx, auth.TokenValidationRequest{Token: tok, ResourceType: "doc", ResourceID: "1"})
	_, _ = c.Register(ctx, auth.RegisterRequest{Email: "a@b.com", Password: "x", ProviderType: "internal"})
	_, _ = c.OrgRegister(ctx, "acme", auth.OrgRegisterRequest{Email: "a@b.com", Password: "x", FirstName: "A", LastName: "B"})
	_, _ = c.CreateAPIKey(ctx, auth.APIKeyCreate{Name: "ci", OrgID: "org1", Audience: []string{"svc"}}, tok)
	_, _ = c.CreateOrganization(ctx, auth.OrganizationCreate{Name: "Acme", BillingType: "enterprise"}, tok)
	status := "active"
	_, _ = c.UpdateOrganization(ctx, "org1", auth.OrganizationUpdate{BillingType: &status, Status: &status}, tok)
	_, _ = c.UpdateOrgUserRole(ctx, "org1", "u1", auth.OrgRoleUpdate{Role: "admin", Permissions: []string{"x"}}, tok)
}
