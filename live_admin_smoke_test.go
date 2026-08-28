package authclient

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestLive_AdminFlow (V2): self-provision admin via the accepted pathway —
// register a user, create an org (owner/admin of it), switch to it — then exercise
// a POSITIVE authorization, the SCIM read surface, and delegation, against a real
// server. Env-guarded (AUTH_LIVE=1, AUTH_BASE). Throwaway test+ accounts.
func TestLive_AdminFlow(t *testing.T) {
	if os.Getenv("AUTH_LIVE") == "" {
		t.Skip("set AUTH_LIVE=1 and AUTH_BASE")
	}
	c := New(os.Getenv("AUTH_BASE"))
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	n := time.Now().UnixNano()
	email := fmt.Sprintf("test+test_%d@ab0t.com", n)

	reg, err := c.Register(ctx, RegisterRequest{Email: email, Password: "Sdk-Admin-Pw-9271!", Name: "SDK Admin"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Logf("registered %s (user=%s, personal org=%s)", email, reg.User.ID, reg.User.OrgID)

	// Create an org — the caller becomes its admin.
	org, err := c.CreateOrganization(ctx, OrganizationCreate{
		Name: "SDK V2 Org", Slug: fmt.Sprintf("sdk-v2-%d", n),
	}, reg.AccessToken)
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	t.Logf("created org id=%s slug=%s", org.ID, org.Slug)

	// Switch to the new org to get an org-scoped admin token.
	sw, err := c.SwitchOrganization(ctx, reg.AccessToken, org.ID)
	if err != nil {
		t.Logf("SwitchOrganization: %v (continuing with the register token)", err)
	}
	adminTok := reg.AccessToken
	if sw != nil && sw.AccessToken != "" {
		adminTok = sw.AccessToken
	}

	// Resolve the admin's effective permissions in the org.
	actor, err := c.ValidateTokenWith(ctx, TokenValidationRequest{Token: adminTok, IncludePermissions: true})
	if err != nil {
		t.Fatalf("ValidateToken(admin): %v", err)
	}
	t.Logf("admin actor: user=%s org=%s perms=%d %v", actor.UserID, actor.OrgID, len(actor.Permissions), firstN(actor.Permissions, 6))

	// POSITIVE authorization: pick a permission the admin actually holds and assert allow=true.
	if len(actor.Permissions) > 0 {
		held := actor.Permissions[0]
		ok, err := c.Authorize(ctx, adminTok, held, Resource{Type: "organization", ID: org.ID})
		if err != nil {
			t.Fatalf("positive Authorize(%q) errored: %v", held, err)
		}
		t.Logf("POSITIVE Authorize(%q on org) = %v", held, ok)
		if !ok {
			t.Errorf("V2: admin holds %q but resource-scoped Authorize denied it", held)
		}
	} else {
		t.Logf("admin actor reported 0 permissions; skipping positive-authz assertion")
	}
	// Negative (deny path): a SECOND user who is NOT a member of the org must be
	// denied on the org's resource. (An org ADMIN is legitimately allowed every
	// permission in their OWN org — reason "org_admin" — so a bogus permission
	// checked as the admin is correctly `true`; the deny path needs an outsider.)
	other, err := c.Register(ctx, RegisterRequest{
		Email: fmt.Sprintf("test+test_%d@ab0t.com", n+1), Password: "Sdk-Other-Pw-9271!", Name: "SDK Other",
	})
	if err != nil {
		t.Fatalf("register outsider: %v", err)
	}
	no, err := c.Authorize(ctx, other.AccessToken, "org.admin", Resource{Type: "organization", ID: org.ID})
	if err != nil {
		t.Fatalf("negative Authorize errored: %v", err)
	}
	if no {
		t.Errorf("V2: a non-member was allowed org.admin on another user's org")
	}
	t.Logf("negative Authorize (non-member on the org) = %v (expected false)", no)

	// SCIM read surface (may require higher privilege — exploratory, non-fatal).
	if cfg, err := c.ScimServiceProviderConfig(ctx, adminTok); err != nil {
		t.Logf("SCIM ServiceProviderConfig: %v (may need platform/SCIM privilege)", err)
	} else {
		t.Logf("SCIM ServiceProviderConfig OK: %d bytes", len(cfg))
	}
	if lu, err := c.ListScimUsers(ctx, adminTok); err != nil {
		t.Logf("SCIM ListUsers: %v", err)
	} else {
		t.Logf("SCIM ListUsers OK: %d resources", lu.TotalResults)
	}

	// Delegation: mint an act-as token (exploratory — needs a target the admin may delegate to).
	if _, err := c.Delegate(ctx, DelegateTokenRequest{TargetUserID: reg.User.ID, OrgID: org.ID}, adminTok); err != nil {
		t.Logf("Delegate (self, exploratory): %v", err)
	} else {
		t.Logf("Delegate OK (act-as token minted)")
	}
}

func firstN(s []string, n int) []string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
