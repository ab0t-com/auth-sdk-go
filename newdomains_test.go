package authclient

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

// ===================== OAuth2 / OIDC / discovery =====================

func TestOAuthInteractiveFlows(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/authorize":
			if r.Header.Get("Authorization") != "Bearer usertok" {
				t.Errorf("authorize auth = %q", r.Header.Get("Authorization"))
			}
			writeJSON(w, 200, AuthorizationResponse{Code: "ac", State: "s1"})
		case "/auth/oauth/par":
			if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
				t.Errorf("par content-type = %q", ct)
			}
			writeJSON(w, 201, PushedAuthorizationResponse{RequestURI: "urn:req:1", ExpiresIn: 60})
		case "/auth/oauth/token":
			writeJSON(w, 200, TokenResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 3600})
		case "/token/refresh":
			if r.FormValue("grant_type") != "refresh_token" {
				t.Errorf("refresh grant_type missing")
			}
			writeJSON(w, 200, TokenResponse{AccessToken: "at2"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	if _, err := c.OAuthAuthorize(context.Background(), "usertok", url.Values{"scope": {"openid"}}); err != nil {
		t.Fatalf("OAuthAuthorize: %v", err)
	}
	par, err := c.PushedAuthorizationRequest(context.Background(), url.Values{"client_id": {"cli"}})
	if err != nil || par.RequestURI != "urn:req:1" {
		t.Fatalf("PAR: %v %+v", err, par)
	}
	if _, err := c.OAuthToken(context.Background(), url.Values{"grant_type": {"authorization_code"}, "code": {"ac"}}); err != nil {
		t.Fatalf("OAuthToken: %v", err)
	}
	tok, err := c.RefreshTokenForm(context.Background(), "rt")
	if err != nil || tok.AccessToken != "at2" {
		t.Fatalf("RefreshTokenForm: %v %+v", err, tok)
	}
}

func TestDynamicClientRegistration(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/auth/oauth/register":
			writeJSON(w, 201, ClientRegistrationResponse{ClientID: "c1", ClientSecret: "sec"})
		case r.Method == "GET" && r.URL.Path == "/auth/oauth/register/c1":
			writeJSON(w, 200, ClientRegistrationResponse{ClientID: "c1"})
		case r.Method == "PUT" && r.URL.Path == "/auth/oauth/register/c1":
			writeJSON(w, 200, ClientRegistrationResponse{ClientID: "c1", ClientName: "renamed"})
		case r.Method == "DELETE" && r.URL.Path == "/auth/oauth/register/c1":
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	reg, err := c.RegisterClient(context.Background(), ClientRegistration{ClientName: "cli", RedirectURIs: []string{"http://x"}})
	if err != nil || reg.ClientID != "c1" {
		t.Fatalf("RegisterClient: %v %+v", err, reg)
	}
	if _, err := c.GetClientRegistration(context.Background(), "c1"); err != nil {
		t.Fatalf("GetClientRegistration: %v", err)
	}
	if _, err := c.UpdateClientRegistration(context.Background(), "c1", ClientRegistration{ClientName: "renamed"}); err != nil {
		t.Fatalf("UpdateClientRegistration: %v", err)
	}
	if err := c.DeleteClientRegistration(context.Background(), "c1"); err != nil {
		t.Fatalf("DeleteClientRegistration: %v", err)
	}
}

func TestDiscoveryDocuments(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(w, 200, OpenIDConfiguration{Issuer: "https://iss", TokenEndpoint: "https://iss/token"})
		case "/.well-known/oauth-authorization-server":
			writeJSON(w, 200, OpenIDConfiguration{Issuer: "https://iss"})
		case "/.well-known/jwks.json/health":
			writeJSON(w, 200, map[string]any{"healthy": true})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	oc, err := c.OpenIDConfiguration(context.Background())
	if err != nil || oc.Issuer != "https://iss" {
		t.Fatalf("OpenIDConfiguration: %v %+v", err, oc)
	}
	if _, err := c.AuthorizationServerMetadata(context.Background()); err != nil {
		t.Fatalf("AuthorizationServerMetadata: %v", err)
	}
	if _, err := c.JWKSHealth(context.Background()); err != nil {
		t.Fatalf("JWKSHealth: %v", err)
	}
}

// ===================== Hosted / org-scoped auth =====================

func TestOrgScopedAuth(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/organizations/acme/auth/login":
			writeJSON(w, 200, TokenSet{AccessToken: "at"})
		case "/organizations/acme/auth/register":
			writeJSON(w, 200, TokenSet{AccessToken: "at"})
		case "/organizations/acme/auth/logout":
			writeJSON(w, 200, HostedLoginMessageResponse{Success: true})
		case "/organizations/acme/auth/providers":
			writeJSON(w, 200, OrgProvidersResponse{Providers: []OrgProviderInfo{{ID: "p1", Type: "saml"}}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	if _, err := c.OrgLogin(context.Background(), "acme", OrgLoginRequest{Email: "a@b.com", Password: "x"}); err != nil {
		t.Fatalf("OrgLogin: %v", err)
	}
	if _, err := c.OrgRegister(context.Background(), "acme", OrgRegisterRequest{Email: "a@b.com", Password: "x"}); err != nil {
		t.Fatalf("OrgRegister: %v", err)
	}
	if _, err := c.OrgLogout(context.Background(), "acme", "tok"); err != nil {
		t.Fatalf("OrgLogout: %v", err)
	}
	pr, err := c.OrgAuthProviders(context.Background(), "acme")
	if err != nil || len(pr.Providers) != 1 {
		t.Fatalf("OrgAuthProviders: %v %+v", err, pr)
	}
}

func TestLoginConfig(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ab0t_sk_k" && r.URL.Path != "/organizations/acme/login-config/public" {
			t.Errorf("auth = %q for %s", r.Header.Get("Authorization"), r.URL.Path)
		}
		switch r.URL.Path {
		case "/organizations/o1/login-config":
			writeJSON(w, 200, LoginConfigResponse{Config: LoginConfig{OrgID: "o1", AllowSignup: true}})
		case "/organizations/acme/login-config/public":
			writeJSON(w, 200, PublicLoginConfig{OrgSlug: "acme", AllowPassword: true})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}, WithAPIKey("ab0t_sk_k"))
	if _, err := c.GetLoginConfig(context.Background(), "o1", ""); err != nil {
		t.Fatalf("GetLoginConfig: %v", err)
	}
	allow := true
	if _, err := c.UpdateLoginConfig(context.Background(), "o1", LoginConfigUpdate{AllowSignup: &allow}, ""); err != nil {
		t.Fatalf("UpdateLoginConfig: %v", err)
	}
	if _, err := c.GetPublicLoginConfig(context.Background(), "acme"); err != nil {
		t.Fatalf("GetPublicLoginConfig: %v", err)
	}
}

// ===================== Passwordless =====================

func TestPasswordlessWebAuthn(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/passwordless/webauthn/config":
			writeJSON(w, 200, WebAuthnConfigResponse{RPID: "ab0t", Enabled: true})
		case "/auth/passwordless/webauthn/register/start":
			if r.Header.Get("Authorization") != "Bearer u" {
				t.Errorf("register/start auth = %q", r.Header.Get("Authorization"))
			}
			writeJSON(w, 200, map[string]any{"challenge": "abc"})
		case "/auth/passwordless/webauthn/register/finish":
			writeJSON(w, 200, WebAuthnRegistrationResult{CredentialID: "cred1", Success: true})
		case "/auth/passwordless/webauthn/authenticate/finish":
			writeJSON(w, 200, PasswordlessAuthResponse{AccessToken: "at"})
		case "/auth/passwordless/webauthn/credentials":
			writeJSON(w, 200, WebAuthnCredentialListResponse{Credentials: []WebAuthnCredential{{ID: "cred1"}}})
		case "/auth/passwordless/webauthn/credentials/cred1":
			writeJSON(w, 200, EnterpriseMessageResponse{Success: true})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	if _, err := c.WebAuthnConfig(context.Background()); err != nil {
		t.Fatalf("WebAuthnConfig: %v", err)
	}
	if _, err := c.WebAuthnRegisterStart(context.Background(), "u", nil); err != nil {
		t.Fatalf("WebAuthnRegisterStart: %v", err)
	}
	res, err := c.WebAuthnRegisterFinish(context.Background(), "u", map[string]any{"id": "x"})
	if err != nil || res.CredentialID != "cred1" {
		t.Fatalf("WebAuthnRegisterFinish: %v %+v", err, res)
	}
	if _, err := c.WebAuthnAuthenticateFinish(context.Background(), map[string]any{"id": "x"}); err != nil {
		t.Fatalf("WebAuthnAuthenticateFinish: %v", err)
	}
	if _, err := c.ListWebAuthnCredentials(context.Background(), "u"); err != nil {
		t.Fatalf("ListWebAuthnCredentials: %v", err)
	}
	if _, err := c.DeleteWebAuthnCredential(context.Background(), "u", "cred1"); err != nil {
		t.Fatalf("DeleteWebAuthnCredential: %v", err)
	}
}

func TestPasswordlessMagicAndRecovery(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/passwordless/magic-link/send":
			writeJSON(w, 200, MagicLinkSendResponse{Success: true})
		case "/auth/passwordless/magic-link/verify":
			writeJSON(w, 200, PasswordlessAuthResponse{AccessToken: "at"})
		case "/auth/passwordless/recovery-codes/generate":
			writeJSON(w, 200, RecoveryCodesResponse{Codes: []string{"a", "b"}, Generated: 2})
		case "/auth/passwordless/devices":
			writeJSON(w, 200, DeviceListResponse{Devices: []Device{{ID: "d1"}}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	if _, err := c.SendMagicLink(context.Background(), url.Values{"email": {"a@b.com"}}); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	if _, err := c.VerifyMagicLink(context.Background(), url.Values{"token": {"t"}}); err != nil {
		t.Fatalf("VerifyMagicLink: %v", err)
	}
	rc, err := c.GenerateRecoveryCodes(context.Background(), "u")
	if err != nil || len(rc.Codes) != 2 {
		t.Fatalf("GenerateRecoveryCodes: %v %+v", err, rc)
	}
	if _, err := c.ListDevices(context.Background(), "u"); err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
}

// ===================== SAML =====================

func TestSAMLManagement(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/saml/metadata":
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<EntityDescriptor/>"))
		case "/saml/acs":
			writeJSON(w, 200, SAMLAssertionResult{NameID: "user@x", AccessToken: "at"})
		case "/saml/sp/register":
			if r.Header.Get("Authorization") != "Bearer ab0t_sk_admin" {
				t.Errorf("sp register auth = %q", r.Header.Get("Authorization"))
			}
			writeJSON(w, 201, SAMLSPRegistrationResponse{SPID: "sp1"})
		case "/saml/sp/list":
			writeJSON(w, 200, SAMLSPListResponse{ServiceProviders: []SAMLServiceProvider{{SPID: "sp1"}}})
		case "/saml/sp/sp1":
			writeJSON(w, 200, SAMLSPDetailResponse{ServiceProvider: SAMLServiceProvider{SPID: "sp1"}})
		case "/saml/certificates":
			writeJSON(w, 200, SAMLCertificateStatusResponse{Certificates: []SAMLCertificate{{Use: "signing", Active: true}}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}, WithAPIKey("ab0t_sk_admin"))

	md, err := c.SAMLMetadata(context.Background())
	if err != nil || md != "<EntityDescriptor/>" {
		t.Fatalf("SAMLMetadata: %v %q", err, md)
	}
	if _, err := c.SAMLAssertionConsumer(context.Background(), url.Values{"SAMLResponse": {"abc"}}); err != nil {
		t.Fatalf("SAMLAssertionConsumer: %v", err)
	}
	if _, err := c.RegisterSAMLSP(context.Background(), SAMLServiceProviderConfig{EntityID: "e1"}, ""); err != nil {
		t.Fatalf("RegisterSAMLSP: %v", err)
	}
	if _, err := c.ListSAMLSPs(context.Background(), ""); err != nil {
		t.Fatalf("ListSAMLSPs: %v", err)
	}
	if _, err := c.GetSAMLSP(context.Background(), "sp1", ""); err != nil {
		t.Fatalf("GetSAMLSP: %v", err)
	}
	if _, err := c.GetSAMLCertificates(context.Background(), ""); err != nil {
		t.Fatalf("GetSAMLCertificates: %v", err)
	}
}

// ===================== Email admin =====================

func TestEmailAdmin(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/emails/history":
			writeJSON(w, 200, EmailHistoryResponse{Emails: []EmailHistoryEntry{{ID: "e1"}}, Total: 1})
		case "/organizations/o1/emails/config":
			if r.Method == "PUT" {
				writeJSON(w, 200, OrgEmailConfigResponse{Config: OrgEmailConfig{Provider: "ses"}})
			} else {
				writeJSON(w, 200, OrgEmailConfigResponse{Config: OrgEmailConfig{Provider: "smtp"}})
			}
		case "/organizations/o1/emails/templates/welcome":
			writeJSON(w, 200, OrgEmailTemplateResponse{Template: &OrgEmailTemplate{Type: "welcome"}})
		case "/organizations/o1/emails/test":
			writeJSON(w, 200, TestEmailSentResponse{Success: true, EmailID: "e9"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}, WithAPIKey("ab0t_sk_admin"))
	if _, err := c.EmailHistory(context.Background(), ""); err != nil {
		t.Fatalf("EmailHistory: %v", err)
	}
	if _, err := c.GetOrgEmailConfig(context.Background(), "o1", ""); err != nil {
		t.Fatalf("GetOrgEmailConfig: %v", err)
	}
	prov := "ses"
	if _, err := c.UpdateOrgEmailConfig(context.Background(), "o1", OrgEmailConfigUpdate{Provider: &prov}, ""); err != nil {
		t.Fatalf("UpdateOrgEmailConfig: %v", err)
	}
	if _, err := c.GetOrgEmailTemplate(context.Background(), "o1", "welcome", ""); err != nil {
		t.Fatalf("GetOrgEmailTemplate: %v", err)
	}
	if _, err := c.SendTestEmail(context.Background(), "o1", TestEmailRequest{To: "a@b.com"}, ""); err != nil {
		t.Fatalf("SendTestEmail: %v", err)
	}
}

// ===================== Events / webhooks =====================

func TestEventSubscriptions(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/events/types":
			writeJSON(w, 200, EventTypesResponse{EventTypes: []EventTypeInfo{{Type: "user.created"}}})
		case r.Method == "POST" && r.URL.Path == "/events/subscriptions":
			writeJSON(w, 201, EventSubscription{ID: "sub1", URL: "https://hook"})
		case r.Method == "GET" && r.URL.Path == "/events/subscriptions":
			writeJSON(w, 200, EventSubscriptionListResponse{Subscriptions: []EventSubscription{{ID: "sub1"}}})
		case r.Method == "PATCH" && r.URL.Path == "/events/subscriptions/sub1":
			writeJSON(w, 200, EventSubscription{ID: "sub1", Active: false})
		case r.Method == "DELETE" && r.URL.Path == "/events/subscriptions/sub1":
			w.WriteHeader(204)
		case r.URL.Path == "/events/subscriptions/sub1/test":
			writeJSON(w, 200, EventSubscriptionTestResponse{Success: true, StatusCode: 200})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	if _, err := c.EventTypes(context.Background()); err != nil {
		t.Fatalf("EventTypes: %v", err)
	}
	sub, err := c.CreateEventSubscription(context.Background(), EventSubscriptionCreate{URL: "https://hook", EventTypes: []string{"user.created"}}, "tok")
	if err != nil || sub.ID != "sub1" {
		t.Fatalf("CreateEventSubscription: %v %+v", err, sub)
	}
	if _, err := c.ListEventSubscriptions(context.Background(), "tok"); err != nil {
		t.Fatalf("ListEventSubscriptions: %v", err)
	}
	active := false
	if _, err := c.UpdateEventSubscription(context.Background(), "sub1", EventSubscriptionUpdate{Active: &active}, "tok"); err != nil {
		t.Fatalf("UpdateEventSubscription: %v", err)
	}
	if _, err := c.TestEventSubscription(context.Background(), "sub1", "tok"); err != nil {
		t.Fatalf("TestEventSubscription: %v", err)
	}
	if err := c.DeleteEventSubscription(context.Background(), "sub1", "tok"); err != nil {
		t.Fatalf("DeleteEventSubscription: %v", err)
	}
}

// ===================== Network access control =====================

func TestNetworkPolicy(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/network-policy/":
			writeJSON(w, 201, NetworkPolicyCreateResponse{PolicyID: "np1"})
		case r.Method == "GET" && r.URL.Path == "/network-policy/":
			writeJSON(w, 200, NetworkPolicyListResponse{Policies: []NetworkPolicy{{ID: "np1"}}})
		case r.URL.Path == "/network-policy/np1":
			writeJSON(w, 200, NetworkPolicy{ID: "np1", Mode: "allowlist"})
		case r.URL.Path == "/network-policy/evaluate":
			if r.URL.Query().Get("ip") != "1.2.3.4" {
				t.Errorf("evaluate ip = %q", r.URL.Query().Get("ip"))
			}
			writeJSON(w, 200, PolicyEvaluationResult{Allowed: true, IP: "1.2.3.4"})
		case r.URL.Path == "/network-policy/temp-allowlist":
			writeJSON(w, 201, TempAllowlistCreateResponse{EntryID: "ta1"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}, WithAPIKey("ab0t_sk_admin"))
	if _, err := c.CreateNetworkPolicy(context.Background(), CreateNetworkPolicyRequest{Name: "p", CIDRs: []string{"10.0.0.0/8"}}, ""); err != nil {
		t.Fatalf("CreateNetworkPolicy: %v", err)
	}
	if _, err := c.ListNetworkPolicies(context.Background(), ""); err != nil {
		t.Fatalf("ListNetworkPolicies: %v", err)
	}
	if _, err := c.GetNetworkPolicy(context.Background(), "np1", ""); err != nil {
		t.Fatalf("GetNetworkPolicy: %v", err)
	}
	ev, err := c.EvaluateNetworkPolicy(context.Background(), "1.2.3.4")
	if err != nil || !ev.Allowed {
		t.Fatalf("EvaluateNetworkPolicy: %v %+v", err, ev)
	}
	if _, err := c.CreateTempAllowlist(context.Background(), TempAllowlistRequest{IP: "1.2.3.4"}, ""); err != nil {
		t.Fatalf("CreateTempAllowlist: %v", err)
	}
}

// ===================== Forward-auth =====================

func TestForwardAuth(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/forward-auth/":
			if r.Header.Get("Authorization") == "Bearer good" {
				w.Header().Set("X-Auth-User", "u1")
				w.WriteHeader(200)
				return
			}
			w.WriteHeader(403)
		case "/forward-auth/live":
			w.WriteHeader(200)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	dec, err := c.ForwardAuth(context.Background(), "GET", "good")
	if err != nil || !dec.Allowed {
		t.Fatalf("ForwardAuth allow: %v %+v", err, dec)
	}
	deny, err := c.ForwardAuth(context.Background(), "POST", "bad")
	if err != nil || deny.Allowed || deny.StatusCode != 403 {
		t.Fatalf("ForwardAuth deny: %v %+v", err, deny)
	}
	live, err := c.ForwardAuthLive(context.Background(), "HEAD", "")
	if err != nil || !live.Allowed {
		t.Fatalf("ForwardAuthLive: %v %+v", err, live)
	}
}

// ===================== Quotas / reports / system =====================

func TestQuotasReportsSystem(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/quotas/my-usage":
			writeJSON(w, 200, QuotaUsageResponse{Tier: "pro", Usage: []QuotaUsageItem{{ResourceType: "api_keys", Used: 1, Limit: 10}}})
		case "/quotas/check/api_keys":
			writeJSON(w, 200, QuotaCheckResponse{Allowed: true})
		case "/quotas/tiers":
			writeJSON(w, 200, QuotaTiersResponse{Tiers: []QuotaTier{{Name: "free"}}})
		case "/reports":
			if r.Method == "POST" {
				writeJSON(w, 201, LeakReportSubmissionResponse{ReportID: "r1"})
			} else {
				writeJSON(w, 200, LeakReportListResponse{Reports: []LeakReport{{ID: "r1"}}})
			}
		case "/reports/r1/resolve":
			writeJSON(w, 200, LeakReportActionResponse{Status: "resolved"})
		case "/health":
			writeJSON(w, 200, HealthCheckResponse{Status: "ok"})
		case "/":
			writeJSON(w, 200, ServiceDiscoveryResponse{Service: "auth"})
		case "/metrics/jwks":
			writeJSON(w, 200, JwksMetricsResponse{ActiveKeys: 2})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}, WithAPIKey("ab0t_sk_admin"))
	if _, err := c.MyQuotaUsage(context.Background(), "tok"); err != nil {
		t.Fatalf("MyQuotaUsage: %v", err)
	}
	if _, err := c.CheckQuota(context.Background(), "api_keys", "tok"); err != nil {
		t.Fatalf("CheckQuota: %v", err)
	}
	if _, err := c.QuotaTiers(context.Background()); err != nil {
		t.Fatalf("QuotaTiers: %v", err)
	}
	rep, err := c.SubmitReport(context.Background(), LeakReportSubmission{Type: "leak"})
	if err != nil || rep.ReportID != "r1" {
		t.Fatalf("SubmitReport: %v %+v", err, rep)
	}
	if _, err := c.ListReports(context.Background(), ""); err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if _, err := c.ResolveReport(context.Background(), "r1", ""); err != nil {
		t.Fatalf("ResolveReport: %v", err)
	}
	if _, err := c.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if _, err := c.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, err := c.JWKSMetrics(context.Background(), ""); err != nil {
		t.Fatalf("JWKSMetrics: %v", err)
	}
}

// ===================== Error model preserved on new ops =====================

func TestNewOpsErrorModel(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 403, map[string]any{"detail": "saml.admin required"})
	}, WithAPIKey("ab0t_sk_x"))
	_, err := c.RegisterSAMLSP(context.Background(), SAMLServiceProviderConfig{EntityID: "e"}, "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsForbidden(err) {
		t.Fatalf("expected forbidden, got %v", err)
	}
	ae, ok := AsAPIError(err)
	if !ok || ae.Endpoint != "/saml/sp/register" {
		t.Fatalf("APIError fields: %+v ok=%v", ae, ok)
	}
}
