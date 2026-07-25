// Package authclient is an isolated, typed Go client for the ab0t Auth Service
// (an Okta-style enterprise auth/permission stack served at
// https://auth.service.ab0t.com).
//
// # Isolation
//
// This package is its own Go module (github.com/ab0t-com/auth-sdk-go) and
// depends ONLY on the standard library. It has no dependency on any particular
// server, simulation, or any game internals. The server can adopt it later to
// gate routes via Authorize/ValidateToken without coupling to auth-service
// internals or to this package's transport details.
//
// # What the auth service provides
//
// Multi-provider authentication (password, OAuth/OIDC, SAML, passwordless),
// multi-tenant organizations, RBAC + a Zanzibar-style relationship engine,
// JWKS-backed JWTs, federation/SSO, API keys and service accounts. Tokens are
// JWTs bound to an active org (tenant); access tokens are short-lived and
// refreshed with a long-lived refresh token. Services authenticate to each
// other with API keys (prefix "ab0t_sk_") sent as bearer tokens.
//
// # Surface
//
// The client groups the endpoints a resource server / agent actually needs:
//
//	Authentication: Login, Register, Refresh, Logout, SwitchOrganization, Me, Delegate
//	OAuth2/OIDC:    OAuthAuthorizeURL, OAuthCallback
//	Revocation:     RevokeToken, RevokeTokenPublic
//	Token/authz:    ValidateToken, ValidateAPIKey, Introspect, CheckPermission, Authorize
//	JWKS:           JWKS, RefreshJWKS, OrgJWKS, SigningKey (TTL-cached)
//	Users:          GetMyProfile, UpdateMyProfile, ChangeMyPassword, GetUser,
//	                UpdateUser, Activate/DeactivateUser, VerifyUserEmail, *PasswordReset
//	Orgs/tenants:   Create/Get/Update/DeleteOrganization, GetOrgHierarchy,
//	                ListOrgUsers, UpdateOrgUserRole, RemoveOrgUser, Invite*,
//	                List/RevokeOrgSessions, RevokeUserSessions
//	Teams/groups:   Create/Get/Update/DeleteTeam, *TeamMember*, GetTeamPermissions
//	Roles/RBAC:     GetRoles, Grant/RevokePermission (query-param based),
//	                registry (services, valid-permissions, validate, stats, register)
//	Zanzibar ReBAC: ZanzibarCheck(+Bulk/Wildcard), Expand, List(Objects|Users),
//	                Write/DeleteRelationships (single tuple), namespaces,
//	                grant/revoke, hierarchy/team setup, visualize, migrate, watch.
//	                Uses combined typed-string ids ("doc:123", "user:alice"); build
//	                them with Object()/Subject(). Request/response types match the
//	                live OpenAPI (verified 2026-07-12).
//	Authz model:    Write/Read/List/EnsureAuthorizationModel,
//	                WriteAndDeleteRelationships (atomic), List(Relationships|Objects)Paged,
//	                DeleteAllRelationshipsForObject
//	                (forward-looking: model management + transact + list-relationships
//	                 pagination are SERVER-GAPs not in the auth service OpenAPI;
//	                 the REAL schema surface is namespaces. See COVERAGE.md.)
//	Providers/SSO:  Create/List/Get/Update/Delete/TestProvider, federation
//	                SSO sessions/config/domains, attribute mappings, JIT, stats
//	API keys:       List/Create/Get/Update/DeleteAPIKey (CreateServiceAccount)
//	Delegation:     Grant/Revoke/Check/ListDelegation
//	Admin:          password policy, JWKS rotate/revoke/generate/activate/cleanup,
//	                circuit breakers, elevate privileges, audit, emergency revoke
//	Super-admin:    time-bound Grant/Revoke/Extend/Approve + active-grants/audit
//	Interactive:    OAuthAuthorize, PushedAuthorizationRequest, OAuthToken,
//	                RefreshTokenForm, dynamic client registration, email-verify,
//	                password-reset, OIDC/OAuth discovery, JWKS health
//	Hosted auth:    OrgLogin/Register/Token/Refresh/Logout, OrgAuthProviders,
//	                OrgSSOInitiate/Callback, login-config, hosted pages, invites
//	Passwordless:   WebAuthn register/authenticate + credentials, magic links,
//	                recovery codes, devices
//	SAML:           IdP/SP SSO/ACS/SLO/metadata, SP CRUD, attribute mappings,
//	                certificates, analytics
//	Email admin:    system + per-org config/templates/preview/test
//	Events:         webhook subscription CRUD + test/toggle/stats
//	Network ACL:    policies, emergency overrides, temp allowlists, violations
//	Forward-auth:   ForwardAuth/Live/Pass/Fail edge decisions (GET/POST/HEAD)
//	Quotas/reports: MyQuotaUsage, CheckQuota, QuotaTiers, Submit/List/Dismiss/ResolveReport
//	System:         Health, Status, Discover, Metrics, JWKSMetrics, alerts, help
//
// The client covers the operations a resource server / agent needs across the
// surfaces listed above. The Zanzibar ReBAC and account/RBAC request/response
// contracts were reconciled against the live OpenAPI on 2026-07-12; a small
// number of forward-looking authorization-model / transact / paging capabilities
// have no server route yet and are marked SERVER-GAP in authzmodel.go. See
// COVERAGE.md for the operation -> method map and the known gaps.
//
// Two interfaces decouple callers from the concrete client:
//
//	Validator  — resolve a bearer token to an Actor (who + tenant + permissions).
//	Authorizer — decide whether a token may perform an action on a resource.
//
// The route-gating primitive is:
//
//	allowed, _ := client.Authorize(ctx, token, "world.write", authclient.Resource{Type: "world", ID: "w1"})
//
// # Quick start
//
//	c := authclient.New("https://auth.service.ab0t.com",
//	        authclient.WithAPIKey("ab0t_sk_..."))   // server's service key (optional)
//
//	tok, err := c.Login(ctx, authclient.LoginRequest{Email: e, Password: p})
//	actor, err := c.ValidateToken(ctx, tok.AccessToken)
//	ok, err := c.Authorize(ctx, tok.AccessToken, "world.write",
//	        authclient.Resource{Type: "world", ID: "w1"})
//
// See README.md for the full mapping to endpoints.
package authclient
