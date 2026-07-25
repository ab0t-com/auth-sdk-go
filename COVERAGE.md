# authclient — Contract Coverage

Reference: the ab0t Auth Service OpenAPI at https://auth.service.ab0t.com/openapi.json
(Auth Service v1.0.0 — **223 paths / 278 operations / 380 schemas**).

This SDK targets the caller archetypes in the contract's Client-Type matrix
(end-user app, service/machine, CLI/device, resource server, admin/tenant
management): the identity & authorization core (users, orgs/tenants, teams,
roles, RBAC + Zanzibar ReBAC, providers/SSO/federation, API keys, delegation,
admin, super-admin) plus the interactive, enterprise and platform domains.

> **Correction (2026-07-12).** An earlier revision of this file claimed
> "FULL contract coverage (278/278 operations, 100%)". That headline was
> **not accurate as a contract-fidelity claim**: a method existing is not the
> same as its request/response shapes matching the live server. In particular
> the entire Zanzibar ReBAC surface was modeled with the WRONG wire shapes
> (split `object_type`/`object_id`/`subject_type`/`subject_id` and a
> `{relationships:[...]}` batch wrapper) that the live server rejects. Those
> types were reconciled to the live OpenAPI on 2026-07-12 (single-tuple
> `RelationshipRequest`, combined typed-string ids, `result_count`,
> `RelationshipEntry`, etc.). A method count is not a fidelity guarantee, and a
> handful of forward-looking capabilities have **no server route** and are
> marked SERVER-GAP (see below).

## Headline numbers

A method exists for every operation surveyed in the reference contract, but note:
the reference contract snapshot and the *live* OpenAPI have drifted, and "a
method exists" ≠ "the wire contract matches". The Zanzibar and RBAC
request/response contracts were verified against the live OpenAPI on 2026-07-12;
the SERVER-GAP items below have no live route.

## Covered by contract section

| § | Domain | Ops | Covered | Go file |
|---|---|---:|---:|---|
| **1** | **Authentication (password/OAuth2/OIDC/PAR/dyn-reg)** | **25** | **25** | `operations.go`, `oauth.go`, `users.go`, `apikeys.go` |
| **2** | **Org-scoped hosted auth (`/organizations/{slug}/auth/*`)** | **9** | **9** | `hosted.go` |
| **3** | **Passwordless (WebAuthn/passkeys, magic links, recovery, devices)** | **17** | **17** | `passwordless.go` |
| **4** | **SAML (IdP/SP, ACS/SLO, metadata, attr-maps, certs, analytics)** | **17** | **17** | `saml.go` |
| **6** | **Tokens (introspect/refresh/revoke)** | **3** | **3** | `operations.go`, `oauth.go` |
| **7** | **JWKS / OIDC discovery / well-known** | **5** | **5** | `operations.go`, `jwks.go`, `oauth.go` |
| **18** | **Email Admin (system + per-org config/templates)** | **14** | **14** | `email.go` |
| **19** | **Hosted login / login-config / clients / invites** | **6** | **6** | `hosted.go` |
| **20** | **Events / Webhook subscriptions** | **9** | **9** | `events.go` |
| **21** | **Network Access Control (IP policy/overrides/allowlists)** | **13** | **13** | `network.go` |
| **22** | **Forward-Auth (edge proxy decisions)** | **12** | **12** | `forwardauth.go` |
| **23** | **Quotas / Tiers** | **3** | **3** | `quotas.go` |
| **24** | **Reports / Abuse** | **4** | **4** | `quotas.go` |
| **25** | **Metrics / Health / Discovery / Help** | **11** | **11** | `system.go` |
| **5** | **Federation / SSO sessions / JIT / attr-map** | **19** | **19** | `providers.go` |
| **8** | **Users (self-service + admin)** | **11** | **11** | `users.go`, `operations.go` |
| **9** | **Organisations / tenants + hierarchy + invites + sessions** | **16** | **16** | `orgs.go`, `operations.go` |
| **10** | **Teams / groups (membership + permissions)** | **8** | **8** | `orgs.go` |
| **11** | **Roles + Permissions (RBAC, registry)** | **10** | **10** | `roles.go`, `operations.go` |
| **12** | **Zanzibar (ReBAC tuples, check/expand/list, namespaces)** | **21** | **21** | `permissions.go` |
| **13** | **Providers / SSO connection config** | **7** | **7** | `providers.go` |
| **14** | **API Keys + Service Accounts** | **5** | **5** | `apikeys.go` |
| **15** | **Delegation (act-as / impersonation)** | **4** | **4** | `apikeys.go` |
| **16** | **Admin (password policy, JWKS, breakers, service accts, elevation)** | **22** | **22** | `admin.go` |
| **17** | **Super-Admin (time-bound grants + approval)** | **7** | **7** | `admin.go` |

**A method exists for every surveyed contract section.** (See the top-of-file
correction: presence of a method is not a wire-contract-fidelity guarantee; the
Zanzibar/RBAC shapes were reconciled to the live OpenAPI on 2026-07-12.)
Sections §1/§6/§7
which were previously partial are now complete (interactive authorize, PAR,
form token endpoint, dynamic client registration, email-verify, password-reset
and OIDC/OAuth discovery added in `oauth.go`).

## New domains (this release)

### §1 interactive OAuth2/OIDC — `oauth.go`
- `GET /auth/authorize` -> `OAuthAuthorize`
- `POST /auth/oauth/par` -> `PushedAuthorizationRequest`
- `GET /auth/oauth/{provider}/authorize` -> `ProviderAuthorizeInfo` (typed; complements `OAuthAuthorizeURL`)
- `POST /auth/oauth/token` -> `OAuthToken`
- `POST /token/refresh` -> `RefreshTokenForm`
- `POST /auth/oauth/register` -> `RegisterClient`
- `GET|PUT|DELETE /auth/oauth/register/{client_id}` -> `GetClientRegistration` / `UpdateClientRegistration` / `DeleteClientRegistration`
- `POST /auth/verify-email/send|confirm` -> `SendVerificationEmail` / `ConfirmVerificationEmail`
- `POST /auth/password-reset`, `/auth/password-reset/confirm`, `GET /auth/password-reset/validate` -> `RequestPasswordResetAuth` / `ConfirmPasswordResetAuth` / `ValidatePasswordResetToken`
- `GET /.well-known/openid-configuration` -> `OpenIDConfiguration`
- `GET /.well-known/oauth-authorization-server` -> `AuthorizationServerMetadata`
- `GET /.well-known/jwks.json/health` -> `JWKSHealth`

### §2 org-scoped hosted auth + §19 hosted login — `hosted.go`
- `OrgLogin`, `OrgRegister`, `OrgToken`, `OrgRefresh`, `OrgLogout`, `OrgResetPassword`, `OrgAuthProviders`, `OrgSSOInitiate`, `OrgSSOCallback`
- `GetLoginConfig`, `UpdateLoginConfig`, `GetPublicLoginConfig`, `ListOrgClients`, `GetHostedLoginPage`, `AcceptInvitePage`

### §3 passwordless — `passwordless.go`
- WebAuthn: `WebAuthnConfig`, `WebAuthnRegisterStart`, `WebAuthnRegisterFinish`, `WebAuthnAuthenticateStart`, `WebAuthnAuthenticateFinish`, `ListWebAuthnCredentials`, `UpdateWebAuthnCredential`, `DeleteWebAuthnCredential`
- Magic links: `SendMagicLink`, `VerifyMagicLink`, `ListActiveMagicLinks`, `RevokeMagicLink`, `MagicLinkConfig`, `MagicLinkAnalytics`
- Recovery/devices: `GenerateRecoveryCodes`, `VerifyRecoveryCode`, `ListDevices`

### §4 SAML — `saml.go`
- IdP/SP flows: `SAMLMetadata`, `SAMLSSORedirect`, `SAMLSSOPost`, `SAMLAssertionConsumer`, `SAMLSingleLogout`, `SAMLSPMetadata`
- SP mgmt: `RegisterSAMLSP`, `ListSAMLSessions`, `ListSAMLSPs`, `GetSAMLSP`, `UpdateSAMLSP`, `DeleteSAMLSP`
- Attr-maps/certs/analytics: `GetSAMLAttributeMappings`, `UpdateSAMLAttributeMappings`, `GetSAMLCertificates`, `GenerateSAMLCertificate`, `SAMLAnalytics`

### §18 email admin — `email.go`
- System: `EmailHistory`, `EmailStats`, `GlobalEmailConfig`, `EmailTemplateTypes`
- Per-org: `OrgEmailHistory`, `GetOrgEmailConfig`, `UpdateOrgEmailConfig`, `DeleteOrgEmailConfig`, `ListOrgEmailTemplates`, `GetOrgEmailTemplate`, `UpdateOrgEmailTemplate`, `DeleteOrgEmailTemplate`, `PreviewOrgEmailTemplate`, `SendTestEmail`

### §20 events/webhooks — `events.go`
- `EventTypes`, `CreateEventSubscription`, `ListEventSubscriptions`, `GetEventSubscription`, `UpdateEventSubscription`, `DeleteEventSubscription`, `TestEventSubscription`, `ToggleEventSubscription`, `EventSubscriptionStats`

### §21 network access control — `network.go`
- `CreateNetworkPolicy`, `ListNetworkPolicies`, `GetNetworkPolicy`, `UpdateNetworkPolicy`, `DeleteNetworkPolicy`, `EvaluateNetworkPolicy`, `CreateEmergencyOverride`, `ListNetworkOverrides`, `DeleteNetworkOverride`, `CreateTempAllowlist`, `ListTempAllowlist`, `DeleteTempAllowlist`, `ListNetworkViolations`

### §22 forward-auth — `forwardauth.go`
- `ForwardAuthLive`, `ForwardAuth`, `ForwardAuthPass`, `ForwardAuthFail` (each accepts GET/POST/HEAD, returning a typed `ForwardAuthDecision`)

### §23 quotas + §24 reports — `quotas.go`
- `MyQuotaUsage`, `CheckQuota`, `QuotaTiers`
- `SubmitReport`, `ListReports`, `DismissReport`, `ResolveReport`

### §25 metrics/health/discovery — `system.go`
- `JWKSMetrics`, `RecentAlerts`, `Health`, `Status`, `JWKSHealthDetail`, `RecoverJWKS`, `EnterpriseLicense`, `Help`, `EnterpriseHelp`, `Metrics`, `Discover`

## Operation -> method map (in-scope domains)

### §8 Users — `users.go` / `operations.go`
- `GET /users/me` -> `GetMyProfile`
- `PUT /users/me` -> `UpdateMyProfile`
- `POST /users/me/change-password` -> `ChangeMyPassword`
- `GET /users/{user_id}` -> `GetUser`
- `PUT /users/{user_id}` -> `UpdateUser`
- `POST /users/{user_id}/verify-email` -> `VerifyUserEmail`
- `POST /users/request-password-reset` -> `RequestPasswordReset`
- `POST /users/reset-password` -> `ResetPassword`
- `POST /users/{user_id}/deactivate` -> `DeactivateUser`
- `POST /users/{user_id}/activate` -> `ActivateUser`
- `GET /users/me/organizations` -> `GetMyOrganizations`

### §9 Organisations — `orgs.go` / `operations.go`
- `POST /organizations/` -> `CreateOrganization`
- `GET /organizations/{org_id}` -> `GetOrganization`
- `PUT /organizations/{org_id}` -> `UpdateOrganization`
- `DELETE /organizations/{org_id}` -> `DeleteOrganization`
- `POST /organizations/{org_id}/teams` -> `CreateTeam`
- `GET /organizations/{org_id}/teams` -> `ListTeams`
- `GET /organizations/{org_id}/hierarchy` -> `GetOrgHierarchy`
- `GET /organizations/{org_id}/users` -> `ListOrgUsers`
- `PUT /organizations/{org_id}/users/{user_id}` -> `UpdateOrgUserRole`
- `DELETE /organizations/{org_id}/users/{user_id}` -> `RemoveOrgUser`
- `POST /organizations/{org_id}/invite` -> `InviteToOrganization`
- `GET /organizations/{org_id}/sessions` -> `ListOrgSessions`
- `DELETE /organizations/{org_id}/sessions` -> `RevokeOrgSessions`
- `DELETE /organizations/{org_id}/users/{user_id}/sessions` -> `RevokeUserSessions`
- `GET /organizations/{org_id}/invitations` -> `ListInvitations`
- `DELETE /organizations/{org_id}/invitations/{invitation_id}` -> `RevokeInvitation`

### §10 Teams — `orgs.go`
- `GET /teams/{team_id}` -> `GetTeam`
- `PUT /teams/{team_id}` -> `UpdateTeam`
- `DELETE /teams/{team_id}` -> `DeleteTeam`
- `POST /teams/{team_id}/members` -> `AddTeamMember`
- `GET /teams/{team_id}/members` -> `ListTeamMembers`
- `DELETE /teams/{team_id}/members/{user_id}` -> `RemoveTeamMember`
- `PUT /teams/{team_id}/members/{user_id}` -> `UpdateTeamMemberRole`
- `GET /teams/{team_id}/permissions` -> `GetTeamPermissions`

### §11 Roles + Permissions — `roles.go` / `operations.go`
- `GET /permissions/roles` -> `GetRoles`
- `POST /permissions/check` -> `CheckPermission`
- `GET /permissions/user/{user_id}` -> `GetUserPermissions`
- `POST /permissions/grant` -> `GrantPermission`
- `POST /permissions/revoke` -> `RevokePermission`
- `GET /permissions/registry/services` -> `ListRegisteredServices`
- `GET /permissions/registry/valid-permissions` -> `ListValidPermissions`
- `POST /permissions/registry/validate` -> `ValidatePermissions`
- `GET /permissions/registry/stats` -> `RegistryStats`
- `POST /permissions/registry/register` -> `RegisterServicePermissions`

### §12 Zanzibar — `permissions.go`
- `POST .../check` -> `ZanzibarCheck`
- `POST .../check/bulk` -> `ZanzibarCheckBulk`
- `GET .../check/wildcard` -> `ZanzibarCheckWildcard`
- `POST .../expand` -> `ZanzibarExpand`
- `POST .../list-objects` -> `ZanzibarListObjects`
- `POST .../list-users` -> `ZanzibarListUsers`
- `POST .../relationships` -> `WriteRelationships`
- `DELETE .../relationships` -> `DeleteRelationships`
- `GET .../relationships/{object_type}/{object_id}` -> `ListRelationships`
- `POST .../namespaces` -> `CreateNamespace`
- `GET .../namespaces` -> `ListNamespaces`
- `GET .../namespaces/{namespace_name}` -> `GetNamespace`
- `POST .../permissions/grant` -> `ZanzibarGrant`
- `DELETE .../permissions/revoke` -> `ZanzibarRevoke`
- `POST .../hierarchy/setup` -> `SetupOrgHierarchy`
- `POST .../teams/membership` -> `SetupTeamMembership`
- `POST .../visualize/hierarchy` -> `VisualizeHierarchy`
- `POST .../visualize/permissions` -> `VisualizePermissions`
- `POST .../migrate/setup-defaults` -> `MigrateSetupDefaults`
- `POST .../migrate/permissions` -> `MigratePermissions`
- `GET .../watch/status` -> `WatchStatus`
- (plus `POST /auth/check-permission` -> `CheckPermissionPublic`)

Authorization-model management + advanced tuple ops (`authzmodel.go`):

These were authored ahead of the server. Verified against the live auth service
OpenAPI (`https://auth.service.ab0t.com/openapi.json`) on 2026-07-12: the service
exposes **no authorization-model management** and **no atomic write+delete
transaction**. Methods below are kept as forward-looking additions and marked
`SERVER-GAP` in their godoc — they will 404 until the server implements them.

- `POST .../authorization-models` -> `WriteAuthorizationModel` — **SERVER-GAP (no such route)**
- `GET .../authorization-models/{authorization_model_id}` -> `ReadAuthorizationModel` — **SERVER-GAP (no such route)**
- `GET .../authorization-models` -> `ListAuthorizationModels` — **SERVER-GAP (no such route)**
- `POST .../relationships/transact` -> `WriteAndDeleteRelationships` — **SERVER-GAP (no such route; use Write+Delete)**
- `GET .../relationships/{object_type}/{object_id}` -> `ListRelationshipsPaged` — route REAL, but **pagination is a SERVER-GAP**: the server accepts only a `relation` query filter and returns `{object, relationships:[]RelationshipEntry}` with no cursor; `page_size`/`continuation_token` are ignored
- `POST .../list-objects` -> `ListObjectsPaged` — route REAL; server caps with `max_results` (not `page_size`), no request-side cursor, response returns `continuation_token` + `result_count`
- (client-side) `DeleteAllRelationshipsForObject` — list+delete cleanup loop over REAL routes (works despite unpaged list)
- (client-side) `EnsureAuthorizationModel` — idempotent read-then-write apply; **SERVER-GAP** (depends on model management above)

Zanzibar wire contract (reconciled to the live OpenAPI on 2026-07-12):
- `RelationshipRequest` is a **single tuple** `{object, relation, subject, context?, expires_at?}` (was a wrong `{relationships:[{object_type,object_id,subject_type,subject_id,...}]}` batch). `Write`/`DeleteRelationships` take one tuple.
- `CheckPermissionRequest` (Zanzibar) is `{subject, permission, object, org_id?, context?, consistency_token?}` (was `{object_type,object_id,relation,subject_type,subject_id,...}`).
- `ListObjectsRequest` `{subject, permission, object_type, org_id?, max_results?, consistency_token?}`; `ListUsersRequest` `{object, permission, org_id?, max_results?, expand_groups?, consistency_token?}`.
- Reads return `RelationshipEntry{relation, subject, context, created_at, expires_at}` and `RelationshipsResponse{object, relationships}`; list responses report `result_count` (not `total`).
- `WriteOperationResponse{success, message, consistency_token?}`.
- Helpers `Object(typ,id)` / `Subject(typ,id)` build the combined `"type:id"` strings the server wants.

> RESOLVED (2026-07-12): the split `object_type`/`object_id`/`subject_type`/
> `subject_id` types and the `{relationships:[...]}` wrapper that the earlier note
> flagged as diverging from the live server have been removed. The remediation
> reconciled against the live OpenAPI on 2026-07-12.

### §13 Providers — `providers.go`
- `POST /providers/` -> `CreateProvider`
- `GET /providers/` -> `ListProviders`
- `GET /providers/{provider_id}` -> `GetProvider`
- `PUT /providers/{provider_id}` -> `UpdateProvider`
- `DELETE /providers/{provider_id}` -> `DeleteProvider`
- `POST /providers/test` -> `TestProvider`
- `GET /providers/types/supported` -> `SupportedProviderTypes`

### §5 Federation — `providers.go`
- SSO sessions: `ListSSOSessions`, `CreateSSOSession`, `GetSSOSession`, `DeleteSSOSession`, `CreateDomainToken`
- Propagation: `PropagateSSO`, `PropagateLogout`
- Config/domains: `GetSSOConfig`, `UpdateSSOConfig`, `ListSSODomains`, `GetSSODomain`, `CreateSSODomain`, `UpdateSSODomain`, `DeleteSSODomain`
- Attr-map/JIT/stats: `ListAttributeMappings`, `CreateAttributeMapping`, `GetJITConfig`, `UpdateJITConfig`, `FederationStats`

### §14 API Keys — `apikeys.go`
- `GET /api-keys/` -> `ListAPIKeys`
- `POST /api-keys/` -> `CreateAPIKey`
- `GET /api-keys/{key_id}` -> `GetAPIKey`
- `PUT /api-keys/{key_id}` -> `UpdateAPIKey`
- `DELETE /api-keys/{key_id}` -> `DeleteAPIKey`

### §15 Delegation — `apikeys.go`
- `POST /delegation/grant` -> `GrantDelegation`
- `DELETE /delegation/revoke/{actor_id}` -> `RevokeDelegation`
- `GET /delegation/check/{target_user_id}` -> `CheckDelegation`
- `GET /delegation/list/{user_id}` -> `ListDelegations`
- (plus `POST /auth/delegate` -> `Delegate`)

### §16 Admin — `admin.go`
- Password policy: `SetPasswordPolicy`, `GetPasswordPolicy`, `ForcePasswordReset`, `PasswordComplianceReport`, `UpdatePasswordAge`, `PasswordAuditEvents`
- JWKS lifecycle: `RevokeSigningKey`, `ListRevokedKeys`, `RotateSigningKeys`, `JWKSRotationStatus`, `JWKSNextRotation`, `GenerateSigningKey`, `ActivateSigningKey`, `CleanupSigningKeys`
- Service accounts / elevation: `CreateServiceAccount`, `ElevatePrivileges`
- Circuit breakers: `CircuitBreakerStatus`, `ResetCircuitBreaker`, `ResetAllCircuitBreakers`
- Audit / emergency / provider status: `RevocationAuditLog`, `EmergencyRevokeAPIKeys`, `UpdateProviderStatus`

### §17 Super-Admin — `admin.go`
- `SuperAdminGrant`, `SuperAdminRevoke`, `SuperAdminExtend`, `SuperAdminActiveGrants`, `SuperAdminApprove`, `SuperAdminCleanupExpired`, `SuperAdminAuditLog`

## Pre-existing core coverage (§1/§6/§7)
`Login`, `Register`, `Refresh`, `Logout`, `RevokeToken`, `RevokeTokenPublic`,
`OAuthAuthorizeURL`, `OAuthCallback`, `SwitchOrganization`, `Me`,
`ValidateToken`, `ValidateAPIKey`, `Introspect`, `JWKS`, `RefreshJWKS`,
`OrgJWKS`, `SigningKey`.

## Not covered / known gaps

Every surveyed contract section has a typed method. Browser/XML-oriented
endpoints (SAML SSO/ACS/SLO/metadata, hosted login/accept-invite pages,
forward-auth decisions) are exposed with the appropriate raw-string / form /
decision shapes rather than forcing a JSON model where the wire format is not
JSON.

**SERVER-GAP capabilities** (client method exists, but the live OpenAPI has no
such route as of 2026-07-12): `WriteAuthorizationModel`, `ReadAuthorizationModel`,
`ListAuthorizationModels`, `EnsureAuthorizationModel`, `WriteAndDeleteRelationships`
(`/relationships/transact`), and list-relationships pagination. See `authzmodel.go`.

## Conventions (preserved from the core)

- **Isolation**: stdlib-only module `github.com/ab0t-com/auth-sdk-go`; no
  coupling to server/sim internals.
- **Error model**: every non-2xx returns `*APIError` with `Is*` classifiers
  (`IsUnauthorized`, `IsForbidden`, `IsNotFound`, `IsValidationError`,
  `IsRateLimited`, `IsServerError`, `IsRetryable`).
- **Auth threading**: each method takes a trailing `token` / `callerToken`
  argument. Passing `""` falls back to the configured service API key
  (`WithAPIKey`), so the same client serves end-user, service and admin callers.
- **Scope constants**: `scopes.go` exposes the dot-permission vocabulary
  (`ScopeOrgAdmin`, `ScopeUsersWrite`, `ScopeZanzibarAdmin`, `ScopeSystemAdmin`, ...).
- **Retry/backoff, JWKS caching**: unchanged from the core transport.
