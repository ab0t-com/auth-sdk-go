package authclient

// This file defines the permission/role vocabulary (dot-permissions) the auth
// service enforces via RBAC + Zanzibar. They are provided as typed constants so
// SDK callers (especially admin/service clients) can reference required scopes
// without stringly-typed literals. The vocabulary mirrors section "Permission/
// role vocabulary" of the FULL contract.
const (
	ScopeOrgRead     = "org.read"
	ScopeOrgAdmin    = "org.admin"
	ScopeSystemAdmin = "system.admin"

	ScopeUsersRead    = "users.read"
	ScopeUsersWrite   = "users.write"
	ScopeUsersInvite  = "users.invite"
	ScopeUsersElevate = "users.elevate"

	ScopeTeamsRead  = "teams.read"
	ScopeTeamsWrite = "teams.write"

	ScopeSAMLRead  = "saml.read"
	ScopeSAMLAdmin = "saml.admin"
	ScopeSSOAdmin  = "sso.admin"

	ScopeZanzibarAdmin = "zanzibar.admin"

	ScopePermissionsRegister = "permissions.register"

	ScopeEventsSubscribe = "events.subscribe"
	ScopeEventsRead      = "events.read"
	ScopeEventsUpdate    = "events.update"
	ScopeEventsDelete    = "events.delete"
	ScopeEventsTest      = "events.test"

	ScopeAdminPasswordPolicyRead   = "admin.password_policy.read"
	ScopeAdminPasswordPolicyWrite  = "admin.password_policy.write"
	ScopeAdminPasswordResetWrite   = "admin.password_reset.write"
	ScopeAdminReportsRead          = "admin.reports.read"
	ScopeAdminAuditRead            = "admin.audit.read"
	ScopeAdminServiceAccountsWrite = "admin.service_accounts.write"
	ScopeAdminUsersElevate         = "admin.users.elevate"
	ScopeAdminTestWrite            = "admin.test.write"

	ScopeAdminJWKSRead   = "admin.jwks.read"
	ScopeAdminJWKSWrite  = "admin.jwks.write"
	ScopeAdminJWKSRotate = "admin.jwks.rotate"
	ScopeAdminJWKSRevoke = "admin.jwks.revoke"
	ScopeAdminJWKSAdmin  = "admin.jwks.admin"

	ScopeAdminCircuitBreakerRead  = "admin.circuit_breaker.read"
	ScopeAdminCircuitBreakerWrite = "admin.circuit_breaker.write"

	ScopeAdminMetricsRead = "admin.metrics.read"
)
