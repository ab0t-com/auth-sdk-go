# ab0t Auth Service — Go SDK

[![CI](https://github.com/ab0t-com/auth-sdk-go/actions/workflows/ci.yml/badge.svg)](https://github.com/ab0t-com/auth-sdk-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ab0t-com/auth-sdk-go.svg)](https://pkg.go.dev/github.com/ab0t-com/auth-sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Go client for the [ab0t Auth Service](https://auth.service.ab0t.com) — authentication,
authorization, organizations, API keys, SSO, and Zanzibar-style relationship-based access control.

- **Standard library only.** No `require` block, no transitive dependencies. This module gets
  embedded in other people's binaries, so it brings nothing with it. CI enforces this.
- **Interface-first.** `Validator` and `Authorizer` are two-method interfaces, so your handlers are
  testable against fakes with no live auth service.
- **Fails closed.** Errors surface as errors. Nothing in this SDK turns a failure into an "allow".

```bash
go get github.com/ab0t-com/auth-sdk-go
```

Requires Go 1.23+.

## Quick start

```go
import auth "github.com/ab0t-com/auth-sdk-go"

// "" selects the production service (auth.DefaultBaseURL).
client := auth.New("",
    auth.WithAPIKey(os.Getenv("AUTH_SERVICE_KEY")), // this service's own ab0t_sk_ key
    auth.WithExpectedAudience("my-service"),        // reject tokens minted for someone else
)

// AuthN: who is this?
actor, err := client.ValidateToken(ctx, token)
if err != nil || !actor.Valid {
    return errUnauthorized
}
fmt.Println(actor.UserID, actor.OrgID, actor.Permissions)

// AuthZ: may they do this?
ok, err := client.Authorize(ctx, token, "economy.transfer", auth.Resource{Type: "wallet", ID: "w1"})
if err != nil {
    return errUnavailable // 503 — do NOT treat this as allow
}
if !ok {
    return errForbidden
}
```

A complete, runnable HTTP middleware example lives in **[`examples/gate`](examples/gate/main.go)**:

```bash
go run ./examples/gate
```

## The two primitives

Depend on these interfaces, not on `*Client`. That is what makes your code testable.

```go
type Validator interface {
    ValidateToken(ctx context.Context, token string) (*Actor, error)
}

type Authorizer interface {
    Authorize(ctx context.Context, token, action string, resource Resource) (bool, error)
}
```

`*Client` satisfies both. In tests, substitute a struct with the answers you want.

**A credential may be a user JWT or an agent/service API key** (`ab0t_sk_…`). `Authorize` routes
each to the endpoint that can resolve it, so agents and humans go through exactly the same call.
`IsAPIKey(cred)` tells them apart if you need to.

## Three rules for using this safely

1. **A `nil` error is not a yes.** Check the boolean too — `Authorize` returns `(false, nil)` for a
   legitimate denial.
2. **Never turn an error into an allow.** A transport failure or a 5xx means *you do not know*.
   Answer 503, not 200. An auth-service blip must not silently unlock your write surface.
3. **Set an expected audience.** Without `WithExpectedAudience`, a token minted for a different
   service will validate against yours.

## What is covered

| Area | Methods |
|---|---|
| **AuthN** | `ValidateToken`, `ValidateAPIKey`, `Introspect`, `JWKS`, `OrgJWKS`, login/refresh/logout |
| **AuthZ (RBAC)** | `Authorize`, `CheckPermission`, `CheckPermissionPublic`, grant/revoke, permission registry |
| **AuthZ (ReBAC / Zanzibar)** | `ZanzibarCheck`(+`Bulk`/`Wildcard`), `Expand`, `List(Objects\|Users)`, relationship write/delete, namespaces, hierarchy, visualize, watch |
| **Users** | CRUD, profile, password reset, **self-delete (`DeleteCurrentUser`)** |
| **Organizations & teams** | CRUD, membership, roles, invitations, session revocation |
| **API keys & delegation** | create/list/update/delete, service accounts, delegation grant/check |
| **SSO / federation** | providers, SAML, OAuth/OIDC, attribute mappings, JIT provisioning |
| **Mesh** | `ListMeshProviders`, `GetMeshProvider`, `PublishMeshProvider` |
| **Admin & system** | password policy, privilege elevation, super-admin grants, quotas, events, health |

Full operation → method map: **[COVERAGE.md](COVERAGE.md)**.

### Two authorization models — pick deliberately

The service exposes **two** authorization systems and they are easy to cross-wire:

| | Account / RBAC | Zanzibar / ReBAC |
|---|---|---|
| Endpoint | `/permissions/check`, `/auth/validate-token` | `/zanzibar/stores/{store_id}/…` |
| Identity | `user_id` | combined typed string, e.g. `user:alice` |
| Question | "does this user hold this permission?" | "does this subject have this relation to this object?" |
| Use for | coarse capabilities — `admin.write`, `users.read` | per-object sharing — "who can view *this document*" |

Build Zanzibar ids with the `Object()` / `Subject()` helpers rather than concatenating strings:

```go
ok, err := client.ZanzibarCheck(ctx, storeID, auth.CheckPermissionRequest{
    Subject:    auth.Subject("user", "alice"),
    Permission: "view",
    Object:     auth.Object("document", "123"),
}, callerToken)
```

For most route gating you want `Authorize`. Reach for Zanzibar when the answer depends on a
*relationship to a specific object*.

## Transport and resilience

- Timeout: 15s default — `WithTimeout`.
- Retries: 2 by default with exponential backoff, honouring `Retry-After` on 429/503 —
  `WithMaxRetries`, `WithBackoff`.
- JWKS: cached 10 minutes, bounded at 512 key sets with stalest-first eviction, and **serves a
  stale-but-good set if a refresh fails** rather than failing your requests.

> **⚠️ Retries apply to non-idempotent POSTs too.** A create call whose write committed before the
> response was lost will be retried, and on an endpoint with no natural dedup key that can produce a
> duplicate side effect — two invitations, two orgs, two emitted webhooks. Where once-only semantics
> matter, use `WithMaxRetries(0)` for that client or call.

## Testing against this SDK

Depend on the interfaces and no network is involved:

```go
type fakeAuthz struct{ allow bool; err error }

func (f fakeAuthz) Authorize(context.Context, string, string, auth.Resource) (bool, error) {
    return f.allow, f.err
}

// Now test allow, deny, and auth-service-unavailable — including that your
// handler answers 503 rather than 200 on the last one.
```

For end-to-end tests, point `auth.New(srv.URL)` at an `httptest.Server` and assert what the client
sends. That is how this SDK tests itself — see `fixes_test.go`.

## Known gaps

Four methods in `authzmodel.go` (`ReadAuthorizationModel`, `ListAuthorizationModels`,
`WriteAuthorizationModel`, `WriteAndDeleteRelationships`) target routes the service does not expose
yet. They ship as forward-looking stubs, each carrying a `SERVER-GAP` doc note, and
`TestAuthorizationModel_IsStillAServerGap` records executably that they 404 today. When the routes
land, that test fails — which is the signal to remove the warnings.

## Versioning

Pre-1.0. Minor releases may change contracts when the service's contract changes — see
[CHANGELOG.md](CHANGELOG.md), which marks breaking changes explicitly. Pin a version.

The **live OpenAPI spec is the source of truth**, not this SDK. If they disagree, this SDK has a
bug — please report it.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md) — report
privately, never in a public issue.

## License

MIT — see [LICENSE](LICENSE).
