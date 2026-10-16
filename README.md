# ab0t Auth Service — Go SDK

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

## Command line

```bash
go install github.com/ab0t-com/auth-sdk-go/cmd/ab0t-auth@latest

ab0t-auth login --key ab0t_sk_…      # or --email you@example.com
ab0t-auth whoami
ab0t-auth can user:alice view doc:123 --store my-store
ab0t-auth doctor                     # why isn't it working?
ab0t-auth help can                   # deep help: purpose, example, failures, what's next
ab0t-auth about                      # licence, source, support, the Go SDK
```

Rehearse writes with `--dry-run`, time-box a grant with `--expires 24h`, clear an object with
`revoke-all`, and get the whole capability catalogue as data with `help --json`.

Same zero dependencies as the library. `NO_COLOR` is honoured, `--json` works on
every command, colour is never the only signal, and exit codes carry the answer
(`0` allowed, `2` denied) so `if ab0t-auth can …; then` works in a script.
`ab0t-auth help` lists everything.

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
   service will validate against yours. `WithExpectedAudience` also applies to API keys, and mesh
   service keys carry no audience — if your routes accept those too, use
   `WithExpectedJWTAudience`, which checks user JWTs only.

## What is covered

| Area | Methods |
|---|---|
| **AuthN** | `ValidateToken`, `ValidateAPIKey` (cached by default — see [Validation caching](#validation-caching-and-local-verification)), `VerifyAccessTokenLocal` (no network), `Introspect`, `JWKS`, `OrgJWKS`, login/refresh/logout |
| **AuthZ (RBAC)** | `Authorize`, `CheckPermission`, `CheckPermissionPublic`, grant/revoke, permission registry |
| **AuthZ (ReBAC / Zanzibar)** | `ZanzibarCheck`(+`Bulk`/`Wildcard`), `Expand`, `List(Objects\|Users)`, relationship write/delete, namespaces, hierarchy, visualize, watch |
| **Users** | CRUD, profile, password reset, **self-delete (`DeleteCurrentUser`)** |
| **Organizations & teams** | CRUD, membership, roles, invitations, session revocation |
| **Calling other mesh services** | **`TokenFor`** — one call for a token to another service, as the service itself (client credentials) or for a signed-in person (RFC 8693 token exchange); cached, typed errors — see [Calling another mesh service](#calling-another-mesh-service--tokenfor) and [docs/OBO_TOKEN_EXCHANGE.md](docs/OBO_TOKEN_EXCHANGE.md). Raw `ExchangeToken` / `OAuthToken` remain |
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

For most route gating you want `Authorize`. Reach for Zanzibar when the answer depends on a
*relationship to a specific object*.

## Zanzibar without the ceremony

The raw methods mirror the HTTP API exactly — every operation reachable, every type matching the
wire. That is the right foundation, but it is not what using it should feel like. Bind the store
once and ask questions:

```go
store := client.Store(storeID, callerToken)

// Can alice view this document?
ok, err := store.Can(ctx, "user", "alice", "view", "doc", "123")

// Make her the owner.
err = store.Relate(ctx, "user", "alice", "owner", "doc", "123")

// Which documents can she view?  (the query behind a filtered index page)
docs, err := store.WhatCan(ctx, auth.Subject("user", "alice"), "view", "doc")

// Who can view this one?  (the query behind a sharing dialog — groups expanded)
users, err := store.WhoCan(ctx, auth.Object("doc", "123"), "view")

// Several questions, one round trip.
ok, err = store.CanAll(ctx,
    auth.Check("user", "alice", "view", "doc", "1"),
    auth.Check("user", "alice", "view", "doc", "2"),
)

// Why did it decide that?  (reason + the relationship path it followed)
res, err := store.Why(ctx, auth.Subject("user", "alice"), "view", auth.Object("doc", "123"))
```

Types are separate arguments on purpose. `("user", "alice")` is impossible to get wrong;
`"user:alice"` is easy to get wrong, and getting it wrong produces a silent **deny** rather than an
error. Use the `*ID` variants (`CanID`, `RelateID`, `UnrelateID`) when you already hold a combined
id.

Every boolean here **fails closed**: an error is `false`, an empty batch is `false` (nothing asked
is not everything permitted), and a bulk response with the wrong number of results is an error
rather than a guess. `Relate` treats `success:false` as an error even on a 200, because a write that
is reported as refused is not a write.

This layer is over the raw methods, never instead of them — `ZanzibarCheck`, `WriteRelationships`
and the rest keep working unchanged, so anything the service can do stays reachable.

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

## Validation caching and local verification

**Validation answers are cached in-process by default (since v0.12.0).** The TTL of a "yes" is the
time a revocation can take to reach your process — that is the trade, stated plainly:

| Question | "yes" cached | "no" cached | So after a revocation this process may keep accepting for up to |
|---|---|---|---|
| `ValidateAPIKey`, `ValidateToken` with an `ab0t_sk_` key | 60 s | 10 s | **60 s** (deleted / revoked API key) |
| `ValidateToken` / `ValidateTokenWith` with a JWT | 15 s, never past the token's `exp` | 5 s | **15 s** (logout, revoked session, removed membership) |
| `Authorize`, or any validation with `RequiredPermissions` | 15 s | 5 s | **15 s** (removed permission) |

Errors (network, 429, 5xx) are never cached, and an expired entry is never served when the auth
service cannot be reached — the cache fails closed. (A definite `401` from validate-token is an
answer — "not valid" — and is remembered for the "no" TTL like `{valid:false}`; the caller gets the
same error either way.) Ways out, from narrow to broad:

```go
client.InvalidateValidation(cred)                       // you learned a credential is gone
ok, err := client.Authorize(authclient.WithFreshValidation(ctx), tok, "billing.refund", res) // always ask, for this call
client := authclient.New("", authclient.WithValidationCache(0))  // no cache at all (pre-v0.12.0 behaviour)
```

An explicit `WithValidationCache(ttl)` / `WithValidationCacheOptions` keeps exactly what it says:
one TTL for every question (and, as before, no caching of the resource-scoped PDP call inside
`Authorize`). `ValidationCacheStats()` shows hits and misses.

**`VerifyAccessTokenLocal`** verifies a JWT with no network call: RS256 signature against the
cached JWKS (an unknown `kid` refetches at most once a minute), `iss`, `aud` (when you expect one),
`exp`/`nbf` with at most 60 s of clock skew, and the token type (refresh tokens are always rejected;
delegation tokens only with `AllowDelegation`). **It cannot see logout.** The service's access
tokens are session-backed — logout revokes them at the service immediately — and a local check
keeps accepting a logged-out token until its `exp` (about 15 minutes). That is why `ValidateToken`
still asks the service; choose per route. A failed check matches `ErrInvalidAccessToken` (answer
401); any other error means the key set could not be fetched (answer 503).

```go
claims, err := client.VerifyAccessTokenLocal(ctx, tok, authclient.LocalVerifyOptions{Audience: "my-service"})
switch {
case errors.Is(err, authclient.ErrInvalidAccessToken): // 401
case err != nil:                                         // 503 — could not evaluate
default:                                                 // claims.Subject, claims.OrgID, …
}
```

## Calling another mesh service — `TokenFor`

Your app gets a token for service B with one call. Pass `nil` as the session when your service acts
as itself; pass the signed-in person's session when it acts for them:

```go
c := auth.New(authURL, auth.WithClientCredentials(clientID, clientSecret)) // sent as HTTP Basic

tok, err := c.TokenFor(ctx, "https://b.service.example", "b.documents.read", nil)     // as the service
tok, err  = c.TokenFor(ctx, "https://b.service.example", "b.documents.read", session) // for the person
var consent *auth.ConsentRequired
switch {
case errors.Is(err, auth.ErrReauthenticate):  // the person's token was not accepted — sign them in again, retry once
case errors.As(err, &consent):                 // the person can approve: send them to consent.AuthorizationURL(...)
case errors.Is(err, auth.ErrNoConnection):     // invalid_target — no usable connection / unknown resource
case errors.Is(err, auth.ErrScopeNotAllowed):  // invalid_scope — ask for less
case errors.Is(err, auth.ErrClientAuth):       // invalid_client — fix / rotate the secret
case errors.Is(err, auth.ErrClientNotEnabled): // unauthorized_client — register the grant type
case errors.Is(err, auth.ErrUnavailable):      // 5xx / network — back off; never treat as allowed
}
req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
```

- Tokens are cached in memory until 30 s before they expire (bounded, one request per key under
  concurrency, errors never cached), so call `TokenFor` per request. There is no refresh token.
- Only the client credentials go to the token endpoint — a `WithAPIKey` key is not sent there.
- The person-present call sends the person's token as `subject_token` with your client credentials
  and no `actor_token` (RFC 8693, the target design). **Until your auth service accepts that, add
  `auth.WithLegacyActorExchange(audience)`**: TokenFor then runs today's chain (your app's
  client-credentials token as the `actor_token`, `audience` = B's registered service audience, plus a
  one-time delegation grant from each person). Removing the option later is the only change.
- Error names follow the wire: `400 invalid_request` and `400 invalid_grant` both mean "re-authenticate"
  (services are moving from the second to the first), `invalid_target` (+ `"suberror":"consent_required"`),
  `invalid_scope`, `invalid_client`, `unauthorized_client`.

Setup and the full wire contract: [docs/OBO_TOKEN_EXCHANGE.md](docs/OBO_TOKEN_EXCHANGE.md);
runnable: [`examples/obo`](examples/obo/main.go). Test it with `authclienttest.NewTokenEndpoint()`.

## HTTP middleware

`authmw` gates routes, so you do not copy-paste a gate out of an example:

```go
import "github.com/ab0t-com/auth-sdk-go/authmw"

gate := &authmw.Gate{V: client, A: client}
mux.Handle("POST /admin", gate.Require("admin.write", "service", adminHandler))
http.ListenAndServe(":8080", gate.Authenticate(mux))
```

`401` no credential · `401` invalid credential · `403` denied · **`503` auth service unreachable** ·
else your handler.

The credential is read from `Authorization: Bearer …` (the scheme is case-insensitive), or — when
that header is absent — from `X-API-Key`, the header mesh consumers send their service key in
(`authmw.Credential`; `Gate.APIKeyHeader` names a different header). `Authorization` wins when both
are sent.

That 503 is the whole point. "I could not decide" is not "yes" — a gate that allows on error turns
an auth-service blip into an open door, quietly, because the requests succeed and nothing pages
anyone. Fail-closed is the default and `FailOpen` must be set deliberately. The other half: an
**invalid** credential is a `401` — the auth service answered, so clients re-authenticate instead
of retrying.

A JSON API where every route needs a caller, accepting user JWTs minted for this service and mesh
service keys, with each caller's permissions on the request:

```go
client := auth.New("", auth.WithExpectedJWTAudience("my-service")) // JWTs only; service keys carry no audience
gate := &authmw.Gate{
    V: client, A: client,
    IncludePermissions: true,               // JWT callers get Permissions too (API keys already do)
    WriteDenial:        authmw.JSONDenial,  // {"error":"invalid token"} instead of text
}
http.ListenAndServe(":8080", gate.RequireIdentity(mux)) // 401 no/invalid credential · 503 auth down

// in a handler:
caller := authmw.Identity(r.Context()) // caller.UserID, caller.OrgID, caller.Permissions
```

| | no credential | invalid credential | denied | auth unreachable |
|---|---|---|---|---|
| `Authenticate` | continues anonymously | 401 | — | 503 |
| `RequireIdentity` | 401 | 401 | — | 503 |
| `Require` | 401 | 401 when the auth service answers 401 | 403 | 503 |

Every default is unchanged: `IncludePermissions` off, plain-text denials, `X-API-Key`. Check your
own wiring against this contract from your tests with
[`authmw/authmwtest`](authmw/authmwtest/authmwtest.go) — see [TESTS.md](TESTS.md).

## Testing

Test doubles ship with the SDK — you do not have to write them:

```go
import "github.com/ab0t-com/auth-sdk-go/authclienttest"

gate := &authmw.Gate{V: authclienttest.Allow(), A: authclienttest.Allow()}       // 200
gate = &authmw.Gate{V: authclienttest.Deny(), A: authclienttest.Deny()}          // 403
gate = &authmw.Gate{V: authclienttest.Unavailable(), A: authclienttest.Unavailable()} // 503
```

**Test the third one.** Everyone tests allow and deny; almost nobody tests what their handler does
when the auth service is unreachable — the one path where a mistake means an outage silently unlocks
the write surface.

`Fake` also records what was asked, so you can assert the *action* actually reached the authorizer
(if it stopped being sent, every authenticated caller would be authorized for everything, and every
status-code assertion would still pass):

```go
f := authclienttest.Allow()
// … drive your handler …
for _, c := range f.Calls() {
    if c.Method == "Authorize" && c.Action != "economy.transfer" { t.Error(...) }
}
```

To exercise the **real** client — its retries, decoding and error mapping — use the fake service:

```go
srv := authclienttest.NewServer()
defer srv.Close()
client := srv.NewClient() // = auth.New(srv.URL(), auth.WithValidationCache(0))
srv.SetStatus(503)   // now assert your handler answers 503, not 200
```

Use `srv.NewClient()` (validation cache off) whenever a test changes the fake's answer mid-test
(`SetValid`, `SetStatus`, `SetActor`): a client built with plain `auth.New(srv.URL())` has the
default cache on, and keeps serving the earlier answer for up to its TTL.

For code that calls `TokenFor`, script the token endpoint:

```go
te := authclienttest.NewTokenEndpoint()
defer te.Close()
te.Script(authclienttest.TokenError(400, "invalid_target", "consent_required"))
c := auth.New(te.URL(), auth.WithClientCredentials("app", "secret"))
// … TokenFor now returns *auth.ConsentRequired; te.Requests() shows what was sent
```

## Observability

```go
client := auth.New("", auth.WithObserver(func(i auth.RequestInfo) {
    slog.Info("auth", "endpoint", i.Endpoint, "status", i.Status,
        "ms", i.Duration.Milliseconds(), "attempt", i.Attempt)
}))
```

One event per **attempt**, so retries are visible rather than hidden inside one slow call. The
endpoint has its query string stripped, so it works as a metric label. No headers and no bodies are
carried — a path and a status cannot leak a credential.

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

## Checks

There is no automatic CI on this repository yet, by choice. Run the checks locally:

```bash
make check    # gofmt + go vet + go test + the stdlib-only assertion
make drift    # compare this SDK against the LIVE OpenAPI spec
```

The contract tests — what each proves, and how to run the integration tests against a local auth
service — are catalogued in [TESTS.md](TESTS.md).

A manual-dispatch-only workflow is staged at `.ci-pending/`; see the README there.

### `make drift`

The spec is the source of truth and it moves. `make drift` fetches
`https://auth.service.ab0t.com/openapi.json` and reports two things:

- **MISSING** — an operation in the spec with no SDK method: a capability you cannot reach.
- **PHANTOM** — an SDK request path the spec does not define: a call that would 404.

PHANTOM is the more dangerous direction. A missing method is a gap someone notices;
a phantom one looks like a working method until it is called.

Current status: **283/283 operations reachable**, plus the four documented
[known gaps](#known-gaps), which the tool lists separately and tells you to remove
the warnings from if the server ever ships them.

`make drift-strict` exits non-zero on any disagreement, if you want it as a gate.

## Documentation and skills

| | |
|---|---|
| [`docs/USAGE.md`](docs/USAGE.md) | The cookbook — task-shaped recipes, install to troubleshooting |
| [`docs/OBO_TOKEN_EXCHANGE.md`](docs/OBO_TOKEN_EXCHANGE.md) | Tokens for other mesh services — `TokenFor` (service or on-behalf-of a person), the bridge for today's services, setup, wire errors |
| [`docs/CLI.md`](docs/CLI.md) | Complete command and flag reference |
| [`skills/auth-sdk-go-concepts`](skills/auth-sdk-go-concepts/SKILL.md) | The mental model: two authz systems, typed ids, tenancy, nested orgs |
| [`skills/auth-sdk-go-cli`](skills/auth-sdk-go-cli/SKILL.md) | Operating the CLI |
| [`skills/auth-sdk-go-integration`](skills/auth-sdk-go-integration/SKILL.md) | Wiring the Go library into a service |

The `skills/` directory is agent-readable: point your coding agent at it and it can
use this SDK without you explaining the model first.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md) — report
privately, never in a public issue.

## License

MIT — see [LICENSE](LICENSE).

## Upgrading

Breaking upgrades ship a migration kit under `migrations/vFROM-to-vTO/`: run its `migrate-check.sh`
against your repo to find every call site to change, and read its `MIGRATION.md`. For v0.10.0 see
`migrations/v0.9.2-to-v0.10.0/`. For the default-on validation cache (v0.12.0) see
`migrations/v0.11.2-to-v0.12.0/` — no source changes are required, but its checker lists the
validation call sites to review for revocation-latency sensitivity. For v0.12.1 (authmw: invalid
JWT is 401 not 503, plus opt-in settings) see `migrations/v0.12.0-to-v0.12.1/` — no source changes
required. The full index is [`migrations/README.md`](migrations/README.md).
