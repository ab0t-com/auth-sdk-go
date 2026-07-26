---
name: auth-sdk-go-integration
description: Wire the ab0t auth Go SDK into a service — HTTP middleware that gates routes, the Validator/Authorizer interfaces, test doubles for allow/deny/unavailable, observability hooks, retries and timeouts, and fail-closed handling. Use when adding authentication or authorization to a Go service, gating routes, deciding what to do when the auth service is down, writing tests for authorization without a live service, adding logging/tracing/metrics to auth calls, or choosing between the CLI and the library.
---

# Integrating the Go SDK

```bash
go get github.com/ab0t-com/auth-sdk-go
```

Standard library only — no transitive dependencies, enforced in CI.

## Depend on the interfaces, never on *Client

```go
type Validator  interface { ValidateToken(ctx, token string) (*Actor, error) }
type Authorizer interface { Authorize(ctx, token, action string, r Resource) (bool, error) }
```

`*auth.Client` satisfies both. Depending on the interfaces is what makes your
handlers testable without a live service — it is the single most important
decision in this file.

## Gate routes with `authmw`

```go
import (
    auth "github.com/ab0t-com/auth-sdk-go"
    "github.com/ab0t-com/auth-sdk-go/authmw"
)

client := auth.New("", auth.WithAPIKey(os.Getenv("AUTH_SERVICE_KEY")),
                       auth.WithExpectedAudience("my-service"))
gate := &authmw.Gate{V: client, A: client}

mux.Handle("POST /admin", gate.Require("admin.write", "service", adminHandler))
http.ListenAndServe(":8080", gate.Authenticate(mux))
```

`401` no credential · `403` denied · **`503` auth service unreachable** · else your handler.

**That 503 is the whole point.** "I could not decide" is not "yes". `FailOpen`
exists but must be set deliberately — a gate that allows on error turns a blip into
an open door, quietly, because requests succeed and nothing pages anyone.

**Set an expected audience.** Without it, a token minted for a *different* service
validates against yours.

## Test the three cases — especially the third

```go
import "github.com/ab0t-com/auth-sdk-go/authclienttest"

gate := &authmw.Gate{V: authclienttest.Allow(),       A: authclienttest.Allow()}       // 200
gate  = &authmw.Gate{V: authclienttest.Deny(),        A: authclienttest.Deny()}        // 403
gate  = &authmw.Gate{V: authclienttest.Unavailable(), A: authclienttest.Unavailable()} // 503
```

Everyone tests allow and deny. **Almost nobody tests unavailable** — the one path
where a mistake means an outage silently unlocks your write surface.

`Fake` also records calls, so you can assert the **action** actually reached the
authorizer. If it stopped being sent, every authenticated caller would be
authorized for everything *and every status-code assertion would still pass*.

```go
f := authclienttest.Allow()
// … drive your handler …
for _, c := range f.Calls() {
    if c.Method == "Authorize" && c.Action != "economy.transfer" { t.Error(…) }
}
```

To exercise the **real** client — retries, decoding, error mapping:

```go
srv := authclienttest.NewServer(); defer srv.Close()
client := auth.New(srv.URL())
srv.SetStatus(503)   // now assert your handler answers 503, not 200
```

## Per-object authorization

```go
store := client.Store(storeID, callerToken)

ok,   err := store.Can(ctx, "user", "alice", "view", "doc", "123")
err        = store.Relate(ctx, "user", "alice", "owner", "doc", "123")
err        = store.RelateUntil(ctx, "user:contractor", "viewer", "doc:9", time.Now().Add(24*time.Hour))
docs, err := store.WhatCan(ctx, auth.Subject("user","alice"), "view", "doc")
users,err := store.WhoCan(ctx, auth.Object("doc","123"), "view")
res,  err := store.Why(ctx, subject, "view", object)   // reason + path
```

Every boolean **fails closed**: an error is `false`, an **empty batch is `false`**
("nothing was asked" is not "everything is permitted"), and a bulk response of the
wrong length is an error rather than a guess.

## Observability

```go
client := auth.New("", auth.WithObserver(func(i auth.RequestInfo) {
    slog.Info("auth", "endpoint", i.Endpoint, "status", i.Status,
        "ms", i.Duration.Milliseconds(), "attempt", i.Attempt, "err", i.Err)
}))
```

One event per **attempt**, so retries are visible rather than hidden inside one slow
call. Endpoint has its query string stripped, so it works as a metric label.
**No headers and no bodies are carried** — a path and a status cannot leak a
credential.

`Status: 0` with a non-nil `Err` means *never got a response*, which needs different
alerting from *got a 500*.

## Transport

- 15s timeout — `WithTimeout`
- 2 retries with backoff, honouring `Retry-After` — `WithMaxRetries`, `WithBackoff`
- JWKS cached 10 min, bounded at 512 key sets, serves stale-but-good on refresh failure

> **⚠️ Retries apply to non-idempotent POSTs.** A create whose write committed before
> the response was lost will be retried, and on an endpoint with no dedup key that
> can duplicate a side effect. Use `WithMaxRetries(0)` where once-only matters.

## CLI or library?

Library for the request path. CLI for operators, CI gates, access reviews and
debugging — and as the fastest way to check what the library *would* do.

## See also

- `auth-sdk-go-concepts` · `auth-sdk-go-cli` · `docs/USAGE.md`
