# Client notice — auth-sdk-go v0.12.1 (authmw: invalid JWT is 401, not 503)

*Copy/paste to any team that imports `github.com/ab0t-com/auth-sdk-go`.*

---

**Subject: auth-sdk-go v0.12.1 — authmw answers 401 (not 503) for a rejected JWT. Your code compiles unchanged; nothing to do unless you read JWT permissions.**

Hi — v0.12.1 of the Go auth client fixes two bugs in the `authmw` middleware and adds a few opt-in
settings. Every default is unchanged.

**The visible fix.** When the auth service rejected a caller's JWT with HTTP 401, `authmw` answered
**503 "auth unavailable"** — your clients retried instead of signing in again, and dashboards showed
an outage that was not one. It now answers **401** (`Require`: 401, or 403 for a 403). Network
failures, timeouts, 429 and 5xx are still **503**. An auth service that answers a bad JWT with
`200 {"valid":false}` already got 401 and still does.

| When this happens | v0.12.0 answered | v0.12.1 answers |
|---|---|---|
| The auth service rejects the JWT with HTTP 401 | 503 | **401** |
| … and the gate has `FailOpen` on | `Require` **ran your handler** | **401** |
| The auth service is down / slow / 5xx | 503 | 503 |
| The same bad JWT, many requests | one auth call each | at most one per 5 s |

**If you read `authmw.Identity(ctx).Permissions`:** JWT callers never had permissions there — only
API keys did — so a permission check on them denied every JWT caller. Turn on
`Gate{IncludePermissions: true}` (your `V` must be the `*auth.Client`).

**New, all optional:**

```go
client := authclient.New("", authclient.WithExpectedJWTAudience("my-service")) // audience on JWTs only — mesh service keys have none
gate := &authmw.Gate{V: client, A: client,
    IncludePermissions: true,              // JWT callers get their permissions
    WriteDenial:        authmw.JSONDenial, // {"error":"invalid token"} instead of text
}
http.ListenAndServe(":8080", gate.RequireIdentity(mux)) // every route needs a caller: 401 / 503
```

Plus `Gate.APIKeyHeader` (default `X-API-Key`), a case-insensitive `Bearer` scheme, and
`authmw/authmwtest` — call `authmwtest.Run(t, …)` from your tests to check your gate against the
contract above.

## What to do

```bash
go get github.com/ab0t-com/auth-sdk-go@v0.12.1 && go mod tidy
$KIT/migrations/v0.12.0-to-v0.12.1/migrate-check.sh .
```

The checker is read-only. It lists gates with `FailOpen` on, places that read JWT permissions
without `IncludePermissions`, and tests that expect 503 when the auth double answers 401 — see
`MIGRATION.md` in the same directory. Then `go build ./... && go test ./...`.

**Rollback:** pin back to `@v0.12.0` and redeploy (drop any of the new settings you started using).
