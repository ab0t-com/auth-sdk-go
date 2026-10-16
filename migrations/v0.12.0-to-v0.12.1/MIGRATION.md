# Migration: auth-sdk-go v0.12.0 → v0.12.1

**Kind: BUG FIX + ADDITIVE (LMKAP RFC-0001 §4).** No public signature changed, nothing was removed,
every default is unchanged, and your code compiles unchanged. Two bug fixes change what `authmw`
answers in specific cases (one is visible to your callers as a status code), and new opt-in settings
were added. This kit tells you where to look.

```bash
# from your service's repo root (KIT = this directory, in a checkout or your module cache):
$KIT/migrate-check.sh .            # lists what to look at; exit 1 until every site is resolved
$KIT/migrate-check.sh . --advisory # same report, always exit 0
```

The checker is **read-only** and never edits your code.

---

## TL;DR

| # | What | Before (v0.12.0) | After (v0.12.1) | Your action |
|---|---|---|---|---|
| 1 | `authmw` when the auth service answers a JWT with HTTP **401/403** | `Authenticate` / `Require`: **503** "auth unavailable" | `Authenticate` / `RequireIdentity`: **401** "invalid token"; `Require`: **401**, or **403** for a 403 | Check retry logic / alerts keyed on authmw 503s |
| 2 | `authmw` + `FailOpen`, same case | `Authenticate` passed on anonymously; **`Require` ran the handler** | refused (401/403) — `FailOpen` covers only "could not decide" | Confirm nothing relied on it (checker R1) |
| 3 | Network / timeout / 429 / 5xx | 503 | **503, unchanged** | none |
| 4 | Same invalid JWT, N requests, auth answers 401 | N auth calls (errors never cached) | ≤ 1 call per 5 s (cached as a "not valid"); same error returned | none |
| 5 | JWT-only audience | — | `WithExpectedJWTAudience(aud)` | Optional — see §3 |
| 6 | Every route needs a caller | — | `gate.RequireIdentity(next)` | Optional |
| 7 | JWT caller's permissions on `authmw.Identity` | never populated for JWTs | `Gate{IncludePermissions: true}` | Optional — **needed if you read them** (checker R2) |
| 8 | JSON error bodies | plain text only | `Gate{WriteDenial: authmw.JSONDenial}` → `{"error":"…"}` | Optional |
| 9 | API key header | `X-API-Key` | `X-API-Key` (default) or `Gate{APIKeyHeader: "…"}` | Optional |
| 10 | `Authorization: bearer x` (lower case) | the whole header was the credential → rejected | `x` (RFC 7235: the scheme is case-insensitive) | none |
| 11 | Check your gate from your tests | — | package `authmw/authmwtest` | Optional, recommended |

An auth service that answers an invalid JWT with `200 {"valid":false}` already got `401` from
`authmw` in v0.12.0; rows 1, 2 and 4 change nothing for it.

---

## 1. Invalid credential → 401, outage → 503 (rows 1–4)

`authmw` now classifies a validation error by **cause**. The auth service answering 401/403 is a
definite answer about the credential, so the caller is told to re-authenticate:

| | no credential | invalid credential | denied | auth unreachable |
|---|---|---|---|---|
| `Authenticate` | continues anonymously | 401 | — | 503 |
| `RequireIdentity` | 401 | 401 | — | 503 |
| `Require` | 401 | 401 when the auth service answers 401 | 403 | 503 |

**What your callers will notice:** `503` → `401` for requests whose JWT the auth service rejects
with HTTP 401. A client that retried on 503 now re-authenticates instead. If you alert on authmw
503s, those alerts get quieter — that is correct.

**`FailOpen`** (which you should not have on) now lets through only "could not decide". In v0.12.0,
when the auth service answered 401, `Require` with `FailOpen` ran your handler for that invalid
credential. If anything depended on that, it depended on a hole.

**Tests** that script the auth double to answer 401 and expect 503 from the gate need their
expectation changed to 401 (checker R3). Tests that expect 503 for an outage are unchanged.

## 2. Caching of a definite 401 (row 4)

A `401` from `POST /auth/validate-token` is remembered for the negative TTL — 5 s by default, or
your `ValidationCacheOptions.NegativeTTL` — exactly like a `{valid:false}`. `ValidateToken`,
`ValidateTokenWith` and `Authorize` return the **same** `*APIError` (matching `IsUnauthorized`)
whether it came from the service or the cache. `WithFreshValidation(ctx)`, `InvalidateValidation`
and `WithValidationCache(0)` work as before. Nothing else that arrives as an error is cached.

## 3. JWT-only audience — `WithExpectedJWTAudience` (row 5)

`WithExpectedAudience` applies to **every** credential, API keys included. Mesh service keys carry no
audience, so a client that also validates them rejects them. If your routes accept both:

**Before:**

```go
client := auth.New("", auth.WithExpectedAudience("my-service")) // rejects audience-less service keys
```

**After:**

```go
client := auth.New("", auth.WithExpectedJWTAudience("my-service")) // JWTs must name my-service; keys are not asked
```

Use `WithExpectedAudience` when every credential, keys included, must name your service. With both
set, a JWT is checked against `WithExpectedJWTAudience` and a key against `WithExpectedAudience`. A
per-call `TokenValidationRequest.ExpectedAudience` or `LocalVerifyOptions.Audience` still wins.
`VerifyAccessTokenLocal` defaults to the JWT audience.

## 4. The new gate settings (rows 6–9)

```go
gate := &authmw.Gate{
    V: client, A: client,
    IncludePermissions: true,              // JWT callers: Identity(ctx).Permissions is filled in
    WriteDenial:        authmw.JSONDenial, // {"error":"invalid token"}, Content-Type application/json
    APIKeyHeader:       "X-API-Key",       // the default; name another header if yours differs
}
http.ListenAndServe(":8080", gate.RequireIdentity(mux)) // 401 no/invalid credential · 503 auth down
```

- **`IncludePermissions`** needs `V` to be an `*auth.Client` (anything with `ValidateTokenWith`).
  With a `V` that cannot ask for permissions — `authclienttest.Fake`, for one — a JWT request is
  answered 503 instead of attaching an identity whose permissions are silently missing. Test it with
  `authclienttest.Server` + `srv.NewClient()`, or with `authmwtest`.
- **If you read `authmw.Identity(ctx).Permissions` today without `IncludePermissions`,** JWT callers
  have none, so a permission check there denies every JWT caller (checker R2). Turn it on.
- Messages written by `WriteDenial` are the gate's static strings; no request input is echoed.

## 5. Check your gate from your own tests — `authmwtest` (row 11)

```go
func TestAuthContract(t *testing.T) {
    authmwtest.Run(t, authmwtest.Contract{
        Wrap: func(c *auth.Client, inner http.Handler) http.Handler {
            return yourGate(c).RequireIdentity(inner) // your production wiring
        },
        WantPermissions: true, // if you set IncludePermissions
        JSONDenials:     true, // if you set WriteDenial = authmw.JSONDenial
    })
}
```

It runs your stack against a fake auth service and fails on: a non-401 for no / invalid credential,
a non-503 for an outage, a cached outage, a handler run without an identity, missing permissions,
repeat requests that are not cached, and (with `JSONDenials`) a non-JSON denial.

---

## Marking sites reviewed (so you can gate CI on the checker)

- the line, or the line above, carries `// authsdk:v0.12.1-reviewed`;
- the file carries `// authsdk:v0.12.1-reviewed-file`;
- R2 is resolved when any non-test file in the repo sets `IncludePermissions`.

## Agent-applicable rules

1. Run `migrate-check.sh .`. Log the count.
2. **R3 (tests)** — mechanical: where the auth double answers 401 and the assertion is 503, change the
   expected status to 401 (403 for a scripted 403 under `Require`). Re-run the tests.
3. **R2 (permissions)** — mechanical when the gate's `V` is an `*auth.Client`: set
   `IncludePermissions: true` on the gate. If `V` is something else, STOP and ask.
4. **R1 (FailOpen)** — do NOT decide alone: report it to the owner, mark it reviewed only on their
   word. Never turn `FailOpen` on to make a check pass.
5. Re-run the checker (expect exit 0), then `go build ./... && go vet ./... && go test ./...`.

## Rollback

```bash
go get github.com/ab0t-com/auth-sdk-go@v0.12.0 && go mod tidy
```

Code that uses the new settings (`WithExpectedJWTAudience`, `RequireIdentity`, `IncludePermissions`,
`WriteDenial`, `JSONDenial`, `APIKeyHeader`, `authmwtest`) must drop them to compile on v0.12.0.
