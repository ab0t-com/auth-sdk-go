# Migration: auth-sdk-go v0.11.2 → v0.12.0

**Kind: BEHAVIOURAL (LMKAP RFC-0001 §4).** No public signature changed and your code compiles
unchanged. One **default** changed — validation answers are now cached in-process unless you say
otherwise — and new API was added (`VerifyAccessTokenLocal`, `WithFreshValidation`). A cache TTL is
a security property: it is how long a revocation can take to reach your process. This kit helps you
decide, per client and per call site, whether that is acceptable.

```bash
# from your service's repo root (KIT = this directory, in a checkout or your module cache):
$KIT/migrate-check.sh .            # lists what to review; exit 1 until every site is resolved
$KIT/migrate-check.sh . --advisory # same report, always exit 0
```

The checker is **read-only**. Its findings are BEHAVIOURAL decisions, so — per the protocol — they
are flagged for a human (or an agent with your instructions) and are **never auto-applied**.

---

## TL;DR

| # | Rule | Before (v0.11.2) | After (v0.12.0) | Your action |
|---|---|---|---|---|
| 1 | Default validation cache | no option → every validation is an HTTP call | no option → answers cached in-process (table below) | Keep the defaults, or `WithValidationCache(0)` |
| 2 | API key validation (`ValidateAPIKey`, `ValidateToken(ab0t_sk_…)`) | always asks the service | "valid" cached **60 s**, "not valid" **10 s** | Revoked key may work ≤ 60 s in your process |
| 3 | JWT validation (`ValidateToken`, `ValidateTokenWith`) | always asks the service | "valid" **15 s** (never past the token's `exp`), "not valid" **5 s** | Logged-out session may work ≤ 15 s |
| 4 | Permission decision (`Authorize` unscoped and resource-scoped; any call with `RequiredPermissions`) | always asks the service | "allowed" **15 s**, "denied" **5 s** | Removed permission may work ≤ 15 s |
| 5 | Explicit `WithValidationCache(ttl)` / `WithValidationCacheOptions` | one TTL for everything | **unchanged** | none |
| 6 | Per-call bypass | — | `WithFreshValidation(ctx)` | Use on sensitive calls |
| 7 | Local JWT verification | — | `VerifyAccessTokenLocal(ctx, tok, opts)` (new, opt-in) | Optional; cannot see logout |
| 8 | `authclienttest.Server` + real client | flipping the fake was seen at once | a plain `auth.New(srv.URL())` caches | Use `srv.NewClient()` in such tests |
| 9 | Conditional opt-in (`if ttl > 0 { WithValidationCache(ttl) }`) | configured 0 = no cache | configured 0 = **default cache** | Pass the option unconditionally |

What is **not** changed: errors (network, 429, 5xx) are never cached; an expired entry is never
served when the auth service cannot be reached (the cache fails closed); `Authorize` still fails
closed; the cache is bounded and does one request per key under concurrency.

---

## 1. The default cache (rules 1–4)

**Before:**

```go
c := authclient.New(authURL, authclient.WithAPIKey(key))
actor, err := c.ValidateToken(ctx, tok)    // HTTP call, every time
```

**After:** the same code; the first call per credential (and per question) reaches the service, and
repeats inside the TTL are answered from memory. The TTL follows the **question**, not the method
name:

| Question | "yes" cached | "no" cached |
|---|---|---|
| API-key identity | 60 s | 10 s |
| JWT identity | 15 s, never past the token's `exp` | 5 s |
| Permission decision | 15 s | 5 s |

*Why:* almost every consumer sits on a hot path (a gateway, an ingest door, request middleware) and
paid one auth round trip per request. These short TTLs remove almost all of them while bounding how
long a revocation can linger.

**Opt out (whole client) — exactly the v0.11.2 behaviour:**

```go
c := authclient.New(authURL, authclient.WithAPIKey(key), authclient.WithValidationCache(0))
```

**Choose your own single TTL** (as before — explicit configuration is unchanged by this release):

```go
c := authclient.New(authURL, authclient.WithValidationCache(5*time.Second))
```

Under an explicit configuration, the resource-scoped PDP call inside `Authorize` is not cached (only
its subject-resolution step is), exactly as in v0.11.2.

## 2. Sensitive calls — `WithFreshValidation` (rule 6)

**Before:** nothing to do — every call asked the service.

**After:** for a decision where even 15 s is too long (admin actions, money movement, ownership
changes), mark that one call fresh. It always asks the service, and its answer refreshes the shared
entry for everyone else:

```go
ok, err := c.Authorize(authclient.WithFreshValidation(ctx), tok, "billing.refund", res)
```

When your process itself revokes something (it deleted a key, handled a revocation webhook, logged a
user out), drop what it knows immediately:

```go
c.InvalidateValidation(credential)
```

## 3. Local verification — `VerifyAccessTokenLocal` (rule 7, new and optional)

```go
claims, err := c.VerifyAccessTokenLocal(ctx, tok, authclient.LocalVerifyOptions{Audience: "my-service"})
switch {
case errors.Is(err, authclient.ErrInvalidAccessToken): // 401 — the token failed a check
case err != nil:                                         // 503 — the key set could not be fetched
default:                                                 // claims.Subject, claims.OrgID, claims.ExpiresAt …
}
```

No network call on the hot path: RS256 signature against the cached JWKS (10 min; an unknown `kid`
refetches at most once a minute), `iss`, `aud` when you expect one, `exp`/`nbf` with at most 60 s of
clock skew (default 30 s), and the token type (refresh tokens always rejected; delegation tokens
only with `AllowDelegation`).

**It cannot see logout.** The auth service's access tokens are session-backed: logout, a revoked
session, a deactivated user or a removed membership invalidate the token at the service at once.
A local check keeps accepting such a token until its `exp` (about 15 minutes). `ValidateToken` was
deliberately **not** changed to verify locally, for exactly this reason. Choose per route:

| | network per request | sees logout |
|---|---|---|
| `VerifyAccessTokenLocal` | none | no — until `exp` (~15 min) |
| `ValidateToken` (default cache) | ≤ 1 per 15 s per token | within 15 s |
| `ValidateToken` + `WithFreshValidation` | 1 | immediately |

## 4. Tests against `authclienttest.Server` (rule 8)

**Before:**

```go
srv := authclienttest.NewServer()
client := auth.New(srv.URL())
// … first call …
srv.SetValid(false)   // the next call saw it
```

**After:** the client caches, so the next call returns the cached earlier answer. Build the client
with the cache off:

```go
client := srv.NewClient()                       // = auth.New(srv.URL(), auth.WithValidationCache(0))
client := srv.NewClient(auth.WithMaxRetries(0)) // extra options are applied after
```

## 5. Config-driven "0 disables" knobs (rule 9)

**Before (common shape):**

```go
if cfg.ValidationCacheTTL > 0 {
    opts = append(opts, authclient.WithValidationCache(cfg.ValidationCacheTTL))
}
client := authclient.New(url, opts...)
```

With a configured `0` this passed no option, which meant "no cache". From v0.12.0, no option means
the **default** cache, so "0 disables" silently stops being true. **After:**

```go
opts = append(opts, authclient.WithValidationCache(cfg.ValidationCacheTTL)) // 0 = off, as documented
client := authclient.New(url, opts...)
```

---

## Marking sites reviewed (so you can gate CI on the checker)

A finding is resolved when any of these holds:

- the construction passes `WithValidationCache(...)` / `WithValidationCacheOptions(...)` — if every
  construction in the repo is explicit, call sites are informational only (the default never applies);
- the call passes `WithFreshValidation(...)`;
- the line, or the line above, carries `// authsdk:cache-reviewed`;
- the file carries `// authsdk:cache-reviewed-file`;
- a test builds its client with `srv.NewClient(...)`.

`*_test.go` files are only checked for rule 8; production rules 1–4 and 9 look at non-test files.

## Agent-applicable rules (for a coding agent following the protocol)

1. Run `migrate-check.sh .`. Log the count.
2. **R3 (tests)** — mechanical: replace `auth.New(srv.URL(), opts...)` with `srv.NewClient(opts...)`
   where `srv` is an `*authclienttest.Server`. Re-run the tests.
3. **R4 (conditional opt-in)** — mechanical when the service documents "0 disables": move the
   `WithValidationCache(cfg.X)` out of the `if`. If the service never documented that, STOP and ask.
4. **R1 / R2 (behavioural)** — do NOT decide alone. For each, ask the owner (or follow written
   instructions): keep the default (mark `// authsdk:cache-reviewed`), opt out
   (`WithValidationCache(0)`), or mark the call fresh (`WithFreshValidation(ctx)`). Never restore
   the old behaviour silently, never lower the bar to pass the checker.
5. Re-run the checker (expect exit 0), then `go build ./... && go vet ./... && go test ./...`.

## Rollback

All changes are behavioural defaults in the library; nothing in your code has to change to roll
back. Pin back to the previous release and redeploy:

```bash
go get github.com/ab0t-com/auth-sdk-go@v0.11.2 && go mod tidy
```

Or stay on v0.12.0 with the old behaviour: add `WithValidationCache(0)` to every client.
