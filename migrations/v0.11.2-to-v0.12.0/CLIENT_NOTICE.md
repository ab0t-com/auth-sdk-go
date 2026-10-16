# Client notice — auth-sdk-go v0.12.0 (validation cache on by default)

*Copy/paste to any team that imports `github.com/ab0t-com/auth-sdk-go`.*

---

**Subject: auth-sdk-go v0.12.0 — validation answers are now cached by default. Your code compiles unchanged; please read the revocation latency below.**

Hi — v0.12.0 of the Go auth client turns its in-process validation cache **on by default**. Until
now every `ValidateToken`, `ValidateAPIKey` and `Authorize` call was a round trip to the auth
service; on a hot path that was one extra network call per request. From v0.12.0, a client you
build without a cache option remembers answers for a short time.

**What that means for revocation — the one thing to check:**

| When this happens at the auth service | Your process may keep accepting it for up to |
|---|---|
| An API key is deleted or revoked | **60 seconds** (`ValidateAPIKey`, or `ValidateToken` with an `ab0t_sk_` key) |
| A user logs out / a session is revoked / a membership is removed | **15 seconds** (`ValidateToken`, `ValidateTokenWith`; never past the token's own expiry) |
| A permission is removed | **15 seconds** (`Authorize`, or any validation with `RequiredPermissions`) |
| A permission is granted (a "no" becoming "yes") | 5 seconds (10 seconds for an API key) |

Errors are never cached, and when the auth service is unreachable an expired answer is never reused —
the cache fails closed.

**If that latency is fine for you, there is nothing to do.** If it is not:

```go
authclient.New(url, authclient.WithValidationCache(0))          // no cache at all — exactly the old behaviour
client.Authorize(authclient.WithFreshValidation(ctx), tok, action, res) // always ask, for this one call
client.InvalidateValidation(credential)                         // you just revoked it yourself
```

If you already configure the cache yourself (`WithValidationCache(ttl)`), **nothing changes for you.**

**Two things that can bite:**
1. **A config knob where `0` meant "no cache".** Code like `if ttl > 0 { opts = append(opts,
   WithValidationCache(ttl)) }` now gets the default cache when the TTL is 0. Pass the option
   unconditionally — `WithValidationCache(0)` is the off switch.
2. **Tests using `authclienttest.Server`** that change the fake's answer mid-test (`SetValid(false)`,
   `SetStatus(503)`) will see the cached earlier answer. Build the client with `srv.NewClient()`.

**New, optional:** `VerifyAccessTokenLocal(ctx, tok, opts)` checks an access token with **no network
call** (RS256 signature against the cached key set, issuer, audience, expiry). It **cannot see
logout** — a logged-out token keeps passing it until it expires (about 15 minutes) — so
`ValidateToken` still asks the service. Use local verification only where that is acceptable.

## What to do

```bash
go get github.com/ab0t-com/auth-sdk-go@v0.12.0 && go mod tidy
```

Then run the migration kit that ships in the module — it lists every client and validation call
site to review, and the two patterns above:

```bash
$KIT/migrations/v0.11.2-to-v0.12.0/migrate-check.sh .
```

It is read-only and exits non-zero until each site is resolved (keep the default and mark it, opt
out, or mark the call fresh) — see `MIGRATION.md` in the same directory. Then
`go build ./... && go test ./...`.

**Rollback:** pin back to `@v0.11.2` and redeploy — or stay on v0.12.0 and add
`WithValidationCache(0)` to every client.
