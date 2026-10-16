# Tests

This SDK's guarantees are written down as tests. This file is the catalogue: which test proves which
promise, where it lives, and how to run it — and how to run the same middleware contract against
**your** service.

Every behavioural test here asserts on what the auth service actually received (request counts,
request bodies) or on the status your callers actually get — not on an internal counter. Tests that
guard a fix were shown to **fail** on the release before the fix.

## Running them

```bash
make check                                    # gofmt + vet + every unit test + the stdlib-only check
go test -race ./...                           # the same tests under the race detector
go test -run TestConformance -v ./authmw/     # one group

# integration: a REAL, LOCAL auth service (the tests refuse any non-local URL; they create users)
AUTH_SDK_IT_BASE_URL=http://localhost:8001 go test -tags integration -run TestIntegration -v .         # cache / revocation
AUTH_SDK_IT_BASE_URL=http://localhost:8001 go test -tags integration -run TestIntegrationAuthmw -v ./authmw/  # middleware
```

The integration tests are excluded from `make check` by the `integration` build tag. A failure to
build a fixture (register, log in, mint a key) is reported as `SKIP: VOID: …` — not a verdict on the
SDK. The `TestLive_*` smoke tests are separate: they run only with `AUTH_LIVE=1` and use `AUTH_BASE`;
point that at a local or staging service you own.

## Middleware — `authmw`

| Test | File | Proves |
|---|---|---|
| `TestRequire_StatusMatrix` | `authmw/authmw_test.go` | no credential 401 · allowed 200 · denied 403 · auth down 503 · API key allowed |
| `TestRequire_FailOpenIsOptIn` | `authmw/authmw_test.go` | an outage is 503 by default; only `FailOpen: true` turns it into an allow |
| `TestRequire_ForwardsActionAndResource` | `authmw/authmw_test.go` | the action and resource reach the authorizer (a gate that dropped them would allow everything) |
| `TestAuthenticate` | `authmw/authmw_test.go` | no credential → anonymous; valid → identity attached; `{valid:false}` → 401; down → 503 |
| `TestGate_AcceptsXAPIKey`, `TestGate_AuthorizationWinsOverXAPIKey` | `authmw/authmw_test.go` | `X-API-Key` is read; `Authorization` wins when both are sent |
| `TestAuthenticate_InvalidJWTAnswered401IsUnauthorizedNot503` | `authmw/invalid_credential_test.go` | the auth service answering a JWT with HTTP 401/403 → **401**, never 503 |
| `TestRequire_InvalidJWTAnswered401IsUnauthorized_ForbiddenStays403` | `authmw/invalid_credential_test.go` | `Require`: auth 401 → 401, auth 403 → 403 (unscoped and resource-scoped) |
| `TestFailOpen_NeverAdmitsAnInvalidJWT` | `authmw/invalid_credential_test.go` | `FailOpen` lets through "could not decide" only — never a credential the service rejected |
| `TestAuthenticate_AuthOutageIsStill503AndNeverCached` | `authmw/invalid_credential_test.go` | 429/500/502/503/unreachable → 503 on every request, each one a fresh auth call |
| `TestAuthenticate_BadJWTStormCostsOneAuthCall` | `authmw/invalid_credential_test.go` | 20 concurrent requests with one bad JWT → 1 auth call |
| `TestGate_IncludePermissionsGivesJWTCallersTheirPermissions` | `authmw/gate_options_test.go` | `IncludePermissions` fills JWT permissions; default unchanged; cached under its own key; API keys unaffected |
| `TestGate_IncludePermissionsWithoutARicherValidatorFailsClosed` | `authmw/gate_options_test.go` | a `V` that cannot return permissions → 503, never an identity with permissions missing |
| `TestRequireIdentity_StatusMatrix` | `authmw/gate_options_test.go` | `RequireIdentity`: 401 none/invalid · 503 down · `FailOpen` honoured · identity attached |
| `TestGate_JSONDenialWritesStaticJSONBodies` | `authmw/gate_options_test.go` | default text denials unchanged; `JSONDenial` writes `{"error":"…"}`, static, no input echoed |
| `TestBearer_SchemeIsCaseInsensitive` | `authmw/gate_options_test.go` | `bearer x` → `x`; headers without the scheme are returned whole, as before |
| `TestGate_APIKeyHeaderIsConfigurable` | `authmw/gate_options_test.go` | `APIKeyHeader` names the key header; `Authorization` still wins; default `X-API-Key` |
| `TestConformance_*` | `authmw/*_test.go` | the SDK's own gates pass `authmwtest.Run` — and the suite **reports** a gate with the 503-for-an-invalid-JWT defect, missing permissions, or text denials |

## Validation cache

| Test | File | Proves |
|---|---|---|
| `TestDefaultTTL_*`, `TestDefaultNegativeTTL_*` | `validationcache_defaults_test.go` | the default per-question TTLs (API key 60 s/10 s, JWT 15 s/5 s, permission decision 15 s/5 s) |
| `TestDefaultTokenPositiveCappedAtJWTExp` | `validationcache_defaults_test.go` | a "valid" never outlives the token's own `exp` |
| `TestDefaultNeverCachesErrors`, `TestValidationCacheNeverCachesErrors` | `validationcache*_test.go` | 429 / 5xx are never cached |
| `TestDefaultFailsClosedAfterExpiry`, `TestValidationCacheDoesNotServeStaleThroughAnOutage` | `validationcache*_test.go` | an expired entry is never served through an outage |
| `TestFreshValidation*`, `TestOptOut*`, `TestExplicitConfig*` | `validationcache_defaults_test.go` | per-call bypass, opt-out, explicit configuration |
| `TestValidationCacheKeysOnRequestShape`, `TestValidationCacheReturnsACopy`, `TestValidationCacheSingleFlight` | `validationcache_test.go` | no cross-request answers; callers cannot corrupt an entry; one call per key under load |
| `TestValidateToken_Definite401IsCachedForTheNegativeTTL` | `invalid_jwt_cache_test.go` | a 401 from validate-token is cached for the negative TTL and returned as the same error |
| `TestValidateToken_OnlyADefinite401IsCached`, `TestValidateAPIKey_401IsNotCached` | `invalid_jwt_cache_test.go` | 400/403/404/422/429/5xx — and a 401 from validate-api-key — stay uncached |
| `TestValidateToken_401NegativeFollowsTheCacheConfiguration` | `invalid_jwt_cache_test.go` | cache off / negatives opted out → not cached; explicit config → its negative TTL |
| `TestValidateToken_Fresh401ReplacesACachedValid` | `invalid_jwt_cache_test.go` | a fresh 401 replaces a cached "valid" |

## Audience and local verification

| Test | File | Proves |
|---|---|---|
| `TestWithExpectedJWTAudience_AssertsJWTsOnlyNeverAPIKeys` | `jwt_audience_test.go` | the JWT audience is sent for JWTs only; `WithExpectedAudience` alone is unchanged |
| `TestWithExpectedJWTAudience_IsTheLocalVerifyDefault` | `jwt_audience_test.go` | `VerifyAccessTokenLocal` defaults to the JWT audience |
| `TestLocalVerify*` | `localverify_test.go` | RS256 only, `kid` refetch limit, `iss`/`aud`/`exp`/`nbf`, refresh tokens rejected, failure vs "could not evaluate" |

## Wire contract

| Test | File | Proves |
|---|---|---|
| `TestContractGate`, `TestContractGate_MechanismDetectsDrift` | `contract_gate_test.go` | request/response structs match the pinned API contract (`scripts/api_contract.json`), and the gate can fail |
| `TestCredentialHeader*`, `TestTransportRoutesCredentialByShape` | `credential_transport_test.go` | API keys travel as `X-API-Key`, JWTs as `Authorization: Bearer` |
| `TestVersionMatchesChangelog` | `version_test.go` | the version has a changelog section |

## Integration (`-tags integration`, local auth service)

| Test | File | Proves |
|---|---|---|
| `TestIntegrationRevokedAPIKey` / `RevokedPermission` / `Logout` | `integration_validation_cache_test.go` | measured revocation latency of the default cache (≤ 60 s / 15 s / 15 s) and the local-vs-server difference |
| `TestIntegrationAuthmw_InvalidJWTIs401` | `authmw/integration_invalid_jwt_test.go` | a garbage, well-formed JWT through a real gate → 401 (and logs what the service answered) |
| `TestIntegrationAuthmw_BadJWTStormCostsAtMostOneCall` | `authmw/integration_invalid_jwt_test.go` | 10 identical bad JWTs → ≤ 1 validate call |
| `TestIntegrationAuthmw_UnreachableAuthIs503AndNotCached` | `authmw/integration_invalid_jwt_test.go` | nothing listening → 503 on every request, nothing cached |
| `TestIntegrationAuthmw_RequireIdentityWithARealToken` | `authmw/integration_gate_options_test.go` | `RequireIdentity` + `IncludePermissions` + `JSONDenial` with a real user token: 200 + identity + permissions, ≤ 1 call for 5 requests, JSON 401 for a bad token |

An auth service that answers an invalid JWT with `200 {"valid":false}` gives 401 on every SDK
version; the HTTP-401 shape that older `authmw` turned into 503 is covered by the unit tests above.

## Reusing the middleware contract in your service — `authmw/authmwtest`

Your gate is a few lines of configuration, and each line can break the contract. Run the contract
against your real wiring from your own test suite:

```go
import (
    "net/http"
    "testing"

    auth "github.com/ab0t-com/auth-sdk-go"
    "github.com/ab0t-com/auth-sdk-go/authmw"
    "github.com/ab0t-com/auth-sdk-go/authmw/authmwtest"
)

func TestAuthContract(t *testing.T) {
    authmwtest.Run(t, authmwtest.Contract{
        Wrap: func(c *auth.Client, inner http.Handler) http.Handler {
            gate := &authmw.Gate{V: c, A: c, IncludePermissions: true, WriteDenial: authmw.JSONDenial}
            return gate.RequireIdentity(inner) // exactly as production builds it
        },
        WantPermissions: true, // if you set IncludePermissions
        JSONDenials:     true, // if you set WriteDenial = authmw.JSONDenial
        // AllowAnonymous: true, // if the stack is Authenticate alone (no credential continues)
        // Method, Path: the request to send (default GET /)
    })
}
```

| Case | Expected |
|---|---|
| no credential | 401 (or the handler runs anonymously with `AllowAnonymous`) |
| invalid JWT — the fake auth service answers HTTP 401 | 401 |
| invalid API key — the fake answers `200 {"valid":false}` | 401 |
| auth answers 503 / is unreachable | 503, and a repeat makes a new auth call (not cached) |
| valid JWT / valid API key | your handler runs with `authmw.Identity` set (and the JWT's permissions with `WantPermissions`) |
| the same valid credential, or the same invalid JWT, N times | no auth calls after the first request |
| any denial, with `JSONDenials` | `Content-Type: application/json`, body `{"error":"…"}` |

Each case gets a fresh fake auth service and a fresh client with the default validation cache. The
contract assumes an identity gate (`Authenticate` or `RequireIdentity`) in the stack — that is what
attaches the identity and makes an invalid credential a 401; a `Require` may sit behind it. The
package depends only on the standard library and this SDK.
