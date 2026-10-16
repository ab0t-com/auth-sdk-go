# Changelog

All notable changes to the ab0t Auth Service Go SDK.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.12.1] — 2026-10-16 — `authmw`: an invalid JWT is 401, not 503 · opt-in gate settings · JWT-only audience

> **Bug fixes + additive API. No source change required, and every default is unchanged.** One fix
> is visible on the wire (below). Migration kit: `migrations/v0.12.0-to-v0.12.1/` (its read-only
> `migrate-check.sh` lists `FailOpen` gates, JWT permissions read without `IncludePermissions`, and
> tests that expect 503 for a 401; `--advisory` never fails a build).

### Fixed — `authmw` answered 503 "auth unavailable" for an invalid JWT (VISIBLE STATUS CHANGE)

**Who this affects:** services that gate routes with `authmw.Gate` (`Authenticate`, `Require`)
against an auth service that answers an invalid, expired or logged-out JWT at
`POST /auth/validate-token` with **HTTP 401**. `authmw` treated every validation error as an outage
and answered **503 "auth unavailable"** — so callers were told to retry instead of re-authenticating,
and monitoring saw a false outage. With `FailOpen` set it was worse: `Authenticate` passed the request
on anonymously and **`Require` ran the handler** for that invalid credential.

- `Authenticate` (and the new `RequireIdentity`): a definite **401 or 403** from the auth service is
  now **401 "invalid token"**. `Require`: a **401** is now **401 "invalid token"**, a **403** is
  **403 "forbidden"**. Anything else — network failure, timeout, 429, 5xx — is **503, unchanged**.
- `FailOpen` now lets through only "could not decide" (the 503 cases), never an invalid or denied
  credential.
- An auth service that answers an invalid JWT with `200 {"valid":false}` already produced 401 and
  still does; nothing changes for it.
- **What your clients will notice:** `503` → `401` for those requests. A client that retried on 503
  now gets the correct "re-authenticate" signal.

### Fixed — a storm of one invalid JWT cost one auth call per request

**Who this affects:** every client with the default validation cache. A definite **401** from
`POST /auth/validate-token` was an error, and errors are never cached, so N requests with the same
bad token made N auth calls. It is now remembered for the negative TTL (5 s by default, the same as
`{valid:false}`; under an explicit `WithValidationCacheOptions`, its `NegativeTTL`).
`ValidateToken` / `ValidateTokenWith` / `Authorize` return **exactly the same error** as before —
an `*APIError` matching `IsUnauthorized` — whether it came from the service or the cache.
`WithFreshValidation`, `InvalidateValidation` and `WithValidationCache(0)` behave as before. Every
other error (403, 429, 5xx, network) is still never cached, and a 401 from `validate-api-key` is not
cached.

### Added

- `WithExpectedJWTAudience(aud)` — asserts `aud` on **user JWTs only** (`ValidateToken`,
  `ValidateTokenWith`, `Authorize` with a JWT, and as the default for `VerifyAccessTokenLocal`),
  never on `ab0t_sk_` API keys. Use it when the same routes accept JWTs minted for your service and
  mesh service keys, which carry no audience; `WithExpectedAudience`, which also applies to API keys,
  rejects those keys. For a JWT it takes precedence over `WithExpectedAudience`. `WithExpectedAudience`
  is unchanged.
- `authmw.Gate.RequireIdentity(next)` — for routers where every route needs a caller: 401 no or
  invalid credential, 503 auth unreachable (`FailOpen` honoured as in `Authenticate`), else `next`
  with `authmw.Identity` set.
- `authmw.Gate.IncludePermissions` (default off) — asks the auth service for a JWT caller's
  permissions, so `authmw.Identity(ctx).Permissions` is populated for JWTs as it already is for API
  keys. Needs a `V` that also implements `ValidateTokenWith` (`*auth.Client` does); with one that
  does not (e.g. `authclienttest.Fake`), a JWT request is a 503 rather than an identity with its
  permissions silently missing.
- `authmw.Gate.WriteDenial` (default: `http.Error` text, unchanged) and `authmw.JSONDenial`, which
  writes `{"error":"<message>"}` with `Content-Type: application/json`. Messages stay static.
- `authmw.Gate.APIKeyHeader` (default `X-API-Key`, unchanged). `Authorization` still wins when both
  are sent.
- Package `authmw/authmwtest` — `Run(t, Contract{Wrap: …})` checks **your** gate wiring from your
  own test suite against a fake auth service: no credential / invalid JWT / invalid API key → 401,
  auth down or unreachable → 503 and not cached, valid credential → your handler with an identity
  (and permissions), repeats cost no extra auth calls, JSON denials when configured.
- `TESTS.md` — the catalogue of the contract tests and how to run them.

### Changed

- `authmw.Bearer` matches the `Bearer` scheme case-insensitively (RFC 7235): `bearer x` → `x`.
  Previously the whole header was returned and the credential was rejected. Headers without a
  Bearer scheme are returned whole, as before.

## [0.12.0] — 2026-10-16 — validation cache ON by default + `VerifyAccessTokenLocal`

> **BEHAVIOURAL change, no source change required.** No public signature changes; one default
> changes and new API is added. A client constructed **without** a cache option now caches
> validation answers in-process, which means **a revocation can take up to the TTL to reach your
> process**. Migration kit: `migrations/v0.11.2-to-v0.12.0/` (run its `migrate-check.sh`).

### Changed — the validation cache is ON by default (BEHAVIOURAL)

Until now every `ValidateToken` / `ValidateAPIKey` / `Authorize` was an HTTP call unless you opted
in with `WithValidationCache`. A client that configures nothing now gets per-question TTLs:

| Question | "yes" cached | "no" cached | Revocation latency in your process |
|---|---|---|---|
| API-key identity — `ValidateAPIKey`, `ValidateToken(ab0t_sk_…)` | 60 s | 10 s | ≤ 60 s |
| JWT identity — `ValidateToken`, `ValidateTokenWith` | 15 s, never past the token's `exp` | 5 s | ≤ 15 s (logout, revoked session) |
| Permission decision — `Authorize` (unscoped and resource-scoped), any call with `RequiredPermissions` | 15 s | 5 s | ≤ 15 s (removed permission) |

- Every existing safety property is kept: the key is a SHA-256 over every input; errors (network,
  429, 5xx) are never cached; an expired entry is never served after a failed refresh (fails
  closed); bounded at 4096 entries; one request per key under concurrency.
- The TTL follows the question, not the method name: `Authorize` with an API key is a permission
  decision (15 s), not an API-key identity (60 s).
- A positive JWT entry is now also capped at the token's own `exp` claim (read from the token; it can
  only shorten an entry). Previously only a service-reported `expires_at` capped it, and
  `validate-token` does not report one for JWTs.
- With the default cache, the resource-scoped PDP decision inside `Authorize` is cached too
  (15 s / 5 s). Under an explicit `WithValidationCache(ttl)` it is **not** — exactly as before.
- **Opt out:** `WithValidationCache(0)` restores the previous behaviour byte for byte (no cache is
  allocated). An explicit `WithValidationCache(ttl)` / `WithValidationCacheOptions` keeps working
  unchanged and overrides the defaults (one TTL for every question).
- `copyActor` now also copies `DelegationScope` / `DelegationChain`, so a caller mutating a cached
  answer's slices cannot alter the shared entry.

### Added

- `WithFreshValidation(ctx)` — a per-call bypass: the call always asks the auth service, and its
  answer refreshes the shared entry. For sensitive operations (admin, money movement, ownership).
- Default-TTL constants: `DefaultAPIKeyValidationTTL` (60 s), `DefaultAPIKeyValidationNegativeTTL`
  (10 s), `DefaultTokenValidationTTL` (15 s), `DefaultTokenValidationNegativeTTL` (5 s),
  `DefaultAuthorizeTTL` (15 s), `DefaultAuthorizeNegativeTTL` (5 s).
- `(*Client).VerifyAccessTokenLocal(ctx, token, LocalVerifyOptions) (*AccessTokenClaims, error)` —
  verifies an access token **with no network call on the hot path**: RS256 only (`none`, `HS*`,
  `ES*`, `PS*` rejected), signature against the cached JWKS (10 min; an unknown `kid` refetches at
  most once a minute), `iss` (default: `"ab0t-auth-service"` and the client's base URL), `aud` when
  one is expected (`LocalVerifyOptions.Audience`, else `WithExpectedAudience`), `exp`/`nbf`/`iat`
  with a leeway of 30 s by default and never more than 60 s, `sub` present, token type `access`
  (refresh tokens always rejected; delegation tokens only with `AllowDelegation`). Failures match
  `ErrInvalidAccessToken` (`*AccessTokenError` with a stable `Reason`); a key-set fetch failure is
  returned as-is so callers can answer 503, not 401.
  **It cannot see logout**: the service's access tokens are session-backed, and a logged-out token
  keeps verifying locally until its `exp`. `ValidateToken` is unchanged and still asks the service.
- `LegacyAccessTokenIssuer`, `DefaultLocalVerifyLeeway`, `MaxLocalVerifyLeeway`.
- `authclienttest.(*Server).NewClient(opts...)` — a real client against the fake service with the
  validation cache **off**, for tests that change the fake's answer mid-test.

### Testing note for consumers

A test that builds a real client with `auth.New(srv.URL())` against `authclienttest.Server` and then
flips the fake's answer (`SetValid(false)`, `SetStatus(503)`) will now see the cached earlier answer.
Build that client with `srv.NewClient()` or add `auth.WithValidationCache(0)`.

## [0.11.2] — 2026-10-09 — `TokenFor`: one call for a token to another mesh service

> **Additive, backwards-compatible.** No existing signature or behaviour changes, except that
> `authmw` now also reads `X-API-Key` when no `Authorization` header is present (a request that was
> answered `401 auth required` because its key was in `X-API-Key` is now validated).

### Added — `TokenFor`

- `(*Client).TokenFor(ctx, resource, scope, session) (*Token, error)`: `session == nil` → client
  credentials (RFC 6749 §4.4) with `resource` (RFC 8707) and `scope`; `session != nil` → RFC 8693 token
  exchange with the person's token as `subject_token`, client authentication, exactly one `resource`,
  and no `actor_token`. Client credentials are sent as HTTP Basic; a `WithAPIKey` key is **not** sent
  on these token-endpoint calls.
- `WithClientCredentials(clientID, secret)`; `Session` interface with `StaticSession` / `SessionFunc`
  adapters; `Token` type.
- `WithLegacyActorExchange(audience)` — a bridge for auth services that do not yet accept the
  client-authenticated exchange: TokenFor mints the app's own client-credentials token (cached) and
  exchanges the person's token with it as `actor_token` and the given `audience`. Delete the option when
  the service supports the target exchange.
- Caching: in memory until 30 s before expiry, never past the person's own token expiry, keyed by
  pattern + resource + scope set (+ a hash of the person's token), bounded LRU (`WithTokenCacheSize`,
  default 1024, negative disables), one request per key under concurrency, errors never cached;
  `TokenCacheStats()`.
- Typed errors: `ErrReauthenticate` (400 `invalid_request` or `invalid_grant` on the person pattern —
  services are moving from the second to the first; both are handled), `*ConsentRequired`
  (400 `invalid_target` + `suberror: consent_required`, with `AuthorizationURL(redirectURI, state,
  codeChallenge)` built from the RFC 8414 metadata: PKCE S256, `resource`, `scope`, `prompt=consent`),
  `ErrNoConnection` (`invalid_target`), `ErrScopeNotAllowed` (`invalid_scope`), `ErrClientAuth`
  (`invalid_client`), `ErrClientNotEnabled` (`unauthorized_client`), `ErrUnavailable` (5xx / 429 /
  network / cancelled context), `ErrClientCredentialsRequired`. The `*APIError` stays reachable with
  `errors.As`.
- `NewPKCE()` — RFC 7636 verifier + S256 challenge.
- `APIError.SubError` — the OAuth `suberror` member.
- `WithResource(uri)` exchange option (RFC 8707 `resource`).
- `authclienttest.TokenEndpoint` — a scripted fake token endpoint (+ RFC 8414 metadata) with
  `TokenOK` / `TokenError` answers and recorded requests, so consumers can test code that calls
  `TokenFor` without a live service.

### Changed — `authmw` reads `X-API-Key`

- New `authmw.Credential(r)`: the `Authorization` credential when present, else `X-API-Key` — the header
  mesh consumers are told to send their service key in. `Gate.Authenticate` and `Gate.Require` use it.
  `Authorization` still wins when both are sent; `authmw.Bearer` is unchanged.

### Fixed — docs and example

- `examples/obo` called `ExchangeToken` without an actor token, which today's services answer
  `400 invalid_request`; it now uses `TokenFor` with the bridge option and branches on the typed errors.
- `docs/OBO_TOKEN_EXCHANGE.md` rewritten around `TokenFor`: error names as on the wire
  (`invalid_request`/`invalid_grant`, `invalid_target`, `invalid_scope`, `invalid_client`,
  `unauthorized_client`) instead of server-internal reasons; the actor token is required on today's raw
  exchange; the audience is one the acting org recognises (its service audience or `SELF:<org id>`);
  `authsetup obo-enable` creates the grant and checks the audience (it does not register one); scopes are
  dotted permissions; `client_id` names the acting app where the service emits it; internal source-line
  references removed. `WithScope` / `ExchangeToken` doc comments corrected to match.

## [0.11.1] — 2026-09-11 — OBO / RFC 8693 token-exchange helper

> Purely **additive, backwards-compatible**: existing `OAuthToken` / `TokenResponse`
> behavior is unchanged (guarded by a test).

### Fixed — `APIError.Code` / `Message` for `{"detail": {"code", "message"}}`

- The auth service now answers several refusals with a stable code in an object `detail`
  (`org_last_owner` 409, `org_move_crosses_service` 409, `delegation_delegator_not_member` 403, and the
  existing `password_policy_violation`). `extractCodeMessage` read `detail` only as a string or a list, so
  `APIError.Code` and `Message` were empty for these and callers could not branch on the code. They are now
  populated (an explicit top-level `code`/`message` or OAuth `error` still wins).

### Added — on-behalf-of (OBO) token exchange

- `GrantTypeTokenExchange` const + token-type consts (`TokenTypeAccessToken`,
  `TokenTypeRefreshToken`, `TokenTypeIDToken`).
- `ExchangeOption` functional options: `WithScope`, `WithActorToken`,
  `WithSubjectTokenType`, `WithRequestedTokenType`.
- `TokenExchangeForm(subjectToken, audience, opts...) url.Values` — builds the
  RFC 8693 form (mirrors `RefreshTokenForm`); defaults both token-types to
  access_token.
- `ExchangeResponse` (§2.2.1) — surfaces `issued_token_type`, which `TokenResponse`
  drops.
- `(*Client).ExchangeToken(ctx, subjectToken, audience, opts...) (*ExchangeResponse, error)`
  — same transport + OAuth error-envelope mapping as `OAuthToken`.
- Docs: `docs/OBO_TOKEN_EXCHANGE.md` (+ README cross-links); runnable
  `examples/obo`. Contract gate extended (`POST /auth/oauth/token` response pin).

## [0.11.0] — 2026-09-07 — contract-fidelity (BREAKING)

> This is a
> **BREAKING** minor bump (SemVer 0.x): several return types, struct fields, and one endpoint path
> changed so the client faithfully matches the auth service wire contract. Consumers migrate with
> `migrations/v0.10.2-to-v0.11.0/` (`migrate-check.sh` + `MIGRATION.md`; migrationbot can drive it). **No server change is
> required.** Migrate with `migrations/v0.10.2-to-v0.11.0/` (run `migrate-check.sh` against your repo,
> or drive `agent-cycle-prompt.md` with a coding agent).

### Fixed — the client now matches the wire contract ("silent unknown-field drop")

Across ~25 endpoints the SDK request/response structs under-exposed, renamed, or mis-shaped fields the
server actually accepts/returns — so calls hard-errored, silently validated the wrong thing, or dropped
data. Full before→after per change: `migrations/v0.10.2-to-v0.11.0/MIGRATION.md`. Highlights:

- **Bare-array / envelope decode fixes (were hard-erroring or empty):** `ListOrgUsers` → `[]OrgMember`;
  `ListOrgClients` → `[]OrgClientSafe`; `GetLoginConfig`/`UpdateLoginConfig` → `*LoginConfig` with five
  nested sections (branding/content/auth_methods/registration/security); authz-model write now sends a
  flat `{schema_version,type_definitions}` body and list/get decode the `authorization_models` /
  `authorization_model` envelopes; hierarchy children are `[]OrgHierarchyChild` (flattened) and
  `WalkOrgTree` passes `*OrgInfo`; session id/count keys (`session_id`/`last_accessed`/`total_sessions`/
  `sessions_revoked`).
- **Missing / renamed accepted fields:** `RegisterRequest.InvitationCode` (invite-join was unreachable);
  `APIKeyCreate.RateLimit`; providers `provider_type`/`is_active` (+`is_default`/`description`/`metadata`,
  settings move into `Config`); invite `TeamID`+`Permissions` and `InviteToOrganization` → `*InviteResult`
  (exposes the `invitation_code`); DCR `client_uri`/`tos_uri`/`software_*`; `TeamMember`
  `team_id`/`permissions`/`joined_at`; `TeamPermissionsResponse.InheritedPermissions`; org
  profile+`slug`+`parent_id` and `Organization.AudienceStatus`; read `expires_at` +
  `ReadRelationshipsForSubject`; new `AdminUserUpdate.Status`.
- **Over-exposure / footguns removed:** `TokenValidationRequest.ResourceType`/`.ResourceID` (SECURITY —
  silently unscoped; use `Authorize(…, Resource{…})`); `OrganizationCreate/Update.BillingType` (billing-
  owned by design — see below) and `OrganizationUpdate.Status`; `RegisterRequest.ProviderType`;
  `OrgRegisterRequest.FirstName`/`.LastName`; `APIKeyCreate.OrgID`/`.Audience`; `APIKeyUpdate.Metadata`;
  `OrgRoleUpdate.Permissions`.
- **Whole-endpoint gaps:** `WriteAndDeleteRelationships` now targets the real `POST …/write`
  (returns `*TransactResponse`); the zanzibar model-assertions surface added
  (`PutModelAssertions`/`GetModelAssertions`/`RunModelAssertions`).

### Added — regression prevention

- **Bidirectional contract gate** (`contract_gate_test.go` + pinned `scripts/api_contract.json`,
  `make contract-gate`): reflects the paired SDK structs against the pinned API contract and fails the
  build on any missing-request / missing-response / over-exposure / envelope-mismatch drift, with a
  reasoned allow-list — so cannot silently recur. Plus 18 real-body `TestWireShape_*` tests.

### Note — `billing_type` is billing-owned (by design, not a gap)

`OrganizationCreate/Update` no longer carry `billing_type`: the auth service's org endpoints deliberately do not
accept it (create forces PREPAID; update 400-rejects it) because a caller-set value would be self-serve
tier escalation. Set org tier via the
billing service; put other custom org attributes in the `Metadata` map.

## [0.10.2] — 2026-08-31 — ship the migrationbot agent (packaging fix)

### Fixed — migration kit driver did not ship

- **The migrationbot agent now ships, from a tracked public folder.** `migrations/README.md` told
  consumers to run `@agent-migrationbot` from `.claude/agents/migrationbot.md`, but `.gitignore`
  excludes all of `.claude/` (it can hold local settings/secrets), so that file was in no tag and
  reached no consumer — a documented driver that did not exist. Fixed by shipping the agent from a
  plain tracked folder, [`migrations/agent/`](migrations/agent/), instead of un-ignoring anything in
  `.claude/` (which stays fully ignored). Clients copy `migrations/agent/migrationbot.md` into
  wherever their setup keeps agents (`<repo>/.claude/agents/` or `~/.claude/agents/`).
- **`migrations/README.md` clarified.** It now leads with the always-shipping, tooling-free path
  (`MIGRATION.md` + `migrate-check.sh`, plus `agent-cycle-prompt.md` where present); the agent is an
  optional convenience with copy-in instructions in `migrations/agent/README.md`. No API change.

## [0.10.1] — 2026-08-29 — delegation-grant fix (G-04)

### Fixed — `DelegationGrant` (G-04)

- **`DelegationGrant` remodelled to the server's request contract.** It now sends `Scope []string`
  (`json:"scope"`, server-**required**) and `ExpiresInHours *int` (required by some server builds),
  and no longer sends `Permissions`/`TargetUserID`/`ExpiresAt`/`Reason` — none of which the server's
  request schema has. The target of the grant is the AUTHENTICATED caller (you grant an actor the
  right to act as YOU), so it is not in the body.
  - *Why:* the old body omitted the required `scope`, so `Client.GrantDelegation` failed with 422 and
    could not succeed as shipped. Same class as F-04/F-05.
  - *Migration:* replace `Permissions` with `Scope`; set `ExpiresInHours`; drop `TargetUserID`/
    `ExpiresAt`/`Reason`. See `migrations/v0.10.0-to-0.10.1/`.

## [0.10.0] — 2026-08-28 — contract-fidelity + provisioning

> Recommended version: **0.10.0** (contains BREAKING changes; per SemVer for a
> 0.x line these ride a minor bump). Run `make release VERSION=0.10.0` per
> RELEASING.md. Verified against the live auth service on 2026-08-27.

### How to move to this version + where the contracts are written down
- **Migration kit (run it):** `migrations/v0.9.2-to-v0.10.0/` — `migrate-check.sh` greps your repo for
  every call site to change and prints the fix (CI-gateable); `MIGRATION.md` has the details + an
  agent-applicable rule list.


- **Migration:** every breaking item below has a one-line *Migration* note. Full before→after with
  internal/external classification: **`docs/CONTRACT_DRIFT_LOG.md`**.
- **Hand-rolled (non-SDK) clients:** the wire field shapes — validation, issuance, delegation, the
  `aud` contract, and the value traps (numeric timestamp, object-map quotas, `error` vs `reason`) —
  are in **`docs/FIELD_CONTRACT.md`**, verified against both live backends.
- **Assurance going forward:** a field+value contract gate (`make field-drift` / `field-drift-strict`,
  operation-based + type-aware) now guards against this drift class. Run it before a release:
  `make field-drift-strict`.

### ⚠️ BREAKING CHANGES — action required for some callers

- **`Authorize()` now performs a real resource-scoped decision.** When you pass a
  non-zero `Resource`, `Authorize` resolves the subject from the credential and then
  asks the resource-aware permission endpoint (`POST /permissions/check`), instead of
  relying on `validate-token` to honor the resource fields.
  - *Why:* against an auth-service deployment whose `validate-token` does not honor the resource
    fields, the old code silently answered the broader "does this subject hold
    the permission at all?" and could **allow an action on a resource the subject was
    never granted** (cross-resource privilege escalation). It now fails closed.
  - *Behavioural change:* a resource-scoped `Authorize` that previously returned `true`
    incorrectly will now return the correct (often `false`) answer, and it makes one
    additional round-trip (subject resolution + PDP). The optional validation cache
    (`WithValidationCache`) absorbs the subject-resolution call.
  - *Migration:* no code change needed. Re-check any authorization tests that asserted
    the old (unscoped) behaviour. Resource-less `Authorize` calls are unchanged.

- **`events.go` — webhook subscription types remodelled to the server contract.**
  - `EventSubscriptionCreate`: field **`URL` → `Endpoint`** (`json:"endpoint"`), and
    **`Name` is now required** by the server. `Active` removed from the create body.
  - `EventSubscription` (response): `ID` → `SubscriptionID`, `URL` → `Endpoint`,
    `Active` → `IsActive`; adds `TenantID`, `Name`, delivery/retry/batch fields.
  - `EventSubscriptionUpdate`: `URL` → `Endpoint`, `Active` → `IsActive`, adds `Name`.
  - `EventSubscriptionListResponse`: `Subscriptions`/`Total` → **`Items`/`Count`** (+`NextToken`).
  - *Why:* the old `EventSubscriptionCreate` sent `url` and omitted the required
    `name`/`endpoint`, so `CreateEventSubscription` could not succeed against the server.
  - *Migration:* rename the fields at your call sites (`URL`→`Endpoint`, set `Name`).

- **`network.go` — network-policy types remodelled to the server contract.**
  - `CreateNetworkPolicyRequest`: **`CIDRs` → `Networks`**, **`Mode` → `Action`**
    (values `allow`/`deny`, not `allowlist`/`blocklist`), and **`OrgID` is now required**.
  - `NetworkPolicy` / `UpdateNetworkPolicyRequest`: same rename; `ID` → `PolicyID`;
    adds `GeoCountries`, `GeoMode`, `RestrictedPermissions`, `RequireMFA`, `ExpiresAt`.
  - *Why:* the old create body sent `cidrs`/`mode` and omitted required
    `networks`/`action`/`org_id`, so `CreateNetworkPolicy` could not succeed.
  - *Migration:* rename fields; set `OrgID` and `Action`.

- **`system.go` — removed phantom fields that no backend returns.**
  - `HealthCheckResponse.Components` **removed** (never populated by any backend).
  - `ServiceDiscoveryResponse.Endpoints` and `.Links` **removed** (never populated).
  - *Migration:* stop referencing these fields; the real data is in the added fields below.

- **`APIKeyWithToken` create response: the secret now reads from `key`.** The service returns the
  one-time secret in `key`, not `token`; the SDK field is still named `Token` (source-compatible) but
  is now tagged `json:"key"`, so it actually populates. Redundant shadow fields were removed (they are
  provided by the embedded `APIKey`). *Migration:* none for `.Token` readers — it now works.
- **`APIKey` / `APIKeyUpdate`: `Enabled` → `IsActive` (wire `is_active`).** The server's field is
  `is_active`; the SDK sent/read `enabled`, which the server **ignored** — so enabling/disabling a key
  through the SDK silently did nothing. Response `APIKey` drops phantom `Enabled`/`LastUsedAt`
  (superseded by `IsActive`/`LastUsed`); request `APIKeyUpdate` renames `Enabled`→`IsActive` and adds
  `RateLimit`/`Metadata`. *Migration:* use `IsActive` instead of `Enabled`. See `docs/CONTRACT_DRIFT_LOG.md`.

### ⚠️ BREAKING (bugfix) — types corrected to the real wire values (F-12)

These fields were typed as a kind the server never sends, so `encoding/json` failed the WHOLE
response decode — the calls did not work at all. Correcting the type is a bugfix, but the Go field
type changes, so callers that referenced these fields must adjust.

- **`HealthCheckResponse.Timestamp`: `string` → `float64`.** `/health` returns a
  numeric Unix epoch (e.g. `1787879913.98`); as a `string` the whole `Health()`/`/health` decode
  errored. *Migration:* treat `Timestamp` as a float epoch.
- **`QuotaUsageResponse`: `Usage []QuotaUsageItem` → `Usage map[string]int64`** (plus new
  `Limits map[string]int64`, `Percentages map[string]float64`, `UserID`). The server returns object
  maps keyed by resource type, not an array; the old shape never decoded. `QuotaUsageItem` is
  retained but deprecated (no endpoint decodes into it). *Migration:* index by resource type.
- **`QuotaTiersResponse`: `Tiers []QuotaTier` → `Tiers map[string]QuotaTierLimits`** (plus
  `UpgradeURL`). `tiers` is an object keyed by tier name. New `QuotaTierLimits` type. *Migration:*
  index by tier name.

### Added — provisioning & directory operations
- **SCIM 2.0 (`scim.go`)** — user and group provisioning (list/create/get/replace/patch/delete) plus
  Schemas, ResourceTypes, and ServiceProviderConfig discovery. Requires an auth-service deployment that
  provides SCIM.
- **HRIS & SCIM connection management (`hris.go`)** — configure and sync an org's HR-system directory
  connection, and manage its SCIM provisioning connection.
- **Additional operations** — network access-check (`NetworkAccessCheck` / `EvaluateNetworkAccess`),
  fetch a single invitation (`GetInvitation`), SAML SP metadata + SLO initiation, and a path-form
  relationship delete (`DeleteRelationshipByObject`).

### Added (non-breaking)

- **Delegation is now observable.** `Actor` gains `IsDelegation`, `ActingAs`,
  `DelegationScope`, `DelegationChain` — the fields the service returns to identify a token acting
  on another user's behalf. `TokenUserInfo`
  gains the embedded `Actor *TokenActorInfo` (the acting principal). Previously a
  resource server could not tell a delegated/impersonated token from a direct one, nor
  name the actor for its own audit log.
- **`PermissionDecision.Scope`** — the grant-scope field the permission check response returns.
- **API-key validation is no longer thin (F-09).** `POST /auth/validate-api-key` returns
  the same `TokenValidationResponse` schema as token validation, so
  `APIKeyValidation` now surfaces `Email`, `Audience`, `ExpiresAt`, and the delegation
  fields (`IsDelegation`, `ActingAs`, `DelegationScope`, `DelegationChain`) — a service
  account can act on another principal's behalf. Also: `APIKeyValidation.Reason` now reads
  from the `error` wire field the server actually sends; previously it was tagged `reason`
  and was **always empty** (a silent bug). Field name `Reason` is unchanged (source-compatible).
- **`User` timestamps** — `CreatedAt`, `UpdatedAt`, `LastLogin`, returned by the user read
  endpoints (`GetUser`/`Me`/`GetMyProfile`); `created_at` is required on `UserProfile`.
- **`TokenSet`** gains `Provider` and `Scope` — returned on `TokenResponse`
  (`Refresh`/`Delegate`/`SwitchOrganization`).
- **`system.go` response fidelity.** `HealthCheckResponse` and `ServiceDiscoveryResponse`
  now model every field the backends return (nested objects as `json.RawMessage` so
  callers can decode what they need); previously `GET /health` surfaced 2 of up to 13
  fields and `GET /` surfaced 2 of 12.
- **`authclienttest`** fake server now serves `/permissions/check` and
  `/auth/check-permission`, so the exported test double exercises the new
  resource-scoped `Authorize` path.

### Notes

- Some less-common response types are still being expanded to surface every field the service returns;
  these are tracked internally and are additive (non-breaking) when they land.
- `UpdateOrganization`'s response varies by service version, so its return type is intentionally
  `*MessageResponse` (see `docs/CONTRACT_DRIFT_LOG.md`).
- Additional operations (SCIM v2 provisioning, HRIS) are being added; see the release notes when they ship.

## [0.9.2] — 2026-07-26

### Added — documentation and agent skills
- **`docs/USAGE.md`** — the cookbook: install, first success, asking questions,
  granting and revoking, access review, offboarding, tenants and environments,
  organizations and hierarchy, gating an HTTP service, CI, agents, troubleshooting.
- **`docs/CLI.md`** — complete command and flag reference, exit codes, the output
  contract, and the on-disk storage layout.
- **`skills/`** — three agent-readable skills following the house convention
  (`skills/<name>/SKILL.md` with trigger-rich frontmatter, as used by `authsetup`
  and `ab0t-quota-go`):
  - `auth-sdk-go-concepts` — the mental model. The two authorization systems and
    when to use which, typed ids, relation vs permission, stores and the
    multi-tenant isolation decision, nested organizations, per-tenant hosted login.
  - `auth-sdk-go-cli` — operating the CLI, by job rather than by verb.
  - `auth-sdk-go-integration` — middleware, test doubles, observability, transport.

## [0.9.1] — 2026-07-26

### Added
- **`--env` / `$AB0T_ENV`** — environment is now a first-class axis alongside the
  tenant profile. `--profile acme --env prod` stores its credential separately from
  `--profile acme --env dev`.

  This follows the convention set by **`authsetup`** (the org's Go binary for
  onboarding services to the auth mesh, from `ab0t-com/clientsetup`), which isolates
  credentials per environment as `<svc>.<env>.json` in one flat directory while the
  config stays shared. The reason it exists is the reason to copy it: it is what
  stops a dev credential being used against production.

### Fixed
- `.gitignore` broadened to the usual project hazards — OS noise, archives, database
  dumps, language/toolchain caches, and local agent scratch. Deliberately does **not**
  blanket-ignore `*.sql`: schema and migration files are legitimate source, so only
  dump/backup shapes are excluded.

## [0.9.0] — 2026-07-26

### Fixed — a silent contract bug in the org hierarchy

- **`OrgHierarchyResponse` decoded to zero values.** The SDK declared it as
  `{root, organizations}`; the service has never returned that shape. The real
  contract is `{organization, teams, children, user_count, team_count}`, recursive
  through `children` — which is how **companies of companies** are represented.
  JSON decoding does not complain about names it does not recognise, so
  `GetOrgHierarchy` returned an empty struct, silently, forever. The old test
  asserted the wrong shape and therefore passed. Same class as the bulk-check bug
  in v0.2.0; the reason `make drift` exists.
  Added `OrgInfo`, `HierarchyTeam`, `HierarchyUser`, and `WalkOrgTree` for the
  recursion every caller would otherwise write by hand.

### Added — the CLI is multi-tenant now, because the service always was

The service is multi-tenant by default: users belong to many organizations,
organizations nest via `parent_id`, and a session can be switched between them.
The CLI stored **one flat credential file** — a single-tenant store for a
multi-tenant product. That is how a staging login ends up running against
production an hour later without a single wrong command being typed.

- **Tenant profiles.** `$XDG_CONFIG_HOME/ab0t/auth-sdk-go/profiles/<name>.json`,
  one file per tenant, 0600 inside 0700, written atomically, namespaced per tool
  so several ab0t clients can share the config root. Each profile carries its
  credential *and its tenancy* — org, slug, service — which is what lets `whoami`
  answer "which tenant am I in" rather than only "who am I". Matches the house
  convention (`connect-cli`'s `connect-auth`: login, API keys, dev/prod, headless).
  A legacy `auth.json` is imported as `default` and renamed aside, never deleted.
- **`profile`** — list, use, remove; plus a global `--profile` and `$AB0T_PROFILE`.
- **`orgs`** — organizations this credential belongs to, with your role and
  `[default]` / `[personal]` / `[sub-org of …]` / `[workspace]` markers.
- **`org-tree`** — the organization hierarchy as an indented tree.

## [0.8.0] — 2026-07-26

### Added — from 105 further customer journeys (15 per hat, all automated)

- **`help --json`** — the capability catalogue as data, whole or per verb. Every
  other surface was machine-readable and this one was not, so an agent
  discovering the tool had to regex prose. That was the one place we forced a
  machine to behave like a human, in the hat we otherwise serve best.
- **`--dry-run`** on `grant`, `revoke` and `revoke-all` — prints exactly what
  would change and sends nothing. Every evaluator was inventing their own safe
  path (usually a throwaway store) because none was offered; a write verb with no
  rehearsal is one people are afraid of.
- **`--expires`** on `grant`, taking a duration (`24h`) or an RFC3339 instant.
  Support engineers were granting **permanent** access for temporary needs because
  the CLI had no expiry, though the service supports it — a permissions leak
  created by our own interface. Also `ZanzibarStore.RelateUntil` in the SDK.
- **`revoke-all <object>`** — removes every relationship on an object. Offboarding
  was a manual loop that required already knowing every relation; anything
  forgotten stayed granted, silently. Object-scoped; the per-principal case is
  named as still open rather than left to be rediscovered.
- **`about`** — licence, source, issues, security contact, changelog, the Go SDK
  import line, and the dependency count. Three separate hats were leaving the tool
  to find basic facts.

### Fixed
- `can`'s help now documents that exit code 2 is an **answer**, not an error, and
  gives the capture-first idiom — `set -e` / `set -o pipefail` otherwise abort a
  script on a perfectly good DENIED. The expanded harness tripped over this itself.

## [0.7.1] — 2026-07-26

### Fixed
- `ab0t-auth --json version` and `--<flag> help <verb>` failed with
  `unknown command`. Leading global flags were hoisted *after* the `help` and
  `version` special cases, so those two never saw the reordered arguments. Found
  by the clean-room check on v0.7.0 — the local build was fine, which is precisely
  why that check exists.
- `version` now honours `--json`, so an agent pinning a version does not have to
  special-case the one command that spoke only prose.

## [0.7.0] — 2026-07-26

### Added — the CLI now behaves like an interactive support page

A user-journey product review walked 28 customer journeys cold against the real
binary. 20 of 28 stalled on the same class of defect: **the tool knew what the
customer would want next and did not say it.** None of it was a missing feature —
it was information already in the binary, withheld.

- **Deep help for every verb, reachable both ways.** `help <verb>` and
  `<verb> --help` now render the same document: what it's FOR, a worked example
  **with real output**, the failures you will actually hit and what they mean, and
  what people usually run next. Previously `help can` printed the generic
  top-level page **and exited 0** — the customer asked one question, got a
  different answer, and was told it succeeded.
- **A common-commands surface.** The bare invocation now says what the tool is for
  before what it can do, lists the ~10 things people actually do (ordered by when a
  newcomer meets them, not alphabetically), and carries a four-step NEW HERE? path.
  `doctor` is first, because stuck people do not read to the bottom of a list.
- **Next-step hints.** After a command, at most two things people usually do next.
  A DENIED now points at `why` — six journeys across four hats stalled on exactly
  that. Hints go to **stderr**, and are silent under `--json` and `--quiet`: a
  script did not ask for advice, and a hint must never contaminate a piped result.

### Fixed

- **Global flags now work before OR after the verb.** `ab0t-auth --server X health`
  previously failed with `unknown command "--server"`. `git`, `docker` and
  `kubectl` all accept the leading form. Found when the journey harness — written
  by the same person who wrote the CLI — made exactly that mistake on its first run.
- **A flag in command position** gets a message naming the real problem instead of
  "unknown command", which sent people looking for a command that never existed.
- **`health` printed a raw Go struct** (`status: &{healthy map[]}`) — a pointer
  dump in the command recommended as the safe first thing to run.

## [0.6.0] — 2026-07-25

### Added
- **`ab0t-auth` — a command-line client.**

  ```bash
  go install github.com/ab0t-com/auth-sdk-go/cmd/ab0t-auth@latest
  ab0t-auth doctor
  ab0t-auth can user:alice view doc:123 --store my-store
  ```

  Answers from a terminal the questions that otherwise need a Go program: is this
  token valid, who am I, can alice read this document and why not, is the service
  up, and what is wrong with my configuration.

  **Still zero dependencies.** A CLI would normally reach for cobra; that would add
  cobra and pflag to this module and break the stdlib-only guarantee for every
  consumer, none of whom asked for a CLI. Subcommand dispatch is written against
  the stdlib `flag` package instead, so `go install` pulls exactly nothing else.

  **Accessibility is built in, not bolted on**, and each property has a test
  because a regression in any of them is invisible to a sighted developer at an
  interactive terminal:
  - `NO_COLOR` (any non-empty value) means **no ANSI at all**, not less colour;
    a non-TTY, `TERM=dumb` and `--json` each disable colour too.
  - **Colour is never the only signal** — strip every escape sequence and the
    output is byte-identical to the plain rendering. Verified by a test.
  - `--json` on every command, with the same facts as the text output.
  - Data on stdout, diagnostics on stderr, so `cmd --json > out.json` yields a
    parseable file and the human still sees the errors.
  - No spinners, progress bars, cursor movement or box drawing anywhere.
  - Every prompt has a non-interactive equivalent; a prompt that would block in CI
    is skipped rather than hanging.
  - Exit codes: `0` ok/ALLOWED, `1` error, `2` DENIED, `3` no credential — so
    `if ab0t-auth can …; then` works in a script.

  Credential storage follows the house pattern: a JSON file at **0600 inside a
  0700 directory**, written atomically, resolved `--token` → `$AB0T_AUTH_TOKEN` →
  `$AUTH_SERVICE_KEY` → file. No command ever prints a credential in full.

  `doctor` reports every check rather than stopping at the first failure — the
  second failure is often what explains the first.

## [0.5.0] — 2026-07-25

### Added
- **`WithObserver(fn)` — an observability seam.** One `RequestInfo` per completed
  HTTP attempt: method, endpoint, status, duration, attempt number, whether a retry
  follows, error, and the service's request id. **Retries are visible** — a retry
  storm that looks like one slow call is the thing you most need to see.

  Deliberately a callback, not a logger: a logger in a library imposes three
  decisions on the consumer (which package, which format, which level) and would
  add a dependency to a module whose defining property is having none. This feeds
  slog, zap, OTel or a test assertion equally.

  It carries **no headers and no bodies**. This client's job is handling
  credentials, and an observability hook is exactly what ends up in a log
  aggregator; a path and a status cannot leak a token. The endpoint has its query
  string stripped, so it is usable as a metric label.

- **`authclienttest` — exported test doubles.** `Fake` (implements both interfaces,
  records calls) plus ready-made `Allow()`, `Deny()` and **`Unavailable()`**, and
  `Server`, an httptest-backed fake auth service for exercising the *real* client.

  `Unavailable()` is the point. Every consumer writes allow and deny fakes; almost
  nobody tests what their handler does when the auth service is unreachable — the
  one path where a mistake means an outage silently unlocks the write surface. Now
  it is one line. A separate package, so the root's dependency surface is untouched.

- **`authmw` — the HTTP middleware, promoted out of `examples/`.** `Authenticate`
  (attach identity; missing credential stays anonymous, invalid is 401, unreachable
  is 503) and `Require(action, resourceType)` (401 / 403 / 503 / handler), plus
  `RequireFunc` for routers that compose `func(http.Handler) http.Handler`.

  It lived only in an example, which meant every consumer copy-pasted it, inherited
  whatever was wrong with it that day, and got none of the fixes — the wrong
  distribution mechanism for a component whose failure mode is "the write surface
  is silently unlocked". **Fail-closed is the default and cannot be forgotten:**
  `FailOpen` must be set deliberately, and a test asserts the default has not
  drifted.

## [0.4.0] — 2026-07-25

### Added
- **A release SOP that is enforced rather than remembered.** `make release VERSION=x.y.z`
  refuses on a dirty tree, a missing changelog section, an existing tag, or a
  failing `make check`, then bumps `version.go`, commits, tags and pushes.
  `TestVersionMatchesChangelog` fails if `Version` has no changelog section behind
  it. See `RELEASING.md`.

  This exists because v0.1.0 shipped without a fix that was already on `main` — it
  had been committed after the tag. Every local test passed; only a clean-room
  `go get` by tag revealed it. Remembering harder does not fix that; a guard does.

## [0.3.0] — 2026-07-25

### Added
- **`Client.Store(storeID, token)` — the ergonomic Zanzibar surface.** The raw methods
  mirror the HTTP API exactly, which is the right foundation but makes a one-line
  question cost six lines of ceremony and a repeated store id and token on every
  call. `ZanzibarStore` binds them once and exposes the questions people actually
  ask: `Can`, `CanAll`, `CanAny`, `Why`, `WhatCan` ("which docs can alice view" —
  the filtered index page), `WhoCan` ("who can view this" — the sharing dialog,
  groups expanded), `RelationsOn`, `Relate`, `Unrelate`, plus `*ID` variants and a
  `Check(...)` batch builder and `As(token)` for per-request tokens.

  Types are separate arguments (`"user", "alice"`) rather than something the caller
  concatenates, because a mistyped combined id produces a silent DENY, not an error.

  Every boolean fails closed: an error is false, an **empty batch is false**
  ("nothing was asked" is not "everything is permitted"), and a bulk response whose
  length does not match the request is an error rather than a guess. `Relate` and
  `Unrelate` treat `success:false` as an error even on a 200 — a write reported as
  refused is not a write.

  It is a layer over the raw methods, never a replacement: everything the service
  can do stays reachable.

## [0.2.0] — 2026-07-25

### Added
- Zanzibar combined ids are now validated before the request. `ZanzibarCheck` and
  `ZanzibarCheckBulk` return `*ErrUntypedID` when a `subject` or `object` is
  missing its `type:` prefix, instead of sending a request that can only come back
  `allowed:false`. A bare `"alice"` where `"user:alice"` was meant is
  indistinguishable, server-side, from an id it has simply never seen — so the
  caller reads a legitimate DENY and debugs the wrong thing. The bulk form names
  the offending index (`check 2: …`).
- `make drift` / `scripts/spec-coverage.py` — compares this SDK against the live
  OpenAPI spec in both directions and reports MISSING (a capability consumers
  cannot reach) and PHANTOM (a call that would 404). Current: 283/283 operations
  reachable. Stdlib-only; no network unless you ask it to fetch.

### Changed
- The staged CI workflow is **manual-dispatch only** (`workflow_dispatch`, no
  `push`/`pull_request`), so installing it does not start anything running.
  Dropped the CI status badge, which would have advertised a workflow that never
  fires.

## [0.1.0] — 2026-07-25

First public release. Extracted from a private in-repo client, reconciled against
the live ab0t Auth Service OpenAPI 3.1 spec, and published under its own module
path `github.com/ab0t-com/auth-sdk-go`.

### Added
- `DeleteCurrentUser` — `DELETE /users/me`, the GDPR / right-to-erasure
  self-delete flow, guarded by a confirm-email match. Previously the endpoint had
  no representation in the SDK at all, so a consumer offering "delete my account"
  had to hand-roll the call and re-derive the confirmation contract.
- `/mesh/providers` service-discovery surface — `ListMeshProviders`,
  `GetMeshProvider`, `PublishMeshProvider`, with `MeshProvider`,
  `MeshProviderPublishRequest/Response` and the tier types. The whole subsystem
  was previously absent.
- `BulkCheckResults.Allowed(i)` and `.AllAllowed()` helpers. Both fail CLOSED:
  an out-of-range index and an empty result set are `false`, because "nothing was
  checked" is not "everything is permitted".
- `Version`, reported in the `User-Agent` of every request so the service can
  attribute traffic and identify clients running a version with a known-bad
  contract.

### Fixed
- **`ZanzibarCheckBulk` returned an error on every successful call.** The live
  spec defines the `check/bulk` 200 as a bare JSON **array** of
  `CheckPermissionResponse`; the SDK decoded it into a struct with a `results`
  map, so every response failed with `json.UnmarshalTypeError` even when the
  server had answered correctly. This was an honest best-effort guess made while
  the server had no declared response schema — the server has since declared one.
- **The JWKS cache was unbounded.** `OrgJWKS` keyed one entry per organization
  and nothing ever evicted, so a long-lived multi-tenant process grew the map by
  one entry per distinct org ever seen, for the life of the process. It is now
  bounded (512 entries) with stalest-first eviction; eviction only ever costs a
  refetch.

### Changed
- **BREAKING:** module path is `github.com/ab0t-com/auth-sdk-go`.
- **BREAKING:** `ZanzibarCheckBulk` now returns `BulkCheckResults`
  (`[]CheckPermissionResponse`, in request order) instead of `*BulkCheckResponse`.
  The old type is removed; it could not decode a real response.
- `User-Agent` no longer names one particular consumer.

### Known gaps
- Four `authzmodel.go` methods (`ReadAuthorizationModel`,
  `ListAuthorizationModels`, `WriteAuthorizationModel`,
  `WriteAndDeleteRelationships`) target routes the auth service does not expose
  yet. They are shipped as forward-looking stubs, each carrying a `SERVER-GAP`
  doc note, and `TestAuthorizationModel_IsStillAServerGap` records executably
  that they 404 today. When the server ships those routes, that test starts
  failing — which is the signal to remove the warnings.
- Non-idempotent `POST`s are retried on 429/5xx. This is deliberate and tested,
  but it means a create call whose write committed before the response was lost
  can be applied twice on an endpoint with no natural dedup key. Use
  `WithMaxRetries(0)` on calls where once-only semantics matter. See README.

### Note for anyone on v0.1.0
The typed-id guard is a behaviour change: a `ZanzibarCheck` that previously sent a
request with an untyped id now returns `*ErrUntypedID` without sending it. If you
were relying on that request going out, it could only ever have come back
`allowed:false` — the guard turns a silent wrong deny into a clear error.

[0.9.2]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.9.2
[0.9.1]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.9.1
[0.9.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.9.0
[0.8.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.8.0
[0.7.1]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.7.1
[0.7.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.7.0
[0.6.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.6.0
[0.5.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.5.0
[0.4.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.4.0
[0.3.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.3.0
[0.2.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.2.0
[0.1.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.1.0
