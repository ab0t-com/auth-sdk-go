# Auth wire field contract

The exact JSON shapes the ab0t auth service sends and expects, for teams building **their own**
client (not using `auth-sdk-go`). If you hand-rolled a client because the SDK was thin, this is what
to conform to — no Go source required.

**Verified** against the live auth service (`https://auth.service.ab0t.com`) on **2026-08-28**.
Fuller background: `tickets/20260827_sdk_contract_drift/` and `tickets/20260828_client_setup_feedback/`.

> **Read the "Traps" section at the bottom first if you are debugging** — every item there is a bug a
> real client (including our own SDK) shipped.

---

## 1. Token validation — `POST /auth/validate-token` **and** `POST /auth/validate-api-key`

**Both endpoints return the SAME shape** (`TokenValidationResponse`). A service API
key is not a lesser citizen — it carries the same fields, including delegation.

```json
{
  "valid": true,
  "user_id": "u_123",
  "org_id": "org_abc",
  "email": "person@example.com",
  "permissions": ["docs.read", "docs.write"],
  "audience": ["disksearch"],
  "expires_at": "2026-08-28T12:00:00Z",
  "error": null,

  "is_delegation": true,
  "acting_as": "u_owner_456",
  "delegation_scope": ["docs.read"],
  "delegation_chain": ["svc_companion", "u_owner_456"]
}
```

| Field | Type | Notes |
|---|---|---|
| `valid` | boolean | **The only always-present field.** An invalid token/key is `200 {"valid": false, "error": …}`, NOT a 4xx. Read this as a raw boolean. |
| `user_id` | string \| null | Who the token resolves to. |
| `org_id` | string \| null | The active tenant. |
| `email` | string \| null | |
| `permissions` | string[] | Resolved permissions (present when requested). |
| `audience` | string[] \| null | The token's audience(s) — see §3. |
| `expires_at` | string \| null | ISO-8601 timestamp. |
| `error` | string \| null | **Failure reason lives here — the field is `error`, NOT `reason`.** (Our own SDK read `reason` and got an always-empty value. Don't repeat it.) |
| `is_delegation` | boolean | True when the token is acting on another principal's behalf. |
| `acting_as` | string \| null | The `user_id` being acted for. |
| `delegation_scope` | string[] | Permissions the delegation is limited to. |
| `delegation_chain` | string[] | Principals in a chained delegation, in order. |

**Delegation applies to API keys too**, not just JWTs — a service account can act on behalf of a
user. Model `is_delegation`/`acting_as`/`delegation_scope`/`delegation_chain` on **both** validation
paths, or you cannot tell an on-behalf-of call from a direct one (and your audit trail is wrong).

> Only `valid` is guaranteed present; the service may mark the delegation fields required in some
> versions (always sent). Treat all as
> present-or-null and you are safe on both.

---

## 2. Token issuance — `TokenResponse` (login / refresh / switch-org / delegate)

```json
{
  "access_token": "eyJ…",
  "refresh_token": "eyJ…",
  "token_type": "bearer",
  "expires_in": 900,
  "provider": "internal",
  "scope": "openid profile",
  "audience": ["disksearch"],
  "user": {
    "id": "u_123",
    "email": "person@example.com",
    "name": "A. Person",
    "org_id": "org_abc",
    "is_delegated": true,
    "actor": { "id": "svc_companion", "email": "companion@svc", "name": "Companion" }
  }
}
```

| Field | Type | Notes |
|---|---|---|
| `access_token` | string | required |
| `refresh_token` | string | required — **persist the latest value**; it may rotate on refresh. |
| `token_type` | string | `"bearer"` |
| `expires_in` | integer | seconds, required |
| `provider` | string \| null | issuing provider (e.g. `internal`, `google`). |
| `scope` | string \| null | granted scope. |
| `audience` | string[] \| null | see §3. |
| `user` | object | required — embedded user (`TokenUserInfo`). |
| `user.actor` | object \| null | The acting principal on a delegated token (`{id, email, name}`). |
| `user.is_delegated` | boolean \| null | Convenience flag; `actor` names *who*. |

### On-behalf-of: where the `act` claim actually comes from
The **JWT `act` claim** (the in-token proof of on-behalf-of, distinct from the response fields above)
is minted onto the token **only** via `/auth/delegate` and the RFC 8693 token-exchange grant — **NOT
on plain `/auth/refresh`** (refresh re-mints a plain access token and drops actor context).

**So for OBO audit attribution: obtain the OBO token via `/auth/delegate` or token-exchange, not by
refreshing.** (Source: server investigation, `tickets/20260828_client_setup_feedback/` → ANSWERS G-01.)

---

## 3. The `aud` / audience contract

- A **valid** service token names a real service audience, e.g. `"audience": ["disksearch"]`. That
  audience must be the org's registered `service_audience`.
- `"audience": ["LOCAL:<org_id>"]` is a **broken fallback** — the server stamps it when an org has no
  `service_audience`. It is unusable: a real downstream service expecting its own name (`disksearch`)
  rejects it with `401 "Audience doesn't match"`. If you see `LOCAL:` as the sole audience, the org
  was mis-provisioned — fix the org's `service_audience`, don't work around the token.
- **Validation is exact-string membership.** A token is accepted only if the verifier's expected
  audience string is literally in the token's `audience` array. There is no prefix/wildcard logic.
- For a cross-service target (e.g. `aud=<engine>`): `<engine>` must be provisioned as the org's
  `service_audience`, or a token-exchange targeting it is rejected `invalid_target`.

This is a server-side concern; it is tracked internally.

---

## 4. Traps we already hit (avoid these)

| Trap | Reality | Why it bites |
|---|---|---|
| **Failure reason** | It's `error`, **not** `reason`. | A client keyed on `reason` gets an always-empty string and can't explain a rejection. |
| **`/health` `timestamp`** | A **number** (Unix epoch float, e.g. `1787879913.98`) — **not** a string. | Typing it as a string makes the *entire* health response fail to parse in a strict decoder. |
| **`/quotas/my-usage` `usage`, `limits`, `percentages`** | **Objects/maps** keyed by resource type (e.g. `{"api_calls": 42}`) — **not** arrays. | Expecting an array fails the whole decode. |
| **`/quotas/tiers` `tiers`** | An **object** keyed by tier name — **not** an array. | Same. |
| **Delegation on API keys** | Present on `validate-api-key`, same as `validate-token`. | Modeling it only for JWTs loses on-behalf-of attribution for service accounts. |
| **`act` on refresh** | Not minted on `/auth/refresh` (only delegate/exchange). | An OBO flow built on refresh silently loses the actor. |

---

_Maintained alongside the SDK. If the live spec moves, re-verify: `make drift` (SDK) or refetch
`/openapi.json` from either backend._
