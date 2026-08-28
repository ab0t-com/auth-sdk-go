# Contract Drift Log — auth-sdk-go

A running record of every change to the SDK's **wire contract** (the fields/types/behaviour a
caller sees), classified **internal vs external**, so consumers know what breaks and why.

**Classification for this module:** `auth-sdk-go` is a **public, externally-consumed** Go module
(`github.com/ab0t-com/auth-sdk-go`, its own GitHub repo). Any change to a request/response type or
to a method's behaviour is therefore an **EXTERNAL / client-visible** change. There is no
"internal-only" contract change in this module — a caller in another team feels all of them. Server
The auth service's own implementation details are internal to the server, not to this SDK, and are not documented here.

---

## 2026-08-28 — contract-fidelity release (proposed v0.10.0)

All entries are **EXTERNAL** (client-visible). Ticket: `tickets/20260827_sdk_contract_drift/`.

### Behavioural
- **`Authorize()` resource scoping (F-01)** — EXTERNAL. A resource-scoped `Authorize` now routes to
  the resource-aware PDP and **fails closed**; it previously could return a wrong `true` on a backend
  that ignored the resource. *Migration:* re-check tests that asserted the old (unscoped) result.

### Field renames / type corrections (break source that referenced the old field)
- **`events.go` (F-04)** — EXTERNAL. `EventSubscriptionCreate.URL`→`Endpoint`, `Name` now required;
  `EventSubscription` `ID`→`SubscriptionID`, `Active`→`IsActive`; list `Subscriptions/Total`→`Items/Count`.
- **`network.go` (F-04)** — EXTERNAL. `CreateNetworkPolicyRequest.CIDRs`→`Networks`, `Mode`→`Action`
  (`allow`/`deny`), `OrgID` required; `NetworkPolicy.ID`→`PolicyID`.
- **`HealthCheckResponse.Timestamp` (F-12)** — EXTERNAL. `string`→`float64` (real value is a numeric
  epoch; as a string the whole `/health` decode failed).
- **`QuotaUsageResponse` / `QuotaTiersResponse` (F-12)** — EXTERNAL. `Usage`/`Tiers` slice→map (server
  returns object maps; old shape never decoded). Added `user_id`/`limits`/`percentages`/`upgrade_url`.
- **`APIKey` / `APIKeyUpdate` `enabled`→`is_active` (E / F-10)** — EXTERNAL. The server field is
  `is_active`; the SDK sent/read `enabled`, which the server **ignored** — so enabling/disabling a key
  through the SDK silently did nothing. Response `APIKey`: removed phantom `Enabled`/`LastUsedAt`
  (superseded by `IsActive`/`LastUsed`). Request `APIKeyUpdate`: `Enabled`→`IsActive`, added
  `RateLimit`/`Metadata`. *Migration:* use `IsActive` instead of `Enabled`.

### Field removals (phantoms — never populated by any backend)
- **`HealthCheckResponse.Components`, `ServiceDiscoveryResponse.Endpoints`/`.Links` (F-08)** — EXTERNAL.
  Returned by no backend; removed. *Migration:* the real data is in the newly-modelled fields.

### Additive (non-breaking, but contract-relevant)
- **Delegation fields on `Actor`, `APIKeyValidation`, `TokenUserInfo.Actor` (F-02, F-09)** — EXTERNAL,
  non-breaking. Lets a caller see on-behalf-of context on both token AND API-key validation.
- **`APIKeyValidation.Reason` now reads the `error` wire field (F-09)** — EXTERNAL bugfix; the field was
  tagged `reason` and always empty. Go field name unchanged.
- **~336 response fields across 15 files (F-10)** — EXTERNAL, additive. Responses that were silently
  dropping server data now surface it.

### Deferred — a genuine backend DIVERGENCE, not a clean change (documented, NOT applied)
- **`UpdateOrganization` return type** — the service's response for this call varies by version (some
  return a message, some the full organization). To decode safely everywhere, the SDK keeps the return
  type as `*MessageResponse`. Revisit if the service converges on returning the full organization.

---

## How to add an entry
When you change a request/response type or a method's behaviour: add a dated bullet, mark it
INTERNAL or EXTERNAL (for this module, essentially always EXTERNAL), give the before→after and a
one-line migration note. The automated gate (`make field-drift`) tells you WHICH types drifted;
this log records the DECISION and its blast radius.
