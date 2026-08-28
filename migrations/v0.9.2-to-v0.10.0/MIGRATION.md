# Migration: auth-sdk-go v0.9.2 → v0.10.0

This release fixes the client so it faithfully matches the auth service's wire contract. Several
fixes are **breaking at the Go source level** — a few field and type names changed, some phantom
fields were removed, and `Authorize()` now makes a real resource-scoped decision. **None of these
require a server change**; they change how your Go code calls the SDK.

**This directory is a migration kit, not just notes.** Run the checker against your codebase and it
tells you exactly what to change — like a dependency bot, but for this contract change:

```bash
# from your service's repo root:
/path/to/auth-sdk-go/migrations/v0.9.2-to-v0.10.0/migrate-check.sh .
```

It greps your Go files for every affected pattern and prints, per finding: the file:line, what it
is, and the exact replacement. It exits non-zero if anything needs changing, so you can gate CI on
it. It is **read-only** — it never edits your code.

**This kit has four pieces:** `migrate-check.sh` (the checker), this `MIGRATION.md` (details + rules),
`MIGRATION.SOP.md` (a step-by-step SOP with expected results), and `agent-cycle-prompt.md` (a paste-ready
prompt to drive the whole loop with a coding agent).

**Driving it with a coding agent:** point your agent at this file and say *"apply the v0.10.0
migration."* The [Agent rules](#agent-rules-machine-applicable) section below is a machine-applicable
find→replace list; the checker output gives the exact sites. Each rule is a safe, mechanical edit.

---

## TL;DR — what changed

| # | Kind | Change | Your action |
|---|---|---|---|
| 1 | Behaviour | `Authorize(...)` with a `Resource` now makes a real scoped decision + fails closed | Re-check tests that assumed the old answer |
| 2 | Rename | `events`: `URL`→`Endpoint`, `Active`→`IsActive`, `ID`→`SubscriptionID`, list `Subscriptions/Total`→`Items/Count`; `Name` now required | Rename fields; set `Name` |
| 3 | Rename | `network`: `CIDRs`→`Networks`, `Mode`→`Action` (values `allow`/`deny`), `ID`→`PolicyID`; `OrgID` now required | Rename fields; set `OrgID`, `Action` |
| 4 | Removed | `HealthCheckResponse.Components`, `ServiceDiscoveryResponse.Endpoints`/`.Links` (no server ever sent them) | Delete references |
| 5 | Type | `HealthCheckResponse.Timestamp` `string`→`float64` | Treat as a numeric epoch |
| 6 | Type | `QuotaUsageResponse.Usage` and `QuotaTiersResponse.Tiers` `[]…`→`map[string]…` | Index by key, don't range as a slice |
| 7 | Rename | `APIKey`/`APIKeyUpdate`: `Enabled`→`IsActive` | Use `IsActive` |
| 8 | Fixed | `APIKeyWithToken` secret now reads from `key` (was silently empty). Field is still `.Token` | None — `.Token` now works |

Full rationale for each is in `CHANGELOG.md` (the `[0.10.0]` section) and `docs/CONTRACT_DRIFT_LOG.md`.

---

## 1. `Authorize()` — behavioural change (read this even if it compiles)

`Authorize(ctx, cred, action, resource)` **still compiles unchanged**, but when you pass a non-zero
`Resource` it now asks a real resource-scoped question and **fails closed** on any error (it never
returns a bare `true` it can't justify). It authenticates the check as the credential you pass, and
makes one extra round trip on the resource-scoped path.

- **You do NOT need a service API key for this** — it authenticates as the credential being checked.
- **If you cached or asserted the old (unscoped) behaviour in tests, revisit those.** A call that
  used to return `true` because the resource was ignored will now return the correct answer (often
  `false`).
- Resource-**less** `Authorize` (zero `Resource{}`) is unchanged.

**Find:** `migrate-check.sh` flags every `Authorize(` call so you can eyeball the resource-scoped ones.

## 2. Events (`events.go`)

| Before | After |
|---|---|
| `EventSubscriptionCreate{URL: "..."}` | `EventSubscriptionCreate{Endpoint: "...", Name: "..."}` (Name required) |
| `sub.URL` / `sub.ID` / `sub.Active` | `sub.Endpoint` / `sub.SubscriptionID` / `sub.IsActive` |
| `EventSubscriptionUpdate{URL, Active}` | `EventSubscriptionUpdate{Endpoint, IsActive}` |
| `list.Subscriptions` / `list.Total` | `list.Items` / `list.Count` |

*Why:* the old create body sent `url` and omitted the server-required `name`/`endpoint`, so
`CreateEventSubscription` could not succeed at all.

## 3. Network policy (`network.go`)

| Before | After |
|---|---|
| `CreateNetworkPolicyRequest{CIDRs, Mode}` | `CreateNetworkPolicyRequest{Networks, Action, OrgID}` (OrgID required) |
| `Mode: "allowlist"` / `"blocklist"` | `Action: "allow"` / `"deny"` |
| `policy.ID` | `policy.PolicyID` |

*Why:* the old body omitted the server-required `networks`/`action`/`org_id`, so create could not succeed.

## 4. Removed phantom fields (`system.go`)

`HealthCheckResponse.Components`, `ServiceDiscoveryResponse.Endpoints`, and `.Links` are **gone** —
no auth service ever populated them (they were always zero). Delete any reference. The real data is
in the fields those types now model (see `docs/FIELD_CONTRACT.md`).

## 5–6. Value types (`system.go`, `quotas.go`)

These were mis-typed against the real wire values, which made the **whole** response fail to decode:

- `HealthCheckResponse.Timestamp` is now `float64` (a Unix epoch, e.g. `1787894650.69`). If you
  formatted it as a string, parse it as a number instead.
- `QuotaUsageResponse.Usage`/`.Limits`/`.Percentages` and `QuotaTiersResponse.Tiers` are now **maps**
  keyed by resource/tier name, not slices. Replace `for _, u := range resp.Usage` with
  `for name, used := range resp.Usage`.

## 7. API keys (`apikeys.go`)

`APIKey.Enabled` (response) and `APIKeyUpdate.Enabled` (request) are now **`IsActive`**. *Why:* the
server's field is `is_active`; the SDK sent/read `enabled`, which the server ignored — so
enabling/disabling a key through the SDK **silently did nothing**. Use `IsActive` and it now works.

## 8. `APIKeyWithToken` secret — no action, just works now

The one-time create secret is on `.Token` as before, but it now reads from the server's `key` field
(it was tagged `token`, which the server never sends, so `.Token` was always empty). Upgrading fixes
it with no code change.

---

## Verify after migrating

```bash
go build ./...    # rename/type errors surface here
go vet ./...
go test ./...     # re-run any auth/authorization tests (item 1)
```

Then run the checker again — it should report **0 findings**.

---

## Agent rules (machine-applicable)

A coding agent can apply these as mechanical find→replace edits **on your call sites** (Go
identifiers, so word-boundary aware). Confirm each against the checker's file:line output.

```
# selector renames (safe: rename the field access / struct key)
.URL            -> .Endpoint         # only on EventSubscription* values
.Active         -> .IsActive         # only on EventSubscription* values
.SubscriptionID <- .ID               # EventSubscription (response) id field
.Subscriptions  -> .Items            # EventSubscriptionListResponse
.Total          -> .Count            # EventSubscriptionListResponse
.CIDRs          -> .Networks         # NetworkPolicy / CreateNetworkPolicyRequest
.Mode           -> .Action           # NetworkPolicy* ; ALSO value "allowlist"->"allow", "blocklist"->"deny"
.PolicyID       <- .ID               # NetworkPolicy (response) id field
.Enabled        -> .IsActive         # APIKey / APIKeyUpdate
# removed (delete the reference; no replacement)
.Components                          # HealthCheckResponse
.Endpoints .Links                    # ServiceDiscoveryResponse
# required fields to ADD
EventSubscriptionCreate: set Name and Endpoint
CreateNetworkPolicyRequest: set OrgID and Action (and Networks instead of CIDRs)
# type shape changes (rewrite the usage, not a rename)
HealthCheckResponse.Timestamp: string -> float64
QuotaUsageResponse.Usage/.Limits/.Percentages, QuotaTiersResponse.Tiers: []T -> map[string]T
# behavioural (no edit; review tests)
Authorize(...) resource-scoped: now a real decision, fails closed, +1 round trip
```

> Caution for the agent: these identifiers (`.ID`, `.Mode`, `.Total`, `.Active`) are common names.
> Apply a rule only where the value's type is the SDK type named in the comment — use the checker's
> file:line hits, don't blanket-replace.
