# Client notice — auth-sdk-go v0.10.0 (contract-fidelity release)

*Copy/paste to any team that imports `github.com/ab0t-com/auth-sdk-go`.*

---

**Subject: auth-sdk-go v0.10.0 is out — a breaking, correctness release. Please upgrade with the included migration kit.**

Hi — we've released **v0.10.0** of the Go auth client. It fixes the client so it faithfully matches
the auth service's wire contract. This is worth doing promptly because **two bugs were silently
affecting callers**, and a few changes are breaking at the Go-source level.

**Two things that were silently wrong before v0.10.0 (fixed now):**
1. **Enabling/disabling an API key did nothing.** `APIKeyUpdate` sent a field the server ignored, so
   toggling a key through the SDK was a no-op. If you relied on it, verify your keys' state.
2. **The API-key create secret came back empty.** `APIKeyWithToken.Token` read the wrong field, so
   the one-time secret was blank. If you create keys via the SDK, this now works — re-check any flow
   that captured an empty secret.

**The headline behavioural change:** `Authorize(ctx, cred, action, resource)` with a **resource**
now makes a *real* resource-scoped decision and **fails closed** (it never returns a `true` it can't
justify). A call that used to return `true` because the resource was ignored may now correctly return
`false`. Resource-less `Authorize` is unchanged.

**Also breaking (Go-source):** a few field renames (events `URL→Endpoint`, network `CIDRs→Networks`/
`Mode→Action`, API keys `Enabled→IsActive`), two value-type fixes (`/health` timestamp is a number;
quota `usage`/`tiers` are maps — the old types failed to decode the whole response), and three phantom
fields removed. **New:** SCIM 2.0 and HRIS provisioning methods.

## What to do

```bash
go get github.com/ab0t-com/auth-sdk-go@v0.10.0 && go mod tidy
```

Then run the **migration kit** that ships in the module — it tells you exactly what to change:

```bash
# from your service's repo root (KIT = the auth-sdk-go module path in your module cache or a checkout)
$KIT/migrations/v0.9.2-to-v0.10.0/migrate-check.sh .
```

It greps your code, prints each file:line with the fix, and exits non-zero until you're clean —
gate CI on it. It never edits your code. Then `go build ./... && go test ./...`.

The kit also has:
- `MIGRATION.md` — before→after for every change.
- `MIGRATION.SOP.md` — a step-by-step runbook (expected results, rollback).
- `agent-cycle-prompt.md` — a paste-ready prompt to have your coding agent do the migration.

## Watch out for
- **Value-type changes are not renames** — `Timestamp` (now a number) and the quota maps need the
  *usage* rewritten, not a field rename. If you skip them, decoding the whole response fails.
- **Re-check authorization tests** — the `Authorize` change may flip an over-permissive `true` to the
  correct `false`. Update the assertion to the correct answer; don't restore the old behaviour.
- **Common field names** (`.ID`, `.Mode`, `.Enabled`, `.Timestamp`) — only change them where the value
  is the SDK type the checker names; don't blanket-replace.

**Rollback:** all changes are source-level — pin back to `@v0.9.2` and redeploy if you need to.

Questions? Reply here. Full detail: the `[0.10.0]` section of the module's `CHANGELOG.md` and
`docs/FIELD_CONTRACT.md`.
