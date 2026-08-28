# Agent cycle prompt — auth-sdk-go v0.9.2 → v0.10.0

Paste the block below to a coding agent (Claude Code, etc.) running in **your service's repo**. It
drives the check → fix → re-check → build loop until clean. It edits only your call sites, never the
SDK. Set `KIT` to where this migration kit lives, then paste from `You are migrating…`.

```text
KIT=/absolute/path/to/auth-sdk-go/migrations/v0.9.2-to-v0.10.0

You are migrating this Go service from github.com/ab0t-com/auth-sdk-go v0.9.2 to v0.10.0.
Work on a new branch. Do NOT edit anything under the SDK module — only this repo's call sites and tests.

Reference (read once): $KIT/MIGRATION.md  (per-change before→after + a machine-applicable rule list).

Run this loop until it converges:

  1. CHECK. Run: $KIT/migrate-check.sh .
     It prints, per finding, a file:line and the exact fix, and exits 0 only when nothing remains.
     If it exits 0 with "No migration findings", go to step 4.

  2. FIX. For EACH finding block, apply the printed fix at that file:line:
       - a rename (e.g. .URL→.Endpoint, .Enabled→.IsActive, .CIDRs→.Networks, Mode value
         "allowlist"→"allow") — apply ONLY where the value's type is the SDK type named in the fix;
         these identifiers are common, so do not blanket-replace.
       - a required field to add (EventSubscriptionCreate needs Name+Endpoint; CreateNetworkPolicyRequest
         needs OrgID+Action+Networks).
       - a removed field (HealthCheckResponse.Components, ServiceDiscoveryResponse.Endpoints/.Links) —
         delete the reference.
       - a TYPE change (rewrite the usage, not a rename): HealthCheckResponse.Timestamp is float64
         (a numeric epoch); QuotaUsageResponse.Usage/.Limits/.Percentages and QuotaTiersResponse.Tiers
         are map[string]T — range as `for k, v := range`, index by key.
       - Authorize(...) with a Resource is BEHAVIOURAL: do not edit the call. Note it for step 4.

  3. RE-CHECK. Re-run step 1. If findings remain, repeat step 2. Never lower the bar to make it pass.

  4. BUILD + BUMP. Run:
       go get github.com/ab0t-com/auth-sdk-go@v0.10.0 && go mod tidy
       go build ./... && go vet ./... && go test ./...
     Fix any compiler errors (they name the remaining rename/type mismatch) and re-run.

  5. AUTHORIZATION REVIEW. For every test that calls Authorize(...) with a non-zero Resource:
     v0.10.0 makes a REAL resource-scoped decision and fails closed, so a call that used to return
     true because the resource was ignored may now correctly return false. If such a test fails,
     update the ASSERTION to the correct answer — do not restore the old behaviour. (An org admin is
     legitimately allowed every permission in their own org; test the deny path with a non-member.)

  6. REPORT. Summarise: files changed, each finding and how you fixed it, the final
     `migrate-check.sh .` output (must be "No migration findings"), and the go build/test result.
     Open a PR. Do NOT merge — a human reviews.

Stop conditions: migrate-check.sh exits 0 AND go build/vet/test are all green. If you cannot resolve
a finding, stop and report it with the file:line rather than guessing.
```

## Non-agent equivalent
If you are not using an agent, follow `MIGRATION.SOP.md` (same directory) — the same loop as numbered
steps with expected results and on-failure branches.
