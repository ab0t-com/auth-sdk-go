# SOP: Migrate a service from auth-sdk-go v0.9.2 → v0.10.0
**Owner:** the consuming service's maintainer (the team that imports `github.com/ab0t-com/auth-sdk-go`) · **Cadence:** once per breaking SDK upgrade · **Scope:** in — your Go call sites and tests that use the SDK; out — the auth service itself (no server change is required)

## Purpose
Move a Go service that depends on `auth-sdk-go` from `v0.9.2` to `v0.10.0` correctly the first time,
using the migration checker to find every affected call site. A stranger to this codebase can follow
it end to end.

## Roles
| Role | Responsibility |
|---|---|
| Maintainer | Runs the steps, applies the edits, opens the PR |
| Reviewer | Confirms the checker reports 0 and tests are green before merge |

## Preconditions
- [ ] Go toolchain installed; your service currently **builds green on v0.9.2** (`go build ./...`).
- [ ] A clean working branch (so the change is reviewable and revertible).
- [ ] Network access to fetch the SDK module and (for step 7) reach the auth service if your tests hit it.
- [ ] You have this kit: `migrations/v0.9.2-to-v0.10.0/` (`migrate-check.sh`, `MIGRATION.md`).

## Steps
1. **Branch.** — `git checkout -b upgrade-auth-sdk-go-0.10.0` → expect: a new branch. If not: resolve uncommitted changes first.
2. **Inventory the work (before changing the dependency).** — `/path/to/auth-sdk-go/migrations/v0.9.2-to-v0.10.0/migrate-check.sh .` → expect: a list of file:line sites, each with its fix, and a non-zero exit if any remain. If it prints "No migration findings", skip to step 6. If not: read each block; the fix is printed with it.
3. **Bump the dependency.** — `go get github.com/ab0t-com/auth-sdk-go@v0.10.0 && go mod tidy` → expect: `go.mod` now pins `v0.10.0`. If not: check the tag exists (`go list -m -versions github.com/ab0t-com/auth-sdk-go`).
4. **Apply the fixes.** For each block the checker printed, make the edit it names (rename the field, add the required field, change the type usage, or delete the removed field) — cross-referencing `MIGRATION.md` for before→after. Apply a rename only where the value's type is the SDK type named in the fix (the checker flags candidates; `.ID`/`.Mode`/`.Total` are common names). → expect: each flagged site edited. If unsure on one: see the matching section number in `MIGRATION.md`.
5. **Re-run the checker.** — `.../migrate-check.sh .` → expect: **"No migration findings", exit 0.** If not: it prints the remaining sites; return to step 4.
6. **Build + vet + unit test.** — `go build ./... && go vet ./... && go test ./...` → expect: all green. If build fails: the compiler names the remaining rename/type mismatch — fix and repeat.
7. **Re-review authorization behaviour (item 1 in MIGRATION.md).** Re-run any test that calls `Authorize(...)` with a `Resource`. → expect: the test still asserts correct allow/deny. If a test now fails: it likely asserted the *old* unscoped behaviour — the new (often `false`) answer is the correct one; update the assertion. If it hits the auth service and 401s on the permission check: you are on `v0.10.0` code but linked an older SDK — re-run step 3.
8. **PR + review.** Open a PR; the reviewer confirms steps 5 and 6 are green in CI/locally. → expect: approval. If not: address review comments.

## Verification
- [ ] `migrate-check.sh .` → **exit 0, "No migration findings".**
- [ ] `go build ./... && go vet ./... && go test ./...` → all pass.
- [ ] `grep auth-sdk-go go.mod` → shows `v0.10.0`.

## Rollback
- Before merge: `git checkout - && git branch -D upgrade-auth-sdk-go-0.10.0` (discard the branch).
- Pin back if already merged and a problem appears: `go get github.com/ab0t-com/auth-sdk-go@v0.9.2 && go mod tidy`, redeploy. All v0.10.0 changes are source-level; reverting the pin restores prior behaviour.

## Pitfalls
- **Common field names.** `.ID`, `.Mode`, `.Total`, `.Enabled`, `.Timestamp` occur on many types — only change them where the value is the SDK type named in the checker's fix. Blanket find-replace will break unrelated code.
- **Value-type changes are not renames.** `Timestamp` (→`float64`) and the quota `map`s require *rewriting the usage* (parse a number; range as `for k, v`), not a field rename.
- **Org-admin is a wildcard in its own org.** If a test checks a permission for an org admin, the server allows it (`reason: org_admin`) — that is correct, not a bug. Use a non-member to test the deny path.
- **Enabled did nothing before.** If you relied on `APIKeyUpdate.Enabled` to toggle a key, it was silently ignored pre-0.10.0; `IsActive` now actually works — test that it does what you expect.

## References
- `MIGRATION.md` (same dir) — per-change before→after + agent-applicable rule list
- `agent-cycle-prompt.md` (same dir) — drive steps 2–6 with a coding agent
- `../../CHANGELOG.md` `[0.10.0]` section; `../../docs/FIELD_CONTRACT.md`; `../../docs/CONTRACT_DRIFT_LOG.md`
