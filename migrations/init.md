# Migrate my service to the latest `auth-sdk-go` — START HERE

This is the **fresh-system entrypoint**. You have a Go service that imports
`github.com/ab0t-com/auth-sdk-go` and you want to move it to a newer (possibly breaking)
version. You don't need to know which version you're on or which kit to use — this figures
it out.

There are two ways: **(A) let an AI agent do it** (recommended for a breaking jump), or
**(B) do it by hand** with the kit. Both use the same per-version kits + `migrate-check.sh`.

---

## A. Agent-driven (recommended) — copy this whole block into Claude Code

> Migrate this Go service to the latest `github.com/ab0t-com/auth-sdk-go`. Do it as a
> mechanical, verifiable migration — no guessing, no merging, leave a worklog. Steps:
>
> 1. **Find my current version**: read this repo's `go.mod` for the
>    `github.com/ab0t-com/auth-sdk-go v0.X.Y` require line. That's FROM.
> 2. **Find the target**: `git ls-remote --tags https://github.com/ab0t-com/auth-sdk-go`
>    (or ask me) — the highest `vX.Y.Z` is TO. (Or use the TO I give you.)
> 3. **Locate the kit chain**: kits live at `<auth-sdk-go>/migrations/<FROM>-to-<TO>/`.
>    If there's no single FROM→TO kit, **chain** the intermediate kits in order
>    (e.g. `v0.9.2-to-v0.10.0` → `v0.10.0-to-0.10.1` → `v0.10.2-to-v0.11.0`), re-verifying
>    between each (see `RFC-0001-library-migration-protocol.txt` §6, Chaining). Non-breaking
>    versions have no kit — skip them.
> 4. **Install the driver**: copy `<auth-sdk-go>/migrations/agent/migrationbot.md` to
>    `~/.claude/agents/migrationbot.md` (all services) or `./.claude/agents/migrationbot.md`
>    (this one). Then hand off to it: `@agent-migrationbot`, giving it FROM, TO, this repo,
>    and the kit path(s).
> 5. **Run the loop per kit**: for each kit, `bash <kit>/migrate-check.sh .` to list the
>    break sites (file:line + fix), apply the mechanical edits from the kit's `MIGRATION.md`,
>    `go get github.com/ab0t-com/auth-sdk-go@<TO>`, then re-run `migrate-check.sh`.
>    **The authoritative stop condition is always a clean `go build ./... && go vet ./... &&
>    go test ./...`** — if it compiled against `<TO>`, no genuine SDK break remains. On the
>    checker's `exit 0`: the **v0.10.2-to-v0.11.0** kit's checker is SDK-type-PRECISE
>    (import-gated + alias-qualified + field-precise literal scan), so its `exit 0` is a
>    trustworthy CI gate — it stays green on a genuinely-migrated repo and only reds on real
>    SDK breaks. **Older kits** still use bare line-greps that flag identically-named fields on
>    your OWN types (false positives) — for those, `exit 0` may be unreachable, so TRIAGE the
>    remaining hits (confirm each is a non-SDK type) and rely on the clean build/vet/test.
> 6. **Do NOT commit or push** — leave the working tree edited + an append-only worklog so
>    a human reviews and commits. Flag anything the kit calls SECURITY (e.g. removed
>    resource-scoping fields) for explicit human review.
>
> Start by printing FROM, TO, and the kit chain you'll walk, then proceed.

*(`migrationbot` ships in the SDK at `migrations/agent/migrationbot.md`. It runs on Opus by
default; it does mechanical, verifiable edits only and never merges.)*

---

## B. By hand (no AI agent)

```sh
SDK=$(go list -m -f '{{.Dir}}' github.com/ab0t-com/auth-sdk-go 2>/dev/null)   # or your local clone
FROM=$(grep -oE 'auth-sdk-go v[0-9.]+' go.mod | awk '{print $2}')             # e.g. v0.10.2
TO=v0.11.0                                                                    # the latest tag

# 1. See exactly what breaks (read-only), for each kit in the chain FROM..TO:
bash "$SDK/migrations/$FROM-to-$TO/migrate-check.sh" .        # file:line + the fix for each

# 2. Apply the before→after edits from that kit's MIGRATION.md, then:
go get github.com/ab0t-com/auth-sdk-go@$TO
go mod tidy

# 3. Re-verify until clean:
bash "$SDK/migrations/$FROM-to-$TO/migrate-check.sh" .        # lists sites — TRIAGE: remaining hits on YOUR own types are false positives
go build ./... && go vet ./... && go test ./...              # THE authoritative stop: green here = migrated (not migrate-check exit 0)
```

If your FROM is more than one breaking release behind TO, walk the kits in order
(re-verify between each) — the checks are cumulative by design, so nothing is skipped.

---

## What each piece is
- **`migrations/<FROM>-to-<TO>/MIGRATION.md`** — every breaking change as before→after + the fix.
- **`migrations/<FROM>-to-<TO>/migrate-check.sh`** — flags each removed/renamed symbol;
  exits non-zero while any remain (CI-gateable). The **v0.10.2-to-v0.11.0** checker is
  SDK-type-precise (import-gated, alias-qualified, field-precise literal scan) → green on a
  migrated repo, red only on real breaks; use its `exit 0` as a gate. *Older kits bare-grep,
  so common field names (e.g. `ResourceType`) can false-positive — there, apply a change only
  where the value's type is the SDK's, and trust the clean build over the checker's exit code.*
- **`migrations/agent/migrationbot.md`** — the Claude Code subagent that drives the loop.
- **`RFC-0001-library-migration-protocol.txt`** — the protocol (change taxonomy + chaining).
