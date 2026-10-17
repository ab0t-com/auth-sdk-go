# migrations/

One directory per breaking upgrade — and per release whose fixes a consumer can see — named
`vFROM-to-vTO/`, each containing:

- **`MIGRATION.md`** — what changed, why, and before→after for every breaking change, plus an
  agent-applicable find→replace rule list.
- **`migrate-check.sh`** — a read-only checker: point it at your repo
  (`./migrate-check.sh /path/to/your/service`) and it prints every call site you must change, with
  the fix, and exits non-zero if any remain (gate CI on it). It never edits your code.

Upgrading across several versions? Run each version's checker in order.

## Kit index

| Kit | Kind | What it covers |
|---|---|---|
| [`v0.9.2-to-v0.10.0/`](v0.9.2-to-v0.10.0/) | breaking (source) | contract-fidelity: renames, retypes, removed fields; resource-scoped `Authorize` fails closed |
| [`v0.10.0-to-0.10.1/`](v0.10.0-to-0.10.1/) | breaking (source) | `DelegationGrant` request shape (`GrantDelegation`) |
| [`v0.10.2-to-v0.11.0/`](v0.10.2-to-v0.11.0/) | breaking (source) | contract-fidelity across ~25 endpoints (return types, field renames/removals) |
| [`v0.11.2-to-v0.12.0/`](v0.11.2-to-v0.12.0/) | **behavioural** (no source change) | validation cache ON by default (API key 60 s, JWT 15 s, permission 15 s revocation latency); `WithFreshValidation`; new `VerifyAccessTokenLocal`. Its checker lists clients and validation call sites to **review**, plus the `if ttl > 0` opt-in and `authclienttest` patterns the new default changes. See its `CLIENT_NOTICE.md`. |
| [`v0.12.1-to-v0.12.2/`](v0.12.1-to-v0.12.2/) | **bug fix** (no source change) | `VerifyAccessTokenLocal`: a token segment must be canonical base64url (no padding) and a NumericDate past the year 9999 is `malformed`; the validation cache stays within `MaxEntries` under concurrency. Its checker lists hand-built test tokens with padding. See its `CLIENT_NOTICE.md`. |
| [`v0.12.0-to-v0.12.1/`](v0.12.0-to-v0.12.1/) | **bug fix + additive** (no source change) | `authmw`: a JWT the auth service rejects with 401 is **401, not 503** (and `FailOpen` no longer admits it); a definite 401 is cached as a negative; new opt-in `WithExpectedJWTAudience`, `RequireIdentity`, `IncludePermissions`, `WriteDenial`/`JSONDenial`, `APIKeyHeader`, `authmwtest`. Its checker lists `FailOpen` gates, JWT permissions read without `IncludePermissions`, and tests expecting 503 for a 401. See its `CLIENT_NOTICE.md`. |

## Automating the migration (optional)

The migration is fully self-serve from the files above — no special tooling required. Hand
`MIGRATION.md` + `migrate-check.sh` to any coding agent, or follow them yourself. Where a kit also
includes `agent-cycle-prompt.md`, paste that into any coding agent as a ready-made driver.

For Claude Code users, this repo also ships an optional packaged agent at
[`agent/migrationbot.md`](agent/migrationbot.md) that runs the whole check→fix→recheck→build loop and
writes a worklog. Copy it into wherever your setup keeps agents (`<your-service>/.claude/agents/` or
`~/.claude/agents/`), then run `@agent-migrationbot`. See [`agent/README.md`](agent/README.md) for
details — it lives in a plain tracked folder (not `.claude/`) so you place it where you want.
