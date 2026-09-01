# migrations/

One directory per breaking upgrade, named `vFROM-to-vTO/`, each containing:

- **`MIGRATION.md`** — what changed, why, and before→after for every breaking change, plus an
  agent-applicable find→replace rule list.
- **`migrate-check.sh`** — a read-only checker: point it at your repo
  (`./migrate-check.sh /path/to/your/service`) and it prints every call site you must change, with
  the fix, and exits non-zero if any remain (gate CI on it). It never edits your code.

Upgrading across several versions? Run each version's checker in order.

## Automating the migration (optional)

The migration is fully self-serve from the files above — no special tooling required. Hand
`MIGRATION.md` + `migrate-check.sh` to any coding agent, or follow them yourself. Where a kit also
includes `agent-cycle-prompt.md`, paste that into any coding agent as a ready-made driver.

For Claude Code users, this repo also ships an optional packaged agent at
[`agent/migrationbot.md`](agent/migrationbot.md) that runs the whole check→fix→recheck→build loop and
writes a worklog. Copy it into wherever your setup keeps agents (`<your-service>/.claude/agents/` or
`~/.claude/agents/`), then run `@agent-migrationbot`. See [`agent/README.md`](agent/README.md) for
details — it lives in a plain tracked folder (not `.claude/`) so you place it where you want.
