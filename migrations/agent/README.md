# migrations/agent — optional Claude Code automation

`migrationbot.md` is a packaged [Claude Code](https://claude.com/claude-code) agent that runs a
version migration for you: check → fix → recheck → build, with an append-only worklog. It is
**optional** — every migration is fully doable from the kit itself (`../<FROM>-to-<TO>/MIGRATION.md`
+ `migrate-check.sh`, and `agent-cycle-prompt.md` where present) with any coding agent, or by hand.

This SDK ships the file here rather than assuming how you run Claude Code. **Copy it wherever your
setup keeps agents**, then invoke it:

- one service:  copy to `<your-service>/.claude/agents/migrationbot.md`
- all services: copy to `~/.claude/agents/migrationbot.md`

Then run `@agent-migrationbot` (or just "migrate my service to auth-sdk-go vX").

> Why copy? `go get` places this SDK in your Go module cache, not your project, so agent files here
> aren't auto-discovered by your editor. Copying is a one-time, explicit step — and it keeps this
> file out of your `.claude/` unless you choose to add it.

Not a Claude Code user? Ignore this folder entirely — the kit's `MIGRATION.md` and `migrate-check.sh`
are all you need.
