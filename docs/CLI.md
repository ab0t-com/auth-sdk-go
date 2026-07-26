# CLI reference

Complete command and flag reference. For task-shaped recipes see
[`USAGE.md`](USAGE.md); for deep per-verb help the binary itself is authoritative:

```bash
ab0t-auth help <verb>      # purpose, worked example, failure modes, what's next
ab0t-auth <verb> --help    # the same, plus the flag list
ab0t-auth help --json      # the whole catalogue as data
```

## Global flags

Accepted **before or after** the verb.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--server URL` | — | production | Auth service base URL |
| `--token VALUE` | `AB0T_AUTH_TOKEN`, `AUTH_SERVICE_KEY` | stored profile | Credential to use |
| `--profile NAME` | `AB0T_PROFILE` | stored current, else `default` | Tenant context |
| `--env NAME` | `AB0T_ENV` | none | Environment isolation (dev/prod/…) |
| `--store ID` | `AB0T_ZANZIBAR_STORE` | — | Zanzibar store (required by authz verbs) |
| `--json` | — | off | Machine-readable output, stable shape |
| `--quiet` | — | off | Suppress non-essential output; errors still shown |
| `--no-color` | `NO_COLOR` | auto | Disable colour entirely |
| `--color` | — | off | Force colour even when not a terminal |
| `--timeout DUR` | — | `30s` | Overall request timeout |
| `--dry-run` | — | off | *(write verbs)* show what would change, send nothing |
| `--expires` | — | none | *(grant)* duration `24h` or RFC3339 |
| `--yes`, `-y` | — | off | *(destructive verbs)* skip confirmation |

## Commands

| Verb | Arguments | Purpose |
|---|---|---|
| `login` | `--key` \| `--email --password [--org]` | Authenticate, store a credential |
| `logout` | `[--yes]` | Remove the stored credential (local only) |
| `whoami` | — | Identity, tenant profile, and credential source |
| `can` | `<subject> <permission> <object>` | May this subject act on this object? |
| `why` | `<subject> <permission> <object>` | The reason and relationship path |
| `who-can` | `<object> <permission>` | Access review — who can reach this |
| `what-can` | `<subject> <permission> <type>` | Least privilege — what they reach |
| `grant` | `<subject> <relation> <object>` | Create a relationship |
| `revoke` | `<subject> <relation> <object>` | Remove a relationship |
| `revoke-all` | `<object>` | Remove **every** relationship on an object |
| `orgs` | — | Organizations this credential belongs to |
| `org-tree` | `<org-id>` | Organization hierarchy, indented |
| `profile` | `list` \| `use <n>` \| `remove <n>` | Tenant profiles |
| `health` | — | Is the service up? (no credential) |
| `doctor` | — | Diagnose config and connectivity |
| `about` | — | Licence, source, support, Go SDK |
| `version` | `[--json]` | Version |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success; for `can`, **ALLOWED** |
| `1` | Error — bad usage, network failure, service error |
| `2` | **DENIED** |
| `3` | No credential, or it was rejected |

`can` carries its answer in the exit code so `if ab0t-auth can …; then` works.
**Exit 2 is an answer, not an error** — capture it before `set -e` sees it.

## Output contract

- **stdout** carries data; **stderr** carries diagnostics and next-step hints. So
  `cmd --json > out.json` yields a parseable file and you still see errors.
- `--json` is a **stable shape** and never contains ANSI.
- **Colour is never the only signal** — every state is also a word.
- `NO_COLOR` (any non-empty value) disables ANSI entirely; so does a non-TTY,
  `TERM=dumb`, and `--json`.
- No spinners, progress bars, cursor movement or redrawing anywhere.

## Storage

```
$XDG_CONFIG_HOME/ab0t/auth-sdk-go/     0700
  config.json                          0600   { "current_profile": "acme" }
  profiles/<profile>[.<env>].json      0600   token + org + slug + service
```

Atomic writes; permissions re-asserted on every write. A legacy `auth.json` is
imported as `default` and renamed aside, never deleted.
