---
name: auth-sdk-go-cli
description: Operate the ab0t-auth CLI — check and change authorization from a terminal or a script. Use when asked "can this user do that", when a permission check is denied and you need the reason, when granting or revoking access, when running an access review or offboarding someone, when diagnosing "it worked yesterday", when wiring an authorization gate into CI, when switching between tenants or environments (dev/prod), or when an agent needs to drive authorization non-interactively. Covers can/why/grant/revoke/revoke-all/who-can/what-can/orgs/org-tree/profile/doctor/health/about, exit codes, --json, --dry-run, --expires, profiles and environments.
---

# ab0t-auth — the CLI

```bash
go install github.com/ab0t-com/auth-sdk-go/cmd/ab0t-auth@latest
```

Zero dependencies — it pulls nothing else. Run `ab0t-auth` bare for the common
commands, `ab0t-auth help <verb>` for deep help on any one.

## The 30-second path

```bash
ab0t-auth health                       # is the service up? (no credential needed)
ab0t-auth login --key ab0t_sk_…        # or --email you@example.com
ab0t-auth doctor                       # confirm everything is wired
ab0t-auth can user:alice view doc:123 --store my-store
```

## Exit codes — the contract scripts depend on

```
0  success; for `can`, the answer was ALLOWED
1  error
2  the answer was DENIED
3  no credential, or it was rejected
```

```bash
if ab0t-auth can user:alice deploy service:api --store s; then
  ./deploy.sh
fi
```

> **Exit 2 is an ANSWER, not an error.** `set -e` and `set -o pipefail` will abort
> your script on a perfectly good DENIED. Capture it first:
> ```bash
> out=$(ab0t-auth can … --json); rc=$?
> ```

## The verbs, by the job

| Job | Command |
|---|---|
| May X do Y to Z? | `can <subject> <permission> <object> --store S` |
| **Why** was that the answer? | `why <subject> <permission> <object> --store S` |
| Give access | `grant <subject> <relation> <object> --store S` |
| Remove access | `revoke <subject> <relation> <object> --store S` |
| Offboard an object entirely | `revoke-all <object> --store S` |
| Who can see this? (access review) | `who-can <object> <permission> --store S` |
| What can they reach? (least privilege) | `what-can <subject> <permission> <type> --store S` |
| Which orgs am I in? | `orgs` |
| Show the company hierarchy | `org-tree <org-id>` |
| Switch tenant | `profile use <name>` |
| Why isn't it working? | `doctor` |
| Licence / support / SDK | `about` |

## Safety rails

**Rehearse every write.** `--dry-run` prints exactly what would change and sends
nothing:

```bash
ab0t-auth revoke-all doc:123 --store s --dry-run
DRY RUN — nothing was sent
  would remove 3 relationship(s) on doc:123
    owner  user:alice
    viewer group:eng
```

**Time-box temporary access.** Support grants become permanent by accident:

```bash
ab0t-auth grant user:contractor viewer doc:9 --store s --expires 24h
# or --expires 2026-08-01T00:00:00Z
```

## Tenants and environments

The service is multi-tenant; so is the CLI.

```bash
ab0t-auth --profile acme --env prod login --key ab0t_sk_…
ab0t-auth --profile acme --env dev  login --key ab0t_sk_…
ab0t-auth profile list          # * marks the current one
ab0t-auth profile use acme
```

Stored one file per tenant+environment at `$XDG_CONFIG_HOME/ab0t/auth-sdk-go/profiles/`,
0600 inside 0700, written atomically. **`--env` is what stops a dev credential
being used against production.**

Credential precedence: `--token` > `$AB0T_AUTH_TOKEN` > `$AUTH_SERVICE_KEY` > profile.
Profile: `--profile` > `$AB0T_PROFILE` > stored current > `default`.
`whoami` prints both the profile and the source — which is the answer to "why is it
using the wrong account".

## For agents and CI

- **`--json` on everything**, including `help --json` for the capability catalogue.
- **Never prompts without a non-interactive path** — `--password`, `--key`, `--yes`.
  A prompt that would block a non-TTY errors instead of hanging.
- **`NO_COLOR`** honoured; colour is never the only signal — every state is also a
  word, so piping, logs and screen readers lose nothing.
- Hints go to **stderr**, so `--json` on stdout is never contaminated.

```bash
ab0t-auth help --json | jq -r '.commands[].name'
ab0t-auth doctor --json | jq -e '.failed == 0'
```

## When it goes wrong

```bash
ab0t-auth doctor      # start here — checks URL, credential, permissions, reachability, validity
```

It reports **every** check rather than stopping at the first failure; the second
failure is often what explains the first.

| Symptom | Meaning |
|---|---|
| `is not a typed Zanzibar id` | use `user:alice`, not `alice` |
| `a store is required` | pass `--store` or set `$AB0T_ZANZIBAR_STORE` |
| DENIED you expected to be ALLOWED | run `why`; the relation may not confer that permission |
| 401 | credential expired — `ab0t-auth login` |
| 503 from your own gate | correct: the auth service was unreachable and you failed closed |

## See also

- `auth-sdk-go-concepts` — the model (two authz systems, typed ids, tenancy)
- `auth-sdk-go-integration` — the Go library
- `docs/CLI.md`, `docs/USAGE.md`
