# USAGE — the cookbook

Task-shaped recipes for the ab0t auth SDK and CLI. For the mental model read
[`skills/auth-sdk-go-concepts`](../skills/auth-sdk-go-concepts/SKILL.md) first — most
problems here are a concept in the wrong place, not a bug.

- [1. Install](#1-install)
- [2. First success in five minutes](#2-first-success-in-five-minutes)
- [3. Ask an authorization question](#3-ask-an-authorization-question)
- [4. Grant and revoke access](#4-grant-and-revoke-access)
- [5. Access review and least privilege](#5-access-review-and-least-privilege)
- [6. Offboarding](#6-offboarding)
- [7. Tenants and environments](#7-tenants-and-environments)
- [8. Organizations, hierarchy and teams](#8-organizations-hierarchy-and-teams)
- [9. Gate an HTTP service](#9-gate-an-http-service)
- [10. CI and automation](#10-ci-and-automation)
- [11. Agents](#11-agents)
- [12. Troubleshooting](#12-troubleshooting)

---

## 1. Install

```bash
# CLI
go install github.com/ab0t-com/auth-sdk-go/cmd/ab0t-auth@latest

# Library
go get github.com/ab0t-com/auth-sdk-go
```

Both pull **nothing else**. `go list -m all` after installing shows one module.

## 2. First success in five minutes

```bash
ab0t-auth health                       # 1. is the service up? no credential needed
ab0t-auth login --key ab0t_sk_…        # 2. store a credential
ab0t-auth doctor                       # 3. confirm everything is wired
export AB0T_ZANZIBAR_STORE=my-store    # 4. stop repeating --store
ab0t-auth can user:alice view doc:123  # 5. your first question
```

Expect `DENIED  user:alice view doc:123 / reason: no relation` — **that is a correct
answer**, not a failure. Nothing has been granted yet.

## 3. Ask an authorization question

```bash
ab0t-auth can user:alice view doc:123
ab0t-auth why user:alice view doc:123     # the reason, and the path it followed
```

Ids are typed: `user:alice`, never `alice`. See
[concepts §2](../skills/auth-sdk-go-concepts/SKILL.md).

In Go:

```go
store := client.Store(storeID, callerToken)
ok, err := store.Can(ctx, "user", "alice", "view", "doc", "123")
if err != nil { return errUnavailable }   // 503 — NOT "denied"
if !ok       { return errForbidden }      // 403
```

## 4. Grant and revoke access

**Rehearse first.** Every write takes `--dry-run`:

```bash
ab0t-auth grant user:alice owner doc:123 --dry-run
DRY RUN — nothing was sent
  would grant: user:alice owner doc:123  (store my-store)

ab0t-auth grant user:alice owner doc:123
ab0t-auth can   user:alice view  doc:123     # ALWAYS verify — this is your evidence
```

**Time-box temporary access**, or it becomes permanent:

```bash
ab0t-auth grant user:contractor viewer doc:9 --expires 24h
ab0t-auth grant user:contractor viewer doc:9 --expires 2026-08-01T00:00:00Z
```

**"I granted owner but view is still denied."** A relation is not a permission —
run `why`. The store's model decides which relations confer which permissions.

## 5. Access review and least privilege

```bash
# Who can see this? (groups expanded to people — what an auditor asks for)
ab0t-auth who-can doc:123 view

# What can this principal reach? (per object TYPE — run once per type)
ab0t-auth what-can user:svc-billing view invoice
```

Export for an auditor:

```bash
for obj in $(cat sensitive-objects.txt); do
  ab0t-auth who-can "$obj" view --json
done | jq -s --arg at "$(date -u +%FT%TZ)" '{generated_at:$at, review:.}' > review.json
```

> `what-can` answers **per object type** and cannot enumerate the types for you —
> take that list from your own schema.

## 6. Offboarding

```bash
ab0t-auth revoke-all doc:123 --dry-run   # see exactly what would go
ab0t-auth revoke-all doc:123
ab0t-auth who-can doc:123 view           # confirm it is empty
```

For a **person** rather than an object, enumerate per type first:

```bash
for t in doc invoice project; do
  ab0t-auth what-can user:leaver view "$t" --json | jq -r '.objects[]'
done | while read -r obj; do ab0t-auth revoke user:leaver viewer "$obj"; done
```

> This loop's completeness depends on you knowing every object type. A true
> per-principal revoke needs a service capability that does not exist yet.

## 7. Tenants and environments

```bash
ab0t-auth --profile acme --env prod login --key ab0t_sk_PROD
ab0t-auth --profile acme --env dev  login --key ab0t_sk_DEV
ab0t-auth profile list
ab0t-auth profile use acme
ab0t-auth --profile other --env prod whoami     # one-off, no switch
```

Stored one file per tenant+environment, 0600 in 0700, written atomically:

```
$XDG_CONFIG_HOME/ab0t/auth-sdk-go/
  config.json                 { "current_profile": "acme" }
  profiles/acme-prod.json
  profiles/acme-dev.json
```

`--env` is what stops a dev credential reaching production. `whoami` prints the
profile **and** the source — the answer to "why is it using the wrong account" is
almost always an environment variable shadowing the profile.

## 8. Organizations, hierarchy and teams

```bash
ab0t-auth orgs                 # your memberships, with role and markers
ab0t-auth org-tree org_01H8XK  # sub-organizations, indented
```

```
acme        org_01H8XK  (teams 4, users 37)
  acme-eu   org_01H9YZ  (teams 2, users 11)
  acme-apac org_01HBBB  (teams 1, users 6)
```

```go
h, _ := client.GetOrgHierarchy(ctx, orgID, token)
h.WalkOrgTree(func(n *auth.OrgHierarchyResponse, depth int) {
    fmt.Printf("%s%s users=%d\n", strings.Repeat("  ", depth), n.Organization.Slug, n.UserCount)
})
```

> Org membership is **not** automatically a Zanzibar relationship. The service
> offers projection endpoints; they are not run for you, so the two can drift.

## 9. Gate an HTTP service

```go
gate := &authmw.Gate{V: client, A: client}
mux.Handle("POST /admin", gate.Require("admin.write", "service", adminHandler))
http.ListenAndServe(":8080", gate.Authenticate(mux))
```

Test all three outcomes — **especially the third**:

```go
for name, f := range map[string]*authclienttest.Fake{
    "allow": authclienttest.Allow(), "deny": authclienttest.Deny(),
    "unavailable": authclienttest.Unavailable(),
} { /* assert 200 / 403 / 503 */ }
```

## 10. CI and automation

```yaml
- name: verify the deploy identity still has access
  run: |
    if ! ab0t-auth can service:ci deploy env:production --store prod; then
      echo "::error::CI identity lost deploy permission"; exit 1
    fi
  env:
    AB0T_AUTH_TOKEN: ${{ secrets.AB0T_AUTH_TOKEN }}
    AB0T_ZANZIBAR_STORE: prod
```

Exit codes: `0` allowed · `1` error · `2` denied · `3` no credential.

> **`set -e` / `pipefail` will abort on a legitimate DENIED.** Capture first:
> `out=$(ab0t-auth can … --json); rc=$?`

A preflight that fails the build on misconfiguration:

```bash
ab0t-auth doctor --json | jq -e '.failed == 0'
```

## 11. Agents

```bash
ab0t-auth help --json                    # the whole capability catalogue as data
ab0t-auth help can --json                # one verb: purpose, example, failures, next
ab0t-auth can … --json 2>/dev/null       # stdout is pure JSON; hints go to stderr
ab0t-auth doctor --json                  # self-diagnose before escalating
```

No command prompts without a non-interactive path. `NO_COLOR` is honoured and
colour is never the only signal, so nothing is lost to a log or a screen reader.

## 12. Troubleshooting

**Always start here:**

```bash
ab0t-auth doctor
```

| Symptom | Cause | Fix |
|---|---|---|
| `is not a typed Zanzibar id` | missing type prefix | `user:alice`, not `alice` |
| `a store is required` | no store selected | `--store` or `$AB0T_ZANZIBAR_STORE` |
| DENIED you expected ALLOWED | relation does not confer that permission | `ab0t-auth why …` |
| 401 | credential expired or revoked | `ab0t-auth login` |
| wrong account being used | env var shadowing the profile | `ab0t-auth whoami` — read `source:` |
| script aborts on a denial | exit 2 under `set -e` | capture into a variable first |
| granted, but access remains after revoke | another path — a group or second relation | `ab0t-auth why …`, read the path |
| your gate returns 503 | auth service unreachable, failing closed | correct behaviour; check `health` |

**Getting help:** `ab0t-auth about` prints the licence, source, issue tracker and
security contact.
