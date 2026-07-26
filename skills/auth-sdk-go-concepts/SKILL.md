---
name: auth-sdk-go-concepts
description: The mental model for the ab0t Auth Service — the TWO authorization systems (account/RBAC vs Zanzibar/ReBAC) and when to use which, typed ids ("user:alice" not "alice"), stores, relations vs permissions, nested organizations and companies-of-companies, teams, workspaces, users belonging to many orgs, and per-tenant hosted login. Use when deciding how to model permissions, when a check returns DENIED and you do not know why, when designing multi-tenant access, when "I granted owner but view is still denied", when choosing between roles and per-object sharing, or before writing the first line of authorization code against ab0t auth.
---

# ab0t Auth — the mental model

Read this before modelling anything. Most authorization bugs against this service
are not bugs; they are one of four concepts applied in the wrong place.

## 1. There are TWO authorization systems. Pick deliberately.

| | Account / RBAC | Zanzibar / ReBAC |
|---|---|---|
| Endpoint family | `/permissions/check`, `/auth/validate-token` | `/zanzibar/stores/{store_id}/…` |
| Identity shape | `user_id` | combined typed string — `user:alice` |
| The question | "does this user hold this permission?" | "does this subject have this relation to **this object**?" |
| Vocabulary | dot scopes — `users.write`, `org.admin` | relations — `owner`, `member`, `viewer` |
| Use for | coarse capability: is this an admin? | per-object sharing: who can see **document 123** |
| Go | `client.Authorize(ctx, tok, "admin.write", Resource{...})` | `client.Store(id, tok).Can(ctx, "user","alice","view","doc","123")` |

**Rule of thumb:** if the answer depends on *which object*, it is ReBAC. If it is
true everywhere in the org, it is RBAC.

Cross-wiring these is the single most common and most expensive mistake — it is
usually discovered months later, in production, as "permissions don't work".

**Scopes are dot-delimited.** `users.write`, `org.admin`, `admin.jwks.read`. Not
colons. (Some older docs elsewhere show `users:read` — that is wrong for this
service; the spec contains zero colon-style scopes.)

## 2. Zanzibar ids are TYPED

```
user:alice        doc:123        group:eng        group:eng#member
```

`alice` alone is rejected — deliberately. The service cannot tell whether you mean
a user, a team or a service account, and **guessing would produce a silent wrong
DENY**, which is indistinguishable from a real authorization decision and gets
debugged in entirely the wrong place.

```go
auth.Subject("user", "alice")   // "user:alice"
auth.Object("doc", "123")       // "doc:123"
```

The SDK rejects untyped ids **before sending**, with `*auth.ErrUntypedID`.

## 3. A RELATION is not a PERMISSION

This is the "I granted owner but view is still denied" trap.

- You **grant a relation**: `user:alice —owner→ doc:123`
- You **check a permission**: can `user:alice` `view` `doc:123`?

The service *derives* permissions from relations via the store's authorization
model. Granting `owner` only implies `view` if the model says so. When a grant
appears not to work, run `why` — it returns the reasoning and the relationship
path it followed.

## 4. A store is the permissions database for your app

`--store` / the `storeID` argument is required and is not a tuning knob. All
relationships live inside one store.

**The multi-tenant decision nobody warns you about:** a tuple names `user:alice`,
and that id carries **no tenant**. So if one store spans several organizations, a
user who "moves" between orgs keeps their relationships — nothing about
`user:alice` changed. Isolation must come from either:

- **one store per tenant** (simplest, strongest), or
- **tenant-qualified object ids** — `doc:acme/123`.

Both are legal, so no client can detect the unsafe choice for you. Decide it
explicitly, write it down, and do not mix the two.

## 5. Organizations nest — companies of companies

`Organization.parent_id` is real. The hierarchy is a **tree**:

```
organization : OrgInfo          (id, name, slug, parent_id, …)
teams        : [HierarchyTeam]  → members: [HierarchyUser{id, type, role}]
children     : [OrgHierarchyResponse]   ← SUB-ORGANIZATIONS, recursive
user_count, team_count
```

A holding company owning operating companies owning teams is natively
expressible. There is also a third grouping axis — **workspace**
(`workspace_type`, `workspace_id`).

```go
h, _ := client.GetOrgHierarchy(ctx, orgID, token)
h.WalkOrgTree(func(n *auth.OrgHierarchyResponse, depth int) { ... })
```

## 6. A user belongs to MANY organizations

`GET /users/me/organizations` returns, per membership: `role`, `is_personal`,
`is_default`, `parent_id`, `workspace_type`. The same human is `admin` in one org
and `member` in another. `POST /auth/switch-organization` changes the **active org
for a session** — identity is stable, tenancy is contextual.

## 7. Two hierarchies that are NOT the same

| Account hierarchy | Zanzibar hierarchy |
|---|---|
| `/organizations/{id}/hierarchy`, `parent_id` | `/zanzibar/stores/{id}/hierarchy/setup` |
| orgs → teams → users | objects via relationships |
| "who is in this company" | "who can act on this thing" |

**Org membership is not automatically a relationship.** The service provides
`hierarchy/setup` and `teams/membership` to *project* the account hierarchy into
the ReBAC store — meaning the two can drift, and nothing reconciles them for you.

## 8. Per-tenant hosted login exists

Keyed by org **slug**: `/organizations/{slug}/auth/{register,login,refresh,logout,
reset-password,providers,sso/initiate,sso/callback,token}`, plus
`login-config/public`, per-org email templates, and **per-org JWKS — each tenant
can sign its own tokens**.

If you are building SaaS on the mesh, you do not need to build signup, login, SSO
or password reset. Most consumers do not know this exists.

## 9. Fail closed, always

`Authorize` returns `(false, err)` on any failure. Treat an error as **"I could not
decide"**, not as "no" and never as "yes":

- deny → **403**
- error → **503**

A gate that allows on error turns an auth-service blip into an open door, quietly,
because the requests succeed and nothing pages anyone.

## See also

- `auth-sdk-go-cli` — the `ab0t-auth` command line
- `auth-sdk-go-integration` — wiring the Go library into a service
- `docs/USAGE.md` — the cookbook
