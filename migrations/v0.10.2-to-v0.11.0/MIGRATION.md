# Migration: auth-sdk-go v0.10.2 → v0.11.0

This release makes the client faithfully match the auth service's wire contract across ~25
endpoints (CLASS-34 "silent unknown-field drop"). Many SDK request/response structs previously
under-exposed, renamed, or mis-shaped fields the server actually accepts/returns — so calls
**hard-errored, silently validated the wrong thing, or dropped data**. The fixes are **breaking at
the Go source level**: several return types, struct fields, and one endpoint path changed. **None of
these require a server change** — they change how your Go code calls the SDK.

**This directory is a migration kit, not just notes.** Run the checker against your codebase and it
tells you exactly what to change — like a dependency bot, for this contract change:

```bash
# from your service's repo root:
/path/to/auth-sdk-go/migrations/v0.10.2-to-v0.11.0/migrate-check.sh .
```

It greps your Go files for every affected pattern and prints, per finding: the file:line, what it
is, and the exact replacement. It exits non-zero if anything needs changing, so you can gate CI on
it. It is **read-only** — it never edits your code.

**This kit has three pieces:** `migrate-check.sh` (the checker), this `MIGRATION.md` (details +
machine-applicable rules), and `agent-cycle-prompt.md` (a paste-ready prompt to drive the whole
check→fix→re-check→build loop with a coding agent).

> Upgrading from older than v0.10.2? Run each version's checker in order (v0.9.2→v0.10.0,
> v0.10.0→v0.10.1, then this one). Each kit catches only its own version's breaks.

---

## TL;DR — what changed

| # | Kind | Change | Your action |
|---|---|---|---|
| 1 | Return type | `ListOrgUsers` → `[]OrgMember` (was `*OrgUserResponse`; endpoint returns a bare array) | Drop `.Users`/`.Total`; range the slice |
| 2 | Return type | `GetLoginConfig`/`UpdateLoginConfig` → `*LoginConfig` (was `*LoginConfigResponse`) | Drop `.Config`; body is now section-nested |
| 3 | Return type | `ListOrgClients` → `[]OrgClientSafe` (was `*OrgClientSafeResponse`) | Drop `.Clients`/`.Total`; range the slice |
| 4 | Return type | `InviteToOrganization` → `*InviteResult` (was `*MessageResponse`) | Read `.InvitationCode` etc. |
| 5 | Return type + path | `WriteAndDeleteRelationships` → `*TransactResponse`, now `POST …/write` | Read `.Written`/`.Deleted`; no `.../transact` |
| 6 | Signature | `OrgHierarchyResponse.Children` `[]OrgHierarchyResponse`→`[]OrgHierarchyChild`; `WalkOrgTree` callback `func(*OrgInfo,int)` | Update the callback + child access |
| 7 | Arg type | `UpdateUser` takes `AdminUserUpdate` (was `UserUpdate`) | Wrap: `AdminUserUpdate{UserUpdate: …, Status: …}` |
| 8 | Nested rework | `LoginConfigUpdate`/`LoginConfig` are now 5 nested sections (branding/content/auth_methods/registration/security) | Nest fields by section |
| 9 | Rename | `OrgSession`: `.ID`→`.SessionID`, `.LastSeenAt`→`.LastAccessed`; `OrgSessionsResponse.Total`→`.TotalSessions`; `SessionRevokeResponse.RevokedCount`→`.SessionsRevoked` | Rename field access |
| 10 | Rename | `TeamMember`: `.AddedAt`→`.JoinedAt` (+`.TeamID`/`.Permissions`; `-.Email`/`-.Name`) | Rename; drop email/name |
| 11 | Rename | `OrganizationInvite.TeamIDs`→`.TeamID` (single); `+.Permissions`; `-.Resend` | Use one `TeamID`; drop `Resend` |
| 12 | Rename | providers: `.Type`→`.ProviderType`, `.Enabled`→`.IsActive` (on `ProviderConfigCreate/Update` + `Provider`) | Rename; provider-specific settings go in `Config` |
| 13 | Rename | `OrgMember.Permissions`→`.OrgPermissions` | Rename field access |
| 14 | Removed | `TokenValidationRequest.ResourceType`/`.ResourceID` (SECURITY: silently unscoped) | Delete; use `Authorize(…, Resource{…})` for resource scope |
| 15 | Removed | `OrganizationCreate.BillingType`, `OrganizationUpdate.BillingType`+`.Status` | Delete (billing_type is billing-owned; status not settable here) |
| 16 | Removed | `RegisterRequest.ProviderType`; `OrgRegisterRequest.FirstName`/`.LastName` | Delete (phantom); set `InvitationCode` where needed |
| 17 | Removed | `APIKeyCreate.OrgID`/`.Audience`; `APIKeyUpdate.Metadata`; `OrgRoleUpdate.Permissions` | Delete references (server ignored them) |
| 18 | Removed | provider top-level `.Domain`/`.IssuerURL` (`ProviderConfigCreate/Update`/`Provider`) — move into `Config` | Move to `Config` map |
| 19 | Removed | `ListAuthorizationModelsResponse.ContinuationToken` (server doesn't paginate) | Delete reference |

Additive (no action, just newly available): `RegisterRequest.InvitationCode`,
`APIKeyCreate.RateLimit`, DCR `ClientURI`/`TOSURI`/`SoftwareID`/`SoftwareVersion`,
`TeamPermissionsResponse.InheritedPermissions`, `Organization.AudienceStatus`, org profile fields
(`LogoURL`/`Website`/`Industry`/`Size`), `ReadRelationshipsForSubject`, and the model-assertions
surface (`PutModelAssertions`/`GetModelAssertions`/`RunModelAssertions`).

Full rationale per change is in `CHANGELOG.md` (the `[0.11.0]` section) and the ticket
`auth/output/tickets/20260907_class_sdk_api_struct_parity/`.

---

## 1. Org users — `ListOrgUsers` returns a slice (`orgs.go`)

The endpoint returns a **bare JSON array**, so decoding into an envelope struct hard-errored on
every call. `OrgUserResponse` is **removed**.

| Before (v0.10.2) | After (v0.11.0) |
|---|---|
| `resp, _ := c.ListOrgUsers(ctx, org, tok); for _, u := range resp.Users { … }` | `users, _ := c.ListOrgUsers(ctx, org, tok); for _, u := range users { … }` |
| `resp.Total` | `len(users)` |
| `u.Permissions` (member grants) | `u.OrgPermissions` |

## 2. Login config — nested sections, no wrapper (`hosted.go`)

The management API uses five nested sections and returns them at the top level; a flat body is
`400`-rejected. `LoginConfigResponse` is **removed**; `GetLoginConfig`/`UpdateLoginConfig` return
`*LoginConfig`.

```go
// Before: cfg, _ := c.GetLoginConfig(...); cfg.Config.LogoURL ; flat LoginConfigUpdate{LogoURL: …}
// After:
cfg, _ := c.GetLoginConfig(ctx, org, tok)                // *LoginConfig (sections at top level)
logo := cfg.Branding.LogoURL                             // *string
sig := true
c.UpdateLoginConfig(ctx, org, authclient.LoginConfigUpdate{
    AuthMethods: &authclient.LoginConfigAuthMethods{SignupEnabled: &sig},
}, tok)
```

## 3. Org clients — `ListOrgClients` returns a slice (`hosted.go`)

Bare array; `OrgClientSafeResponse` is **removed**. `resp.Clients` → range the returned
`[]OrgClientSafe`; `resp.Total` → `len(...)`.

## 4. Invitations — richer result + single team (`orgs.go`)

`InviteToOrganization` returns `*InviteResult` (was `*MessageResponse`) so you can read the
`InvitationCode` the invitee redeems. `OrganizationInvite.TeamIDs []string` → `TeamID string`;
`+Permissions []string`; `Resend` is **removed** (re-sends are deduped server-side).

```go
inv, _ := c.InviteToOrganization(ctx, org, authclient.OrganizationInvite{
    Email: e, Role: "member", TeamID: "team_1", Permissions: []string{"users.read"},
}, tok)
code := inv.InvitationCode   // pass to RegisterRequest.InvitationCode
```

## 5. Zanzibar transact — real path + counts (`authzmodel.go`)

`WriteAndDeleteRelationships` now `POST`s the **real** route `…/write` (the old
`…/relationships/transact` never existed → 404) and returns `*TransactResponse{Success, Message,
Written, Deleted, ConsistencyToken}`. The request tuple wire is `{object,relation,subject}` only —
`RelationshipRequest.Context`/`.ExpiresAt` are **not** supported on a transact write (use
`WriteRelationships` for an expiring/contextual grant).

## 6. Org hierarchy — flattened children (`orgs.go`)

Each child is a **flattened** org (fields inline) with its own `children`, not a nested
`{organization,…}`. `OrgHierarchyResponse.Children` is now `[]OrgHierarchyChild`, and `WalkOrgTree`
passes the node's `*OrgInfo`:

```go
// Before: h.WalkOrgTree(func(n *authclient.OrgHierarchyResponse, d int){ _ = n.Organization.ID })
h.WalkOrgTree(func(org *authclient.OrgInfo, d int) { _ = org.ID })   // uniform across root + children
```

## 7. Admin user status — `AdminUserUpdate` (`users.go`)

`UpdateUser` now takes `AdminUserUpdate` (embeds `UserUpdate` + `Status`); `/users/me` stays
`UserUpdate` (no status). Suspend/reactivate a user:

```go
st := "suspended"
c.UpdateUser(ctx, uid, authclient.AdminUserUpdate{
    UserUpdate: authclient.UserUpdate{Name: &nm}, Status: &st,
}, tok)
```

## 8. Sessions — field renames (`orgs.go`)

`OrgSession.ID`→`.SessionID`, `.LastSeenAt`→`.LastAccessed` (`.ExpiresAt` removed; `+UserEmail`,
`+UserName`); `OrgSessionsResponse.Total`→`.TotalSessions` (`+OrganizationID`);
`SessionRevokeResponse.RevokedCount`→`.SessionsRevoked`.

## 9. Team members / permissions (`orgs.go`)

`TeamMember.AddedAt`→`.JoinedAt` (`+TeamID`, `+Permissions`; `.Email`/`.Name` removed — the server
never sent them). `TeamPermissionsResponse` gains `.InheritedPermissions` (union it with
`.Permissions` for effective grants).

## 10. Providers (`providers.go`)

On `ProviderConfigCreate`, `ProviderConfigUpdate`, and the `Provider` response: `.Type`→
`.ProviderType`, `.Enabled`→`.IsActive`. Provider-specific settings (`client_id`, `client_secret`,
`issuer_url`, `domain`, …) now go **inside `Config map[string]any`** — the top-level
`ClientID`/`ClientSecret`/`IssuerURL`/`Domain` fields are removed. New: `Description`, `IsDefault`,
`Metadata`.

## 11. Removed phantom / ignored request fields

Delete these — the server ignored or 400-rejected them, so removing them changes no behaviour except
closing a footgun:

- `TokenValidationRequest.ResourceType`/`.ResourceID` — **security**: they were silently dropped, so
  a "resource-scoped" `ValidateToken` validated **unscoped**. For a real resource decision use
  `Authorize(ctx, token, action, authclient.Resource{Type: …, ID: …})`.
- `OrganizationCreate.BillingType`, `OrganizationUpdate.BillingType` — billing_type is **billing-
  owned by design** (a caller-set value would be self-serve tier escalation; goauth `create.go`
  forces PREPAID, `update` 400-rejects it). Put non-billing custom attributes in the org `Metadata`
  map. `OrganizationUpdate.Status` is also removed (not in the update schema).
- `RegisterRequest.ProviderType`; `OrgRegisterRequest.FirstName`/`.LastName`;
  `APIKeyCreate.OrgID`/`.Audience`; `APIKeyUpdate.Metadata`; `OrgRoleUpdate.Permissions` — all
  ignored by the server.
- `ListAuthorizationModelsResponse.ContinuationToken` — the server does not paginate this endpoint.

---

## Verify after migrating

```bash
go get github.com/ab0t-com/auth-sdk-go@v0.11.0 && go mod tidy
go build ./...    # rename/return-type errors surface here
go vet ./...
go test ./...     # re-run auth/session/org tests
```

Then run the checker again — it should report **0 findings**.

---

## Agent rules (machine-applicable)

A coding agent applies these as mechanical edits **on your call sites** (Go identifiers, word-
boundary aware). Confirm each against the checker's file:line output; some names are common, so
apply a rule only where the value's type is the named SDK type.

```
# return-type / envelope changes (rewrite the usage, not a rename)
ListOrgUsers:    *OrgUserResponse       -> []OrgMember          # .Users->range slice, .Total->len(), member .Permissions->.OrgPermissions
ListOrgClients:  *OrgClientSafeResponse -> []OrgClientSafe      # .Clients->range slice, .Total->len()
GetLoginConfig / UpdateLoginConfig: *LoginConfigResponse -> *LoginConfig   # drop .Config; LoginConfigUpdate is section-nested
InviteToOrganization: *MessageResponse  -> *InviteResult        # read .InvitationCode/.InvitationID/.ExpiresAt/.UserID
WriteAndDeleteRelationships: *WriteOperationResponse -> *TransactResponse   # POST .../write; read .Written/.Deleted; drop tuple Context/ExpiresAt
UpdateUser: 2nd arg UserUpdate -> AdminUserUpdate{UserUpdate: …, Status: …}
WalkOrgTree callback: func(*OrgHierarchyResponse,int) -> func(*OrgInfo,int)   # OrgHierarchyResponse.Children is now []OrgHierarchyChild
# selector renames (rename the field access on the named SDK type)
OrgSession.ID           -> .SessionID
OrgSession.LastSeenAt   -> .LastAccessed
OrgSessionsResponse.Total       -> .TotalSessions
SessionRevokeResponse.RevokedCount -> .SessionsRevoked
TeamMember.AddedAt      -> .JoinedAt          # .Email/.Name removed
OrgMember.Permissions   -> .OrgPermissions
OrganizationInvite.TeamIDs -> .TeamID (single); + .Permissions; remove .Resend
ProviderConfigCreate/Update/Provider: .Type -> .ProviderType ; .Enabled -> .IsActive
LoginConfigUpdate: flat fields -> nested sections (Branding/Content/AuthMethods/Registration/Security)
# removed (delete the reference; provider settings move into Config)
TokenValidationRequest.ResourceType / .ResourceID   # -> Authorize(…, Resource{…})
OrganizationCreate.BillingType ; OrganizationUpdate.BillingType ; OrganizationUpdate.Status
RegisterRequest.ProviderType ; OrgRegisterRequest.FirstName / .LastName
APIKeyCreate.OrgID / .Audience ; APIKeyUpdate.Metadata ; OrgRoleUpdate.Permissions
ProviderConfig*.ClientID/.ClientSecret/.IssuerURL/.Domain  # -> Config["client_id"] etc.
ListAuthorizationModelsResponse.ContinuationToken
```

> Caution for the agent: `.ID`, `.Total`, `.Type`, `.Enabled`, `.Status`, `.Permissions`,
> `.Metadata`, `.Domain` are common names. Apply a rule ONLY where the value's type is the SDK type
> named above — use the checker's file:line hits, don't blanket-replace.
