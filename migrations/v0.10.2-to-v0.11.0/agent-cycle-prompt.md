# Agent cycle prompt — auth-sdk-go v0.10.2 → v0.11.0

Paste the block below to a coding agent (Claude Code, etc.) running in **your service's repo**. It
drives the check → fix → re-check → build loop until clean. It edits only your call sites, never the
SDK. Set `KIT` to where this migration kit lives, then paste from `You are migrating…`.

```text
KIT=/absolute/path/to/auth-sdk-go/migrations/v0.10.2-to-v0.11.0

You are migrating this Go service from github.com/ab0t-com/auth-sdk-go v0.10.2 to v0.11.0.
Work on a new branch. Do NOT edit anything under the SDK module — only this repo's call sites and tests.

Reference (read once): $KIT/MIGRATION.md  (per-change before→after + a machine-applicable rule list).

Run this loop until it converges:

  1. CHECK. Run: $KIT/migrate-check.sh .
     It prints, per finding, a file:line and the exact fix, and exits 0 only when nothing remains.
     If it exits 0 with "No migration findings", go to step 4.

  2. FIX. For EACH finding block, apply the printed fix at that file:line:
       - RETURN-TYPE / ENVELOPE changes (rewrite the usage, not a rename):
           ListOrgUsers -> []OrgMember (drop .Users/.Total; member grants are .OrgPermissions),
           ListOrgClients -> []OrgClientSafe (drop .Clients/.Total),
           GetLoginConfig/UpdateLoginConfig -> *LoginConfig (drop .Config; LoginConfigUpdate is
             section-nested: Branding/Content/AuthMethods/Registration/Security with pointer fields),
           InviteToOrganization -> *InviteResult (read .InvitationCode),
           WriteAndDeleteRelationships -> *TransactResponse on POST .../write (read .Written/.Deleted).
       - ARG-TYPE change: UpdateUser's 2nd arg is AdminUserUpdate{UserUpdate: UserUpdate{...}, Status: &s}.
       - CALLBACK change: WalkOrgTree(func(org *OrgInfo, depth int){...}); Children is []OrgHierarchyChild.
       - SELECTOR renames (apply ONLY where the value's type is the named SDK type — these identifiers
         are common, do not blanket-replace): OrgSession .ID->.SessionID, .LastSeenAt->.LastAccessed;
         OrgSessionsResponse .Total->.TotalSessions; SessionRevokeResponse .RevokedCount->.SessionsRevoked;
         TeamMember .AddedAt->.JoinedAt (.Email/.Name gone); OrgMember .Permissions->.OrgPermissions;
         providers .Type->.ProviderType, .Enabled->.IsActive.
       - STRUCT-LITERAL field changes: OrganizationInvite TeamIDs->TeamID (single) + Permissions, drop
         Resend; ProviderConfigCreate/Update move ClientID/ClientSecret/IssuerURL/Domain into Config;
         OrganizationInvite/Create/Update per the notes.
       - REMOVED fields (delete the reference): TokenValidationRequest.ResourceType/.ResourceID (for a
         resource decision use Authorize(ctx, token, action, Resource{Type,ID})); OrganizationCreate/
         Update.BillingType and OrganizationUpdate.Status; RegisterRequest.ProviderType;
         OrgRegisterRequest.FirstName/.LastName; APIKeyCreate.OrgID/.Audience; APIKeyUpdate.Metadata;
         OrgRoleUpdate.Permissions; ListAuthorizationModelsResponse.ContinuationToken.

  3. RE-CHECK. Re-run step 1. If findings remain, repeat step 2. Never lower the bar to make it pass.

  4. BUILD + BUMP. Run:
       go get github.com/ab0t-com/auth-sdk-go@v0.11.0 && go mod tidy
       go build ./... && go vet ./... && go test ./...
     Fix any compiler errors (they name the remaining rename/return-type mismatch) and re-run.

  5. SECURITY REVIEW. For every removed TokenValidationRequest.ResourceType/.ResourceID: the old code
     BELIEVED it was scoping the check to a resource but the server ignored it (validated unscoped).
     If that call was meant to gate access to a specific resource, replace it with
     Authorize(ctx, token, action, Resource{Type: t, ID: id}) — do NOT just delete the fields and keep
     an unscoped ValidateToken as if it were scoped.

  6. REPORT. Summarise: files changed, each finding and how you fixed it, the final
     `migrate-check.sh .` output (must be "No migration findings"), and the go build/test result.
     Open a PR. Do NOT merge — a human reviews.

Stop conditions: migrate-check.sh exits 0 AND go build/vet/test are all green. If you cannot resolve
a finding, stop and report it with the file:line rather than guessing.
```

## Packaged agent
For Claude Code users, `migrations/agent/migrationbot.md` runs this same loop and writes a worklog —
copy it into your agents dir and run `@agent-migrationbot` (see `migrations/agent/README.md`).
