#!/usr/bin/env bash
# migrate-check.sh — find every call site your codebase must change for auth-sdk-go v0.11.0.
#
# Read-only. Greps your Go files for the patterns affected by the v0.10.2 -> v0.11.0 breaking
# changes (CLASS-34 contract-fidelity) and prints, per finding, the file:line and the exact fix.
# Exits non-zero if anything needs changing (so you can gate CI on it). It NEVER edits your code.
#
# Usage:   ./migrate-check.sh [path-to-your-repo]      (default: current dir)
# See MIGRATION.md (same directory) for the full rationale and an agent-applicable rule list.

set -u
set -o pipefail

TARGET="${1:-.}"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
FOUND=0

if [ ! -d "$TARGET" ]; then echo "not a directory: $TARGET" >&2; exit 2; fi
GO_FILES="$(find "$TARGET" -name '*.go' -not -path '*/vendor/*' -not -path '*/.git/*' 2>/dev/null | wc -l)"
echo -e "${BOLD}auth-sdk-go v0.10.2 -> v0.11.0 migration check${NC}"
echo    "target: $TARGET  ($GO_FILES .go files)"
if [ "$GO_FILES" -eq 0 ]; then echo "no .go files under $TARGET — nothing to check."; exit 0; fi

# check <label> <fix-advice> <extended-regex>
check() {
  local label="$1" advice="$2" pat="$3"
  local hits
  hits="$(grep -rnE --include='*.go' --exclude-dir=vendor --exclude-dir=.git "$pat" "$TARGET" 2>/dev/null)" || true
  if [ -n "$hits" ]; then
    local n; n="$(printf '%s\n' "$hits" | grep -c .)"
    FOUND=$((FOUND + n))
    echo -e "\n${YELLOW}● ${label}${NC}  (${n})"
    echo -e "  ${BOLD}fix:${NC} ${advice}"
    printf '%s\n' "$hits" | sed 's/^/    /'
  fi
}

# ---- removed types (unambiguous — delete/replace) ----
check "Removed envelope types" \
  "OrgUserResponse -> ListOrgUsers now returns []OrgMember; LoginConfigResponse -> GetLoginConfig/UpdateLoginConfig return *LoginConfig; OrgClientSafeResponse -> ListOrgClients returns []OrgClientSafe." \
  '\b(OrgUserResponse|LoginConfigResponse|OrgClientSafeResponse)\b'
check "OrgHierarchyResponse used as a child element" \
  "Children is now []OrgHierarchyChild (a FLATTENED org + recursive children), not []OrgHierarchyResponse." \
  '\[\]OrgHierarchyResponse\b'

# ---- return-type / behavioural method call sites ----
check "ListOrgUsers — return type changed" \
  "returns []OrgMember (bare array). Drop .Users (range the slice) and .Total (len()); member grants moved to .OrgPermissions." \
  '\bListOrgUsers\('
check "ListOrgClients — return type changed" \
  "returns []OrgClientSafe (bare array). Drop .Clients (range the slice) and .Total (len())." \
  '\bListOrgClients\('
check "GetLoginConfig / UpdateLoginConfig — return type + nested body" \
  "return *LoginConfig (no .Config wrapper). LoginConfigUpdate is now 5 nested sections (Branding/Content/AuthMethods/Registration/Security); a flat body is 400-rejected." \
  '\b(GetLoginConfig|UpdateLoginConfig)\(|\bLoginConfigUpdate\{'
check "InviteToOrganization — return type changed" \
  "returns *InviteResult (was *MessageResponse). Read .InvitationCode / .InvitationID / .ExpiresAt / .UserID." \
  '\bInviteToOrganization\('
check "WriteAndDeleteRelationships — path + return type changed" \
  "now POSTs the real route .../write (not .../relationships/transact) and returns *TransactResponse (read .Written/.Deleted/.ConsistencyToken). Tuple wire is {object,relation,subject} ONLY — Context/ExpiresAt are dropped; use WriteRelationships for an expiring grant." \
  '\bWriteAndDeleteRelationships\('
check "UpdateUser — argument type changed" \
  "2nd arg is now AdminUserUpdate (embeds UserUpdate + Status). Wrap: AdminUserUpdate{UserUpdate: UserUpdate{...}, Status: &s}. (/users/me via UpdateMyProfile stays UserUpdate.)" \
  '\bUpdateUser\('
check "WalkOrgTree — callback signature changed" \
  "callback is now func(org *OrgInfo, depth int) (was func(node *OrgHierarchyResponse, depth int)); counts are a root-only field, read them from the response value." \
  '\bWalkOrgTree\('

# ---- selector renames (apply on the named SDK type only) ----
check "ListOrgSessions — response field renames" \
  "on the returned *OrgSessionsResponse: .Total -> .TotalSessions (+.OrganizationID). On each OrgSession: .ID -> .SessionID, .LastSeenAt -> .LastAccessed (.ExpiresAt removed; +UserEmail/UserName)." \
  '\bListOrgSessions\(|OrgSessionsResponse\b'
check "OrgSession.LastSeenAt -> .LastAccessed" \
  ".LastSeenAt -> .LastAccessed (OrgSession); .ExpiresAt on OrgSession is removed." \
  '\.LastSeenAt\b'
check "SessionRevokeResponse.RevokedCount -> .SessionsRevoked" \
  ".RevokedCount -> .SessionsRevoked (SessionRevokeResponse, from RevokeUserSessions)." \
  '\.RevokedCount\b'
check "TeamMember.AddedAt -> .JoinedAt" \
  ".AddedAt -> .JoinedAt (TeamMember); .Email/.Name are removed (server never sent them); .TeamID/.Permissions are new." \
  '\.AddedAt\b'
check "OrgMember.Permissions -> .OrgPermissions" \
  "on OrgMember (ListOrgUsers items) the member grants are .OrgPermissions (json org_permissions), not .Permissions." \
  '\bOrgMember\b'

# ---- struct literals needing field changes ----
check "OrganizationInvite — TeamIDs -> TeamID, +Permissions, -Resend" \
  "TeamIDs []string -> TeamID string (single); add Permissions []string; remove Resend." \
  'OrganizationInvite\{|\.TeamIDs\b'
check "ProviderConfigCreate / ProviderConfigUpdate — Type/Enabled + settings->Config" \
  "Type -> ProviderType; Enabled -> IsActive; move ClientID/ClientSecret/IssuerURL/Domain into Config map; new Description/IsDefault/Metadata." \
  'ProviderConfig(Create|Update)\{'
check "Provider (response) — Type/Enabled/Domain/IssuerURL" \
  "on Provider values: .Type -> .ProviderType; .Enabled -> .IsActive; top-level .Domain/.IssuerURL are gone (they live in .Config)." \
  '\bProvider\{|\.IssuerURL\b'
check "RegisterRequest — ProviderType removed" \
  "remove ProviderType (server ignores it; provider is always internal here). To join an org by invite, set InvitationCode." \
  'RegisterRequest\{'
check "OrgRegisterRequest — FirstName/LastName removed" \
  "remove FirstName/LastName (server reads only Name). ClientID and InvitationCode are now available." \
  'OrgRegisterRequest\{'
check "APIKeyCreate — OrgID/Audience removed, RateLimit added" \
  "remove OrgID/Audience (server ignored them). You can now set RateLimit *int64 at create." \
  'APIKeyCreate\{'
check "APIKeyUpdate — Metadata removed" \
  "remove Metadata (server ignores it on update)." \
  'APIKeyUpdate\{'
check "OrgRoleUpdate — Permissions removed" \
  "remove Permissions (the role-update handler reads only Role; member perms are set via invite/team)." \
  'OrgRoleUpdate\{'
check "OrganizationCreate / OrganizationUpdate — BillingType/Status removed" \
  "remove BillingType (billing-owned by design; put non-billing attrs in Metadata) and, on Update, Status (not in the update schema). New: LogoURL/Website/Industry/Size; Update also gains Slug/ParentID." \
  'Organization(Create|Update)\{|\.BillingType\b'

# ---- security-relevant removal ----
check "TokenValidationRequest.ResourceType/.ResourceID removed (SECURITY)" \
  "these were SILENTLY DROPPED by the server -> a resource-scoped ValidateToken validated UNSCOPED. Remove them; for a real resource decision use Authorize(ctx, token, action, Resource{Type:.., ID:..})." \
  'ResourceType:|ResourceID:|\.ResourceType\b|\.ResourceID\b'

# ---- removed response field ----
check "ListAuthorizationModelsResponse.ContinuationToken removed" \
  "the server does not paginate this endpoint; delete the reference (the list is the full set)." \
  'ListAuthorizationModelsResponse\b'

echo
echo "======================================================"
if [ "$FOUND" -eq 0 ]; then
  echo -e "${GREEN}No migration findings.${NC} Your call sites look compatible with v0.11.0."
  echo "Still run: go build ./... && go vet ./... && go test ./..."
  exit 0
else
  echo -e "${RED}${FOUND} candidate site(s) to review/change for v0.11.0.${NC}"
  echo "Each block above shows the fix. Some patterns (.ID, .Total, .Type, .Enabled, .Status, .BillingType,"
  echo "ResourceType/ResourceID) are common names — apply a change only where the value's type is the SDK"
  echo "type named in the fix. Then re-run this checker (expect 0) and: go build ./... && go test ./..."
  exit 1
fi
