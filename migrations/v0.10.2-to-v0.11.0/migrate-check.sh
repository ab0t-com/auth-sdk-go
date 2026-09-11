#!/usr/bin/env bash
# migrate-check.sh — find every call site your codebase must change for auth-sdk-go v0.11.0.
#
# Read-only. Reports, per finding, the file:line and the exact fix for the v0.10.2 -> v0.11.0
# breaking changes (CLASS-34 contract-fidelity). Exits non-zero if anything HIGH-confidence
# needs changing (so you can gate CI on it). It NEVER edits your code.
#
# PRECISION (why this does not false-red):
#   Earlier versions grepped BARE identifiers (ResourceType, .Type, .Enabled, TeamIDs,
#   RevokedCount). On a real consumer those match the consumer's OWN identically-named
#   struct fields -> 100% false positives, so the check could NEVER exit 0. This version is
#   SDK-TYPE-PRECISE:
#     1. It only looks at .go files that actually import github.com/ab0t-com/auth-sdk-go,
#        and it resolves that import's LOCAL ALIAS per file (default package name: authclient).
#     2. Type usages are matched ALIAS-QUALIFIED (e.g. auth.TokenValidationRequest{), never
#        as a bare token, so your own Provider/ResourceType/TeamIDs can't trip it.
#     3. For types that SURVIVE v0.11.0 with renamed/removed FIELDS, it opens the composite
#        literal and only fires when a genuinely-removed field is set inside it — so a
#        correctly-migrated auth.TokenValidationRequest{...} stays green.
#     4. Bare selector renames that need real type resolution (e.g. resp.RevokedCount on a
#        value returned by the SDK) are emitted separately as REVIEW hits (gated on a
#        co-occurring SDK token). REVIEW hits are advisory and do NOT affect the exit code.
#   Result: green on an already-migrated consumer, red on an unmigrated one.
#
# Usage:   ./migrate-check.sh [path-to-your-repo]      (default: current dir)
# See MIGRATION.md (same directory) for the full rationale and an agent-applicable rule list.

set -u
set -o pipefail

TARGET="${1:-.}"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
FOUND=0        # HIGH-confidence hits — these set the exit code
REVIEW=0       # advisory hits — informational only

if [ ! -d "$TARGET" ]; then echo "not a directory: $TARGET" >&2; exit 2; fi
GO_FILES="$(find "$TARGET" -name '*.go' -not -path '*/vendor/*' -not -path '*/.git/*' 2>/dev/null | wc -l)"
echo -e "${BOLD}auth-sdk-go v0.10.2 -> v0.11.0 migration check${NC}"
echo    "target: $TARGET  ($GO_FILES .go files)"
if [ "$GO_FILES" -eq 0 ]; then echo "no .go files under $TARGET — nothing to check."; exit 0; fi

SDK_PATH_RE='"github\.com/ab0t-com/auth-sdk-go"'

# ---- 1. Resolve the SDK-importing files and each one's local import alias. --------------
# Emits "path<TAB>alias" per file. alias="" means a dot-import (bare symbols); blank
# imports ("_") are skipped (no symbols are referenced through them).
SDK_FILES_TMP="$(mktemp)"
trap 'rm -f "$SDK_FILES_TMP"' EXIT
while IFS= read -r f; do
  [ -n "$f" ] || continue
  aln="$(grep -E "$SDK_PATH_RE" "$f" 2>/dev/null | head -1 \
         | sed -E 's#"github\.com/ab0t-com/auth-sdk-go".*##; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  [ -z "$aln" ] && aln="authclient"
  [ "$aln" = "_" ] && continue
  [ "$aln" = "." ] && aln=""
  printf '%s\t%s\n' "$f" "$aln"
done < <(grep -rlE "$SDK_PATH_RE" --include='*.go' --exclude-dir=vendor --exclude-dir=.git "$TARGET" 2>/dev/null) > "$SDK_FILES_TMP"

SDK_FILE_COUNT="$(grep -c . "$SDK_FILES_TMP" 2>/dev/null || echo 0)"
echo    "SDK-importing files: $SDK_FILE_COUNT"
if [ "$SDK_FILE_COUNT" -eq 0 ]; then
  echo
  echo -e "${GREEN}No file imports github.com/ab0t-com/auth-sdk-go — nothing to migrate.${NC}"
  exit 0
fi

# ---- helpers ---------------------------------------------------------------------------

# grep_sdk <ere-with-@Q@> : run an alias-qualified regex across SDK files. @Q@ is replaced
# per-file with "<alias>\." (or "" for a dot-import). Prints file:line:content.
grep_sdk() {
  local pat="$1" f a p
  while IFS=$'\t' read -r f a; do
    [ -n "$f" ] || continue
    if [ -n "$a" ]; then p="${pat//@Q@/${a}\\.}"; else p="${pat//@Q@/}"; fi
    grep -nHE "$p" "$f" 2>/dev/null || true
  done < "$SDK_FILES_TMP"
}

# emit_high <label> <advice> <hits>
emit_high() {
  local label="$1" advice="$2" hits="$3" n
  [ -n "$hits" ] || return 0
  n="$(printf '%s\n' "$hits" | grep -c .)"
  FOUND=$((FOUND + n))
  echo -e "\n${YELLOW}● ${label}${NC}  (${n})"
  echo -e "  ${BOLD}fix:${NC} ${advice}"
  printf '%s\n' "$hits" | sed 's/^/    /'
}

# check_symbol <label> <advice> <ere-with-@Q@>  — alias-qualified type/symbol usage (HIGH).
check_symbol() { emit_high "$1" "$2" "$(grep_sdk "$3")"; }

# check_method <label> <advice> <method-ere>  — a call to a method whose signature/return
# changed. Matched in SDK files as (.|start)Method( ; the SDK Client is the receiver.
check_method() { emit_high "$1" "$2" "$(grep_sdk "(^|[^A-Za-z0-9_])($3)\\(")"; }

# check_litfield <label> <advice> <TypeName> <removed-field-ere>  (HIGH)
# Opens each <alias>.<TypeName>{ ... } composite literal (single- or multi-line) and fires
# only on lines that set one of the removed fields inside it. A migrated literal that no
# longer sets those fields stays green.
check_litfield() {
  local label="$1" advice="$2" T="$3" F="$4" f a hits="" h
  while IFS=$'\t' read -r f a; do
    [ -n "$f" ] || continue
    h="$(awk -v alias="$a" -v type="$T" -v fre="$F" '
      function braces(s,  t,o,c){ t=s; o=gsub(/{/,"",t); t=s; c=gsub(/}/,"",t); return o-c }
      function hasfield(s){ return match(s, "(^|[^A-Za-z0-9_.])(" fre ")[[:space:]]*:") }
      BEGIN{
        if (alias!="") opener = alias "[.]" type "[{]"
        else           opener = "(^|[^A-Za-z0-9_.])" type "[{]"
      }
      {
        if (inlit==0) {
          if (match($0, opener)) {
            after = substr($0, RSTART + RLENGTH - 1)   # from the "{" onward
            inlit = 1; depth = braces(after)
            if (hasfield(after)) print FILENAME ":" FNR ":" $0
            if (depth <= 0) inlit = 0
          }
        } else {
          depth += braces($0)
          if (hasfield($0)) print FILENAME ":" FNR ":" $0
          if (depth <= 0) inlit = 0
        }
      }
    ' "$f" 2>/dev/null)" || true
    [ -n "$h" ] && hits+="$h"$'\n'
  done < "$SDK_FILES_TMP"
  emit_high "$label" "$advice" "$(printf '%s' "$hits" | grep -c . >/dev/null 2>&1 && printf '%s' "$hits")"
}

# check_review <label> <advice> <selector-ere> <gate-ere>  (ADVISORY, does not gate CI)
# For bare selector renames on SDK-returned values (real type resolution needed). Only
# fires in an SDK file that ALSO mentions a distinctive owning SDK token (gate), so a
# consumer's own same-named field never surfaces.
check_review() {
  local label="$1" advice="$2" sel="$3" gate="$4" f a hits="" h n
  while IFS=$'\t' read -r f a; do
    [ -n "$f" ] || continue
    grep -qE "$gate" "$f" 2>/dev/null || continue
    h="$(grep -nHE "$sel" "$f" 2>/dev/null)" || true
    [ -n "$h" ] && hits+="$h"$'\n'
  done < "$SDK_FILES_TMP"
  hits="$(printf '%s' "$hits" | grep -c . >/dev/null 2>&1 && printf '%s' "$hits")"
  [ -n "$hits" ] || return 0
  n="$(printf '%s\n' "$hits" | grep -c .)"
  REVIEW=$((REVIEW + n))
  echo -e "\n${CYAN}? REVIEW — ${label}${NC}  (${n})"
  echo -e "  ${BOLD}verify:${NC} ${advice}"
  printf '%s\n' "$hits" | sed 's/^/    /'
}

# ========================================================================================
# HIGH-confidence rules (set the exit code)
# ========================================================================================

# ---- removed types (unambiguous — alias-qualified) ----
check_symbol "Removed envelope types" \
  "OrgUserResponse -> ListOrgUsers now returns []OrgMember; LoginConfigResponse -> GetLoginConfig/UpdateLoginConfig return *LoginConfig; OrgClientSafeResponse -> ListOrgClients returns []OrgClientSafe." \
  '@Q@(OrgUserResponse|LoginConfigResponse|OrgClientSafeResponse)\b'
check_symbol "OrgHierarchyResponse used as an element/callback type" \
  "Children is now []OrgHierarchyChild (a FLATTENED org + recursive children), not []OrgHierarchyResponse; the WalkOrgTree callback is func(org *OrgInfo, depth int)." \
  '(\[\]|\*)@Q@OrgHierarchyResponse\b'

# ---- return-type / behavioural method call sites (method signature/return changed) ----
check_method "ListOrgUsers — return type changed" \
  "returns []OrgMember (bare array). Drop .Users (range the slice) and .Total (len()); member grants moved to .OrgPermissions." \
  'ListOrgUsers'
check_method "ListOrgClients — return type changed" \
  "returns []OrgClientSafe (bare array). Drop .Clients (range the slice) and .Total (len())." \
  'ListOrgClients'
check_method "GetLoginConfig / UpdateLoginConfig — return type + nested body" \
  "return *LoginConfig (no .Config wrapper). LoginConfigUpdate is now 5 nested sections (Branding/Content/AuthMethods/Registration/Security); a flat body is 400-rejected." \
  'GetLoginConfig|UpdateLoginConfig'
check_method "InviteToOrganization — return type changed" \
  "returns *InviteResult (was *MessageResponse). Read .InvitationCode / .InvitationID / .ExpiresAt / .UserID." \
  'InviteToOrganization'
check_method "WriteAndDeleteRelationships — path + return type changed" \
  "now POSTs the real route .../write and returns *TransactResponse (read .Written/.Deleted/.ConsistencyToken). Tuple wire is {object,relation,subject} ONLY — Context/ExpiresAt are dropped; use WriteRelationships for an expiring grant." \
  'WriteAndDeleteRelationships'
check_method "UpdateUser — argument type changed" \
  "2nd arg is now AdminUserUpdate (embeds UserUpdate + Status). Wrap: AdminUserUpdate{UserUpdate: UserUpdate{...}, Status: &s}. (/users/me via UpdateMyProfile stays UserUpdate.)" \
  'UpdateUser'
check_method "WalkOrgTree — callback signature changed" \
  "callback is now func(org *OrgInfo, depth int) (was func(node *OrgHierarchyResponse, depth int)); counts are a root-only field, read them from the response value." \
  'WalkOrgTree'
check_method "ListOrgSessions — response field renames" \
  "on the returned *OrgSessionsResponse: .Total -> .TotalSessions (+.OrganizationID). On each OrgSession: .ID -> .SessionID, .LastSeenAt -> .LastAccessed (.ExpiresAt removed; +UserEmail/UserName)." \
  'ListOrgSessions'
check_method "RevokeUserSessions — response field renamed" \
  "on the returned *SessionRevokeResponse: .RevokedCount -> .SessionsRevoked." \
  'RevokeUserSessions'
check_method "ListTeamMembers — TeamMember field renames" \
  "on each TeamMember: .AddedAt -> .JoinedAt; .Email/.Name are removed (server never sent them); .TeamID/.Permissions are new." \
  'ListTeamMembers'

# ---- surviving types whose FIELDS changed (open the literal; fire only on removed fields) ----
check_litfield "TokenValidationRequest — ResourceType/ResourceID removed (SECURITY)" \
  "these were SILENTLY DROPPED by the server -> a resource-scoped ValidateToken validated UNSCOPED. Remove them; for a real resource decision use Authorize(ctx, token, action, Resource{Type:.., ID:..})." \
  'TokenValidationRequest' 'ResourceType|ResourceID'
check_litfield "OrganizationInvite — TeamIDs -> TeamID, -Resend" \
  "TeamIDs []string -> TeamID string (single); add Permissions []string; remove Resend." \
  'OrganizationInvite' 'TeamIDs|Resend'
check_litfield "ProviderConfigCreate — Type/Enabled + settings->Config" \
  "Type -> ProviderType; Enabled -> IsActive; move ClientID/ClientSecret/IssuerURL/Domain into the Config map; new Description/IsDefault/Metadata." \
  'ProviderConfigCreate' 'Type|Enabled|ClientID|ClientSecret|IssuerURL|Domain'
check_litfield "ProviderConfigUpdate — Type/Enabled + settings->Config" \
  "Type -> ProviderType; Enabled -> IsActive; move ClientID/ClientSecret/IssuerURL/Domain into the Config map." \
  'ProviderConfigUpdate' 'Type|Enabled|ClientID|ClientSecret|IssuerURL|Domain'
check_litfield "Provider (response literal) — Type/Enabled/Domain/IssuerURL" \
  "on Provider values: .Type -> .ProviderType; .Enabled -> .IsActive; top-level Domain/IssuerURL are gone (they live in .Config)." \
  'Provider' 'Type|Enabled|Domain|IssuerURL'
check_litfield "RegisterRequest — ProviderType removed" \
  "remove ProviderType (server ignores it; provider is always internal here). To join an org by invite, set InvitationCode." \
  'RegisterRequest' 'ProviderType'
check_litfield "OrgRegisterRequest — FirstName/LastName removed" \
  "remove FirstName/LastName (server reads only Name). ClientID and InvitationCode are now available." \
  'OrgRegisterRequest' 'FirstName|LastName'
check_litfield "APIKeyCreate — OrgID/Audience removed" \
  "remove OrgID/Audience (server ignored them). You can now set RateLimit *int64 at create." \
  'APIKeyCreate' 'OrgID|Audience'
check_litfield "APIKeyUpdate — Metadata removed" \
  "remove Metadata (server ignores it on update)." \
  'APIKeyUpdate' 'Metadata'
check_litfield "OrgRoleUpdate — Permissions removed" \
  "remove Permissions (the role-update handler reads only Role; member perms are set via invite/team)." \
  'OrgRoleUpdate' 'Permissions'
check_litfield "OrganizationCreate — BillingType removed" \
  "remove BillingType (billing-owned by design; put non-billing attrs in Metadata). New: LogoURL/Website/Industry/Size." \
  'OrganizationCreate' 'BillingType'
check_litfield "OrganizationUpdate — BillingType/Status removed" \
  "remove BillingType (billing-owned) and Status (not in the update schema). New: LogoURL/Website/Industry/Size/Slug/ParentID." \
  'OrganizationUpdate' 'BillingType|Status'

# ========================================================================================
# ADVISORY (REVIEW) rules — bare selectors on SDK-returned values. Gated on a co-occurring
# owning SDK token so a consumer's own same-named field never surfaces. Never gates CI.
# ========================================================================================
check_review "OrgSession.LastSeenAt -> .LastAccessed" \
  ".LastSeenAt -> .LastAccessed and .ID -> .SessionID on an OrgSession value (.ExpiresAt removed)." \
  '\.LastSeenAt\b' '(^|[^A-Za-z0-9_])ListOrgSessions\(|OrgSessionsResponse\b|OrgSession\b'
check_review "SessionRevokeResponse.RevokedCount -> .SessionsRevoked" \
  ".RevokedCount -> .SessionsRevoked on the RevokeUserSessions result." \
  '\.RevokedCount\b' '(^|[^A-Za-z0-9_])RevokeUserSessions\(|SessionRevokeResponse\b'
check_review "TeamMember.AddedAt -> .JoinedAt" \
  ".AddedAt -> .JoinedAt on a TeamMember value." \
  '\.AddedAt\b' '(^|[^A-Za-z0-9_])ListTeamMembers\(|TeamMember\b'
check_review "OrgMember.Permissions -> .OrgPermissions" \
  "on OrgMember (ListOrgUsers items) the member grants are .OrgPermissions (json org_permissions)." \
  '\.Permissions\b' 'OrgMember\b'
check_review "ListAuthorizationModelsResponse.ContinuationToken removed" \
  "the server does not paginate this endpoint; delete the reference (the list is the full set)." \
  '\.ContinuationToken\b' 'ListAuthorizationModels'

# ========================================================================================
echo
echo "======================================================"
if [ "$REVIEW" -gt 0 ]; then
  echo -e "${CYAN}${REVIEW} REVIEW hit(s)${NC} above are advisory — confirm the value's type is the named SDK"
  echo "type before changing, and IGNORE it if it's your own struct. They do NOT gate CI."
fi
if [ "$FOUND" -eq 0 ]; then
  echo -e "${GREEN}No high-confidence migration findings.${NC} Your SDK call sites look compatible with v0.11.0."
  echo "Still run: go build ./... && go vet ./... && go test ./..."
  exit 0
else
  echo -e "${RED}${FOUND} high-confidence site(s) to change for v0.11.0.${NC}"
  echo "Each ● block shows the fix. These are SDK-type-precise (alias-qualified usage, changed"
  echo "method call, or a removed field set inside an SDK literal). Apply them, re-run this"
  echo "checker (expect 0), then: go build ./... && go vet ./... && go test ./..."
  exit 1
fi
