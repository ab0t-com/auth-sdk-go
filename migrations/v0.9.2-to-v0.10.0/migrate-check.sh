#!/usr/bin/env bash
# migrate-check.sh — find every call site your codebase must change for auth-sdk-go v0.10.0.
#
# Read-only. Greps your Go files for the patterns affected by the v0.9.2 -> v0.10.0 breaking
# changes and prints, per finding, the file:line and the exact fix. Exits non-zero if anything
# needs changing (so you can gate CI on it). It NEVER edits your code.
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
echo -e "${BOLD}auth-sdk-go v0.9.2 -> v0.10.0 migration check${NC}"
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

# ---- behavioural (review, not a mechanical edit) ----
check "Authorize() resource-scoped calls" \
  "review: a non-zero Resource now makes a REAL scoped decision and fails closed (may flip true->false). Resource-less calls are unchanged." \
  '\.Authorize\('

# ---- events (renames + required fields) ----
check "EventSubscriptionCreate — set Name+Endpoint (not URL)" \
  "EventSubscriptionCreate{URL:...} -> {Endpoint:..., Name:...}  (Name and Endpoint are required)" \
  'EventSubscription(Create|Update)\{'
check "EventSubscription field renames" \
  ".URL->.Endpoint  .Active->.IsActive  .ID->.SubscriptionID  (on EventSubscription* values)" \
  '\bEventSubscription[A-Za-z]*\b.*\.(URL|Active|ID)\b'
check "EventSubscriptionListResponse fields" \
  ".Subscriptions->.Items   .Total->.Count" \
  '\.(Subscriptions|Total)\b'

# ---- network policy (renames + required fields) ----
check "CreateNetworkPolicyRequest — set OrgID+Action+Networks" \
  "CIDRs->Networks, Mode->Action, add OrgID.  Mode values: \"allowlist\"->\"allow\", \"blocklist\"->\"deny\"." \
  'CreateNetworkPolicyRequest\{'
check "Network policy .CIDRs / .Mode" \
  ".CIDRs->.Networks   .Mode->.Action   .ID->.PolicyID  (on NetworkPolicy* values)" \
  '\.(CIDRs)\b'
check "Network Mode string values" \
  "Mode value \"allowlist\"->\"allow\", \"blocklist\"->\"deny\"" \
  '"(allowlist|blocklist)"'

# ---- removed phantom fields ----
check "Removed: HealthCheckResponse.Components" \
  "DELETE the reference — no server sent it (always zero)." \
  '\.Components\b'
check "Removed: ServiceDiscoveryResponse.Endpoints/.Links" \
  "DELETE the reference — no server sent them." \
  '\.(Endpoints|Links)\b'

# ---- value type changes ----
check "HealthCheckResponse.Timestamp is now float64" \
  "Timestamp is a numeric epoch (float64), not a string. Parse it as a number." \
  '\.Timestamp\b'
check "Quota collections are now maps, not slices" \
  "QuotaUsageResponse.Usage/.Limits/.Percentages and QuotaTiersResponse.Tiers are map[string]T. Range as 'for k, v := range', index by key." \
  'range[^\n]*\.(Usage|Tiers|Percentages)\b'

# ---- api keys ----
check "APIKey / APIKeyUpdate: Enabled -> IsActive" \
  ".Enabled->.IsActive (server field is is_active; 'enabled' was ignored, so toggling did nothing)." \
  '\.Enabled\b|Enabled:\s'

echo
echo "======================================================"
if [ "$FOUND" -eq 0 ]; then
  echo -e "${GREEN}No migration findings.${NC} Your call sites look compatible with v0.10.0."
  echo "Still run: go build ./... && go vet ./... && go test ./..."
  exit 0
else
  echo -e "${RED}${FOUND} candidate site(s) to review/change for v0.10.0.${NC}"
  echo "Each block above shows the fix. Some patterns (.ID, .Mode, .Total, .Enabled, .Timestamp) are"
  echo "common names — apply a change only where the value's type is the SDK type named in the fix."
  echo "Then re-run this checker (expect 0) and: go build ./... && go test ./..."
  exit 1
fi
