#!/usr/bin/env bash
# migrate-check.sh — auth-sdk-go v0.12.0 -> v0.12.1: find what to LOOK AT after the authmw fixes.
#
# Read-only. It NEVER edits your code (LMKAP RFC-0001 §3.4a).
#
# WHAT CHANGED (bug fixes + additive API — your code compiles unchanged, every default is unchanged)
#   - authmw: when the auth service answers a JWT with HTTP 401/403, Authenticate now answers 401 (was 503
#     "auth unavailable"); Require answers 401 / 403 (was 503). Network / 429 / 5xx stay 503.
#   - authmw + FailOpen: an invalid or denied credential is never let through any more (v0.12.0 let Authenticate
#     pass it on anonymously and made Require RUN THE HANDLER when the auth service answered 401).
#   - A definite 401 from validate-token is cached for the negative TTL (5 s); same error to the caller.
#   - New, opt-in: WithExpectedJWTAudience, Gate.RequireIdentity, Gate.IncludePermissions, Gate.WriteDenial +
#     authmw.JSONDenial, Gate.APIKeyHeader, package authmw/authmwtest. Bearer scheme is case-insensitive.
#
# WHAT IT REPORTS (per finding: file:line, the rule, the fix — RFC §3.4c)
#   ● R1 FAILOPEN   a Gate with FailOpen on: invalid/denied credentials are no longer admitted. Confirm nothing
#                   relied on that (it was a hole, not a feature).
#   ● R2 PERMS      authmw.Identity(...) permissions read while no gate in the repo sets IncludePermissions: JWT
#                   callers carry NO permissions, so a check on them denies every JWT caller. Set
#                   Gate.IncludePermissions = true (needs V = *auth.Client), or confirm only API keys reach it.
#   ● R3 TEST       a test that scripts the auth service to answer 401 and expects 503 from the gate (CANDIDATE):
#                   v0.12.1 answers 401 there. Update the expectation.
#   ? INFO          every authmw.Gate (clients may now see 401 where they saw 503 — retry logic, dashboards,
#                   alerts keyed on authmw 503s); WithExpectedAudience call sites (if the same client also checks
#                   mesh API keys, which carry no audience, WithExpectedJWTAudience checks JWTs only).
#
# MARKING A SITE REVIEWED (so CI can gate on this checker, RFC §3.4d)
#     - the line, or the line above it, carries   // authsdk:v0.12.1-reviewed
#     - the file carries                          // authsdk:v0.12.1-reviewed-file
#     - R2 is also resolved when any non-test file in the repo sets IncludePermissions
#
# PRECISION: only .go files importing github.com/ab0t-com/auth-sdk-go (or /authmw) are read; the authmw alias is
#   resolved per file. R2/R3 are CANDIDATES (prefer false positives, §3.4f): mark what you have checked.
#
# Usage:   ./migrate-check.sh [path-to-your-repo] [--advisory]
#          --advisory  report only, always exit 0
# Exit:    0 = nothing left to look at · 1 = findings to review · 2 = usage error
# See MIGRATION.md (same directory) and CLIENT_NOTICE.md.

set -u
set -o pipefail

TARGET="."
ADVISORY=0
for a in "$@"; do
  case "$a" in
    --advisory) ADVISORY=1 ;;
    -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
    -*) echo "unknown option: $a" >&2; exit 2 ;;
    *) TARGET="$a" ;;
  esac
done
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
FOUND=0

if [ ! -d "$TARGET" ]; then echo "not a directory: $TARGET" >&2; exit 2; fi
echo -e "${BOLD}auth-sdk-go v0.12.0 -> v0.12.1 migration check (authmw fixes + opt-in settings — no source change required)${NC}"
echo    "target: $TARGET"

SDK_RE='"github\.com/ab0t-com/auth-sdk-go(/authmw)?"'
MW_RE='"github\.com/ab0t-com/auth-sdk-go/authmw"'
MARK_LINE='authsdk:v0.12.1-reviewed'
MARK_FILE='authsdk:v0.12.1-reviewed-file'

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

grep -rlE "$SDK_RE" --include='*.go' --exclude-dir=vendor --exclude-dir=.git "$TARGET" 2>/dev/null > "$TMP/files" || true
if [ ! -s "$TMP/files" ]; then
  echo -e "\n${GREEN}No file imports github.com/ab0t-com/auth-sdk-go — nothing to look at.${NC}"
  exit 0
fi
echo "SDK-importing files: $(grep -c . "$TMP/files")"
grep -v '_test\.go$' "$TMP/files" > "$TMP/nontest" || true
# in_nontest ARGS... — grep over the non-test SDK files (never reads stdin when there are none)
in_nontest() { [ -s "$TMP/nontest" ] && xargs -d '\n' grep "$@" < "$TMP/nontest"; }

# "path<TAB>alias" for files importing authmw (alias "authmw" unless renamed; dot/blank imports skipped)
while IFS= read -r f; do
  grep -qE "$MW_RE" "$f" || continue
  aln="$(grep -E "$MW_RE" "$f" | head -1 | sed -E 's#"github\.com/ab0t-com/auth-sdk-go/authmw".*##; s/^[[:space:]]*(import[[:space:]]+)?//; s/[[:space:]]*$//')"
  [ -z "$aln" ] && aln="authmw"
  case "$aln" in _|.) continue ;; esac
  printf '%s\t%s\n' "$f" "$aln"
done < "$TMP/files" > "$TMP/mw"

reviewed() {
  local f="$1" n="$2"
  grep -q "$MARK_FILE" "$f" 2>/dev/null && return 0
  awk -v n="$n" -v m="$MARK_LINE" 'NR==n-1 || NR==n { if (index($0, m)) found=1 } END { exit found ? 0 : 1 }' "$f"
}

emit() {
  local label="$1" advice="$2" file="$3" n
  [ -s "$file" ] || return 0
  n="$(grep -c . "$file")"
  FOUND=$((FOUND + n))
  echo -e "\n${YELLOW}● ${label}${NC}  (${n})"
  echo -e "  ${BOLD}review:${NC} ${advice}"
  sed 's/^/    /' "$file"
}

# ---- R1: FailOpen gates (non-test files) ----
: > "$TMP/r1"
while IFS=$'\t' read -r f a; do
  case "$f" in *_test.go) continue ;; esac
  grep -nE 'FailOpen[[:space:]]*(:|=)[[:space:]]*true' "$f" | while IFS=: read -r n rest; do
    reviewed "$f" "$n" || echo "$f:$n:$rest"
  done
done < "$TMP/mw" > "$TMP/r1"
emit "R1 FAILOPEN — a gate that allows on auth errors" \
  "v0.12.1 no longer lets an INVALID or DENIED credential through FailOpen (v0.12.0 let Require run the handler when the auth service answered 401). Only 'could not decide' (network, timeout, 429, 5xx) passes now. Confirm nothing relied on the old hole, then mark '// $MARK_LINE'." \
  "$TMP/r1"

# ---- R2: permissions read from authmw.Identity while nothing sets IncludePermissions ----
: > "$TMP/r2"
if ! in_nontest -lE 'IncludePermissions[[:space:]]*(:|=)[[:space:]]*true' >/dev/null 2>&1; then
  while IFS=$'\t' read -r f a; do
    case "$f" in *_test.go) continue ;; esac
    grep -qE "(^|[^A-Za-z0-9_])${a}[.]Identity[(]" "$f" || continue
    grep -nE '[.]Permissions([^A-Za-z0-9_]|$)' "$f" | while IFS=: read -r n rest; do
      reviewed "$f" "$n" || echo "$f:$n:$rest"
    done
  done < "$TMP/mw" > "$TMP/r2"
fi
emit "R2 PERMS — permissions read from authmw.Identity, but no gate sets IncludePermissions (CANDIDATE)" \
  "a JWT caller's identity carries NO permissions unless the gate asks for them, so a permission check here denies every JWT caller (API keys are unaffected). Set Gate{IncludePermissions: true} (V must be *auth.Client), or — if only API keys reach this code — mark '// $MARK_LINE'." \
  "$TMP/r2"

# ---- R3: tests that script a 401 from auth and expect 503 from the gate ----
: > "$TMP/r3"
while IFS= read -r f; do
  case "$f" in *_test.go) ;; *) continue ;; esac
  grep -qE "$MW_RE" "$f" || continue
  grep -qE '(SetStatus|WriteHeader)[(][[:space:]]*(401|http[.]StatusUnauthorized)[[:space:]]*[)]' "$f" || continue
  grep -nE 'StatusServiceUnavailable|(^|[^0-9])503([^0-9]|$)' "$f" | while IFS=: read -r n rest; do
    reviewed "$f" "$n" || echo "$f:$n:$rest"
  done
done < "$TMP/files" > "$TMP/r3"
emit "R3 TEST — the auth double answers 401 and the test expects 503 (CANDIDATE)" \
  "v0.12.1 answers 401 (Require: 401, or 403 for a 403) when the auth service rejects the credential; 503 stays for network/429/5xx. Update the expectation; mark '// $MARK_LINE' where the 503 is about an outage." \
  "$TMP/r3"

# ---- INFO ----
GATES=0
while IFS=$'\t' read -r f a; do
  case "$f" in *_test.go) continue ;; esac
  n="$(grep -cE "(^|[^A-Za-z0-9_])${a}[.]Gate[{]" "$f" || true)"; GATES=$((GATES + ${n:-0}))
done < "$TMP/mw"
if [ "$GATES" -gt 0 ]; then
  echo -e "\n${CYAN}? INFO — ${GATES} authmw.Gate construction(s): requests whose JWT the auth service rejects with HTTP 401 now get 401 (was 503). Check client retry logic, dashboards and alerts keyed on authmw 503s.${NC}"
  echo -e "${CYAN}         Optional: authmwtest.Run(t, authmwtest.Contract{Wrap: …}) checks your gate wiring from your tests.${NC}"
fi
in_nontest -nHE 'WithExpectedAudience[(]' 2>/dev/null > "$TMP/aud" || true
if [ -s "$TMP/aud" ]; then
  echo -e "\n${CYAN}? INFO — WithExpectedAudience also applies to API keys; mesh service keys carry no audience and are rejected. If this client also validates such keys, use WithExpectedJWTAudience (JWTs only):${NC}"
  sed 's/^/    /' "$TMP/aud"
fi

echo
echo "======================================================"
if [ "$FOUND" -eq 0 ]; then
  echo -e "${GREEN}Nothing left to look at for v0.12.1.${NC} Then: go build ./... && go vet ./... && go test ./..."
  exit 0
fi
echo -e "${RED}${FOUND} site(s) to review for v0.12.1.${NC} Your code compiles unchanged — resolve each (fix or mark), re-run"
echo "this checker (expect 0), then: go build ./... && go vet ./... && go test ./..."
[ "$ADVISORY" -eq 1 ] && { echo "(--advisory: exiting 0)"; exit 0; }
exit 1
