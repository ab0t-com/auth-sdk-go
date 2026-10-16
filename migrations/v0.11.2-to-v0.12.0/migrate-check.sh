#!/usr/bin/env bash
# migrate-check.sh — auth-sdk-go v0.11.2 -> v0.12.0: find what to REVIEW for the default-on validation cache.
#
# Read-only. It NEVER edits your code (LMKAP RFC-0001 §3.4a).
#
# WHAT CHANGED (behavioural only — your code still compiles unchanged)
#   A client built WITHOUT a cache option now caches validation answers in-process:
#     API key (ValidateAPIKey, ValidateToken with ab0t_sk_)   60 s "valid" / 10 s "not valid"
#     JWT     (ValidateToken, ValidateTokenWith)              15 s / 5 s (never past the token's exp)
#     permission decision (Authorize, RequiredPermissions)    15 s / 5 s
#   So a revoked key / logged-out session / removed permission can keep being accepted for up to that TTL.
#
# WHAT IT REPORTS (per finding: file:line, the rule, the fix — RFC §3.4c)
#   ● R1 CLIENT    an SDK client constructed without WithValidationCache/WithValidationCacheOptions: it now
#                  gets the default cache. Decide per client: keep the defaults, or add WithValidationCache(0).
#   ● R2 CALL      a ValidateToken / ValidateTokenWith / ValidateAPIKey / Authorize call site (CANDIDATE —
#                  prefer false positives, §3.4f): is this call revocation-latency-sensitive (admin, money
#                  movement, ownership change)? If so pass WithFreshValidation(ctx) for it.
#   ● R3 TEST      a test that builds a real client against authclienttest.Server and flips the fake's answer
#                  (SetValid/SetStatus/SetActor): it will see the cached earlier answer. Use srv.NewClient().
#   ● R4 COND      WithValidationCache(...) passed only inside `if ttl > 0 { … }`: a configured 0 used to mean
#                  "off" and now means "defaults on". Pass the option unconditionally (0 = off).
#   ? INFO         authmw gates (every request through them now uses the cached client) — advisory only.
#
# MARKING A SITE REVIEWED (so CI can gate on this checker, RFC §3.4d)
#   A finding is resolved when ANY of these holds:
#     - the call passes WithFreshValidation(...) on that line                          (R2)
#     - the construction passes WithValidationCache(...) or WithValidationCacheOptions (R1; and if EVERY
#       construction in the repo is explicit, all R2 call sites are informational — the default never applies)
#     - the line, or the line above it, carries the comment   // authsdk:cache-reviewed   (R1, R2)
#     - the file carries the comment                          // authsdk:cache-reviewed-file   (R1, R2)
#     - the test builds its client with srv.NewClient(...)                             (R3)
#     - the option is passed unconditionally, or the line carries the marker            (R4)
#
# PRECISION: only .go files importing github.com/ab0t-com/auth-sdk-go (or its authclienttest) are read; the
#   SDK package's local alias is resolved per file, so constructions are matched alias-qualified (<alias>.New().
#   Method calls are matched by name (.Authorize( etc.) in SDK-importing files — CANDIDATES: a method of your own
#   with the same name in such a file is a false positive; mark it reviewed.
#
# Usage:   ./migrate-check.sh [path-to-your-repo] [--advisory]
#          --advisory  report only, always exit 0 (for a CI job that should not gate)
# Exit:    0 = nothing left to review · 1 = findings to review/fix · 2 = usage error
# See MIGRATION.md (same directory) for the full rationale and CLIENT_NOTICE.md for the latency per method.

set -u
set -o pipefail

TARGET="."
ADVISORY=0
for a in "$@"; do
  case "$a" in
    --advisory) ADVISORY=1 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) TARGET="$a" ;;
  esac
done
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
FOUND=0; INFO=0

if [ ! -d "$TARGET" ]; then echo "not a directory: $TARGET" >&2; exit 2; fi
GO_FILES="$(find "$TARGET" -name '*.go' -not -path '*/vendor/*' -not -path '*/.git/*' 2>/dev/null | wc -l)"
echo -e "${BOLD}auth-sdk-go v0.11.2 -> v0.12.0 migration check (default-on validation cache — BEHAVIOURAL)${NC}"
echo    "target: $TARGET  ($GO_FILES .go files)"
if [ "$GO_FILES" -eq 0 ]; then echo "no .go files under $TARGET — nothing to check."; exit 0; fi

SDK_PATH_RE='"github\.com/ab0t-com/auth-sdk-go"'
TEST_PATH_RE='"github\.com/ab0t-com/auth-sdk-go/authclienttest"'
MW_PATH_RE='"github\.com/ab0t-com/auth-sdk-go/authmw"'
MARK_LINE='authsdk:cache-reviewed'
MARK_FILE='authsdk:cache-reviewed-file'

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---- 1. SDK-importing files and each one's local alias for the root package ----
# "path<TAB>alias"; alias "" = dot-import; blank imports skipped.
while IFS= read -r f; do
  [ -n "$f" ] || continue
  aln="$(grep -E "$SDK_PATH_RE" "$f" 2>/dev/null | head -1 \
         | sed -E 's#"github\.com/ab0t-com/auth-sdk-go".*##; s/^[[:space:]]*(import[[:space:]]+)?//; s/[[:space:]]*$//')"
  [ -z "$aln" ] && aln="authclient"
  [ "$aln" = "_" ] && continue
  [ "$aln" = "." ] && aln=""
  printf '%s\t%s\n' "$f" "$aln"
done < <(grep -rlE "$SDK_PATH_RE" --include='*.go' --exclude-dir=vendor --exclude-dir=.git "$TARGET" 2>/dev/null) > "$TMP/sdk_files"

SDK_FILE_COUNT="$(grep -c . "$TMP/sdk_files" 2>/dev/null || true)"; SDK_FILE_COUNT="${SDK_FILE_COUNT:-0}"
echo    "SDK-importing files: $SDK_FILE_COUNT"
if [ "$SDK_FILE_COUNT" -eq 0 ] && ! grep -rqE "$TEST_PATH_RE|$MW_PATH_RE" --include='*.go' --exclude-dir=vendor --exclude-dir=.git "$TARGET" 2>/dev/null; then
  echo -e "\n${GREEN}No file imports github.com/ab0t-com/auth-sdk-go — nothing to review.${NC}"
  exit 0
fi

# reviewed FILE LINE  → 0 when the line or the one above carries the marker, or the file carries the file marker
reviewed() {
  local f="$1" n="$2"
  grep -q "$MARK_FILE" "$f" 2>/dev/null && return 0
  awk -v n="$n" -v m="$MARK_LINE" 'NR==n-1 || NR==n { if (index($0, m)) found=1 } END { exit found ? 0 : 1 }' "$f"
}

# emit LABEL ADVICE FILE_WITH_HITS
emit() {
  local label="$1" advice="$2" file="$3" n
  [ -s "$file" ] || return 0
  n="$(grep -c . "$file")"
  FOUND=$((FOUND + n))
  echo -e "\n${YELLOW}● ${label}${NC}  (${n})"
  echo -e "  ${BOLD}review/fix:${NC} ${advice}"
  sed 's/^/    /' "$file"
}

# ---- R1: client constructions <alias>.New( ... ) — multi-line aware; explicit cache option? ----
# R1/R2 are about PRODUCTION behaviour, so *_test.go files are skipped here; the one test pattern the
# default breaks (flipping a fake's answer mid-test) is R3.
: > "$TMP/r1"; : > "$TMP/r1_explicit"
while IFS=$'\t' read -r f a; do
  [ -n "$f" ] || continue
  case "$f" in *_test.go) continue ;; esac
  if [ -n "$a" ]; then opener="(^|[^A-Za-z0-9_.])${a}[.]New[(]"; else opener="(^|[^A-Za-z0-9_.])New[(]"; fi
  awk -v opener="$opener" '
    function bal(s,  t,o,c){ t=s; o=gsub(/\(/,"",t); t=s; c=gsub(/\)/,"",t); return o-c }
    {
      if (!in_call && match($0, opener)) {
        in_call=1; start=FNR; first=$0; text=substr($0, RSTART); depth=bal(text)
      } else if (in_call) { text=text " " $0; depth+=bal($0) }
      if (in_call && depth<=0) {
        explicit = (text ~ /WithValidationCache(Options)?[(]/) ? "explicit" : "default"
        gsub(/^[ \t]+/, "", first)
        print FILENAME "\t" start "\t" explicit "\t" first
        in_call=0
      }
    }' "$f" 2>/dev/null
done < "$TMP/sdk_files" > "$TMP/constructions"

TOTAL_NEW="$(grep -c . "$TMP/constructions" 2>/dev/null || true)"; TOTAL_NEW="${TOTAL_NEW:-0}"
DEFAULT_NEW=0
while IFS=$'\t' read -r f n kind line; do
  [ -n "$f" ] || continue
  if [ "$kind" = explicit ]; then echo "$f:$n: $line" >> "$TMP/r1_explicit"; continue; fi
  DEFAULT_NEW=$((DEFAULT_NEW + 1))
  reviewed "$f" "$n" && continue
  echo "$f:$n: $line" >> "$TMP/r1"
done < "$TMP/constructions"
ALL_EXPLICIT=0
[ "$TOTAL_NEW" -gt 0 ] && [ "$DEFAULT_NEW" -eq 0 ] && ALL_EXPLICIT=1

emit "R1 CLIENT — built without a cache option: the validation cache is now ON for it" \
  "decide per client. Keep the defaults (API key 60 s / JWT 15 s / permission 15 s revocation latency) and mark the line '// $MARK_LINE', OR add WithValidationCache(0) for the pre-v0.12.0 behaviour (every validation an HTTP call), OR choose your own TTL with WithValidationCache(ttl)." \
  "$TMP/r1"

# ---- R2: validation call sites (CANDIDATES) ----
: > "$TMP/r2"
while IFS=$'\t' read -r f a; do
  [ -n "$f" ] || continue
  case "$f" in *_test.go) continue ;; esac
  grep -nE '[.](ValidateToken|ValidateTokenWith|ValidateAPIKey|Authorize)[(]' "$f" 2>/dev/null | while IFS=: read -r n rest; do
    case "$rest" in *WithFreshValidation*) continue ;; esac
    case "$rest" in *"func ("*) continue ;; esac   # a method DEFINITION, not a call
    reviewed "$f" "$n" && continue
    echo "$f:$n:$rest"
  done
done < "$TMP/sdk_files" > "$TMP/r2"
if [ "$ALL_EXPLICIT" -eq 1 ] && [ -s "$TMP/r2" ]; then
  n="$(grep -c . "$TMP/r2")"; INFO=$((INFO + n))
  echo -e "\n${CYAN}? INFO — ${n} validation call site(s); every client in this repo sets an explicit cache option, so the new default never applies to them (unchanged behaviour).${NC}"
else
  emit "R2 CALL — validation call site (CANDIDATE): its answer may now come from the cache" \
    "is this decision revocation-latency-sensitive (admin action, money movement, ownership change, a just-revoked key)? If yes: pass authclient.WithFreshValidation(ctx) on THIS call (always asks the service). If no: mark it '// $MARK_LINE'. A method of your own with the same name is a false positive — mark it." \
    "$TMP/r2"
fi

# ---- R4: CONDITIONAL opt-in — WithValidationCache added only when a configured TTL is non-zero ----
# The classic config-driven shape:   if cfg.TTL > 0 { opts = append(opts, WithValidationCache(cfg.TTL)) }
# Before v0.12.0 a configured 0 meant "no option" = no cache. From v0.12.0 "no option" = the DEFAULT
# cache, so the service's documented "0 disables" silently stops being true. Fix: pass the option
# unconditionally — WithValidationCache(0) is the documented "off".
: > "$TMP/r4"
while IFS=$'\t' read -r f a; do
  [ -n "$f" ] || continue
  case "$f" in *_test.go) continue ;; esac
  awk -v m="$MARK_LINE" '
    { hist[NR % 8] = $0 }
    /WithValidationCache(Options)?[(]/ && $0 !~ /WithValidationCache[(]0[)]/ {
      cond = 0
      for (i = 1; i <= 6 && NR - i > 0; i++) {
        l = hist[(NR - i) % 8]
        if (l ~ /(^|[^A-Za-z0-9_])if[[:space:]]/ && l ~ /(>|!=)[[:space:]]*0([^.0-9]|$)/) { cond = 1; break }
      }
      if (cond && index($0, m) == 0 && index(hist[(NR - 1) % 8], m) == 0) { s = $0; sub(/^[ \t]+/, "", s); print FILENAME ":" NR ": " s }
    }' "$f" 2>/dev/null
done < "$TMP/sdk_files" > "$TMP/r4"
emit "R4 CONDITIONAL OPT-IN — the cache option is only passed when a configured TTL is non-zero" \
  "a configured 0 used to mean 'no cache'; from v0.12.0 omitting the option means the DEFAULT cache (API key 60 s / JWT 15 s / permission 15 s). If 0 must still mean off, pass the option unconditionally: WithValidationCache(cfg.TTL) — WithValidationCache(0) is the documented off switch." \
  "$TMP/r4"

# ---- R3: tests that flip authclienttest.Server answers on a client built with plain New(srv.URL()) ----
: > "$TMP/r3"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  grep -qE '[.]Set(Valid|Status|Actor)[(]' "$f" 2>/dev/null || continue
  grep -nE '[.]New[(][^)]*[.]URL[(][)]' "$f" 2>/dev/null | while IFS=: read -r n rest; do
    case "$rest" in *WithValidationCache*) continue ;; esac
    reviewed "$f" "$n" && continue
    echo "$f:$n:$rest"
  done
done < <(grep -rlE "$TEST_PATH_RE" --include='*.go' --exclude-dir=vendor --exclude-dir=.git "$TARGET" 2>/dev/null) > "$TMP/r3"
emit "R3 TEST — real client against authclienttest.Server in a test that changes the fake's answer" \
  "the client now caches, so SetValid(false)/SetStatus(503) after a first call is not seen for up to the TTL. Build it with srv.NewClient(opts...) (cache off), or add auth.WithValidationCache(0)." \
  "$TMP/r3"

# ---- INFO: authmw gates ----
MW="$(grep -rlE "$MW_PATH_RE" --include='*.go' --exclude-dir=vendor --exclude-dir=.git "$TARGET" 2>/dev/null || true)"
if [ -n "$MW" ]; then
  n="$(printf '%s\n' "$MW" | grep -c .)"; INFO=$((INFO + n))
  echo -e "\n${CYAN}? INFO — authmw gates in ${n} file(s): every request through them is validated by the client you pass in, so the R1 decision for that client applies to them.${NC}"
  printf '%s\n' "$MW" | sed 's/^/    /'
fi

if [ -s "$TMP/r1_explicit" ]; then
  n="$(grep -c . "$TMP/r1_explicit")"; INFO=$((INFO + n))
  echo -e "\n${CYAN}? INFO — ${n} client(s) already configure the cache explicitly — UNCHANGED by v0.12.0:${NC}"
  sed 's/^/    /' "$TMP/r1_explicit"
fi

echo
echo "======================================================"
echo "Revocation latency with the v0.12.0 defaults: API key ≤60 s · JWT/logout ≤15 s · permission ≤15 s."
echo "Opt out per client: WithValidationCache(0) · per call: WithFreshValidation(ctx) · per credential: InvalidateValidation(cred)."
if [ "$FOUND" -eq 0 ]; then
  echo -e "${GREEN}Nothing left to review for v0.12.0.${NC} Then: go build ./... && go vet ./... && go test ./..."
  exit 0
fi
echo -e "${RED}${FOUND} site(s) to review/fix for v0.12.0.${NC} Your code compiles unchanged — these are BEHAVIOURAL"
echo "decisions (RFC-0001 P6: flagged, never auto-applied). Resolve each, re-run this checker (expect 0), then:"
echo "go build ./... && go vet ./... && go test ./..."
[ "$ADVISORY" -eq 1 ] && { echo "(--advisory: exiting 0)"; exit 0; }
exit 1
