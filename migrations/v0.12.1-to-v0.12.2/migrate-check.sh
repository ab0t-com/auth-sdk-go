#!/usr/bin/env bash
# migrate-check.sh — auth-sdk-go v0.12.1 -> v0.12.2. Read-only: it NEVER edits your code (LMKAP RFC-0001 §3.4a).
#
# WHAT CHANGED (bug fixes — your code compiles unchanged, every default is unchanged)
#   - VerifyAccessTokenLocal decodes each token segment strictly (no '=' padding, canonical base64url): a padded
#     or non-canonical token string is now 'malformed'. The auth service never pads, so only hand-built test
#     tokens can be affected.
#   - exp / nbf / iat past the year 9999 are 'malformed'.  - The validation cache stays within MaxEntries.
#
# WHAT IT REPORTS
#   ● R1 TOKENFIXTURE  a JWT-looking Go string literal (three base64url parts starting "eyJ") that contains '=':
#                      v0.12.2 refuses it. Regenerate the fixture with base64.RawURLEncoding.
#
# MARKING A SITE REVIEWED:  // authsdk:v0.12.2-reviewed  on the line or the line above it, or
#                           // authsdk:v0.12.2-reviewed-file  anywhere in the file.
# Usage: ./migrate-check.sh [repo-dir] [--advisory]     Exit: 0 clean · 1 findings · 2 usage error
set -u
T="."
ADVISORY=0
for a in "$@"; do
  case "$a" in
    --advisory) ADVISORY=1 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    -*) echo "unknown option: $a" >&2; exit 2 ;;
    *) T="$a" ;;
  esac
done
[ -d "$T" ] || { echo "not a directory: $T" >&2; exit 2; }
F=0
hits=""
while IFS= read -r f; do
  [ -n "$f" ] || continue
  grep -q 'authsdk:v0.12.2-reviewed-file' "$f" && continue
  while IFS=: read -r n rest; do
    prev=$(sed -n "$((n>1 ? n-1 : 1))p" "$f")
    case "$rest$prev" in *authsdk:v0.12.2-reviewed*) continue ;; esac
    hits="$hits$f:$n:$rest"$'\n'
  done < <(grep -nE '"eyJ[A-Za-z0-9_-]*=*\.[A-Za-z0-9_-]*=*\.[A-Za-z0-9_-]*=+"|"eyJ[A-Za-z0-9_-]*=+\.' "$f" 2>/dev/null)
done < <(find "$T" -name '*.go' -not -path '*/vendor/*' -not -path '*/.git/*' 2>/dev/null)
if [ -n "$hits" ]; then
  echo "● R1 TOKENFIXTURE — a JWT-looking literal with '=' padding: v0.12.2's VerifyAccessTokenLocal refuses it (malformed). Regenerate it with base64.RawURLEncoding, or mark the line 'authsdk:v0.12.2-reviewed'."
  printf '%s' "$hits" | sed 's/^/    /'
  F=1
fi
if [ "$F" = 0 ]; then echo "No v0.12.2 migration findings."; else echo "Candidates above — see MIGRATION.md."; fi
[ "$ADVISORY" = 1 ] && exit 0
exit $F
