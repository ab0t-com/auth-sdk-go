#!/usr/bin/env bash
# v0.10.0 -> v0.11.0: only DelegationGrant changed. Read-only.
set -u; T="${1:-.}"; F=0
hits=$(grep -rnE --include='*.go' 'DelegationGrant\{|\.TargetUserID|Permissions:' "$T" 2>/dev/null | grep -iE 'deleg' || true)
if [ -n "$hits" ]; then echo "Review DelegationGrant call sites (Permissions→Scope, set ExpiresInHours, drop TargetUserID/ExpiresAt/Reason):"; echo "$hits" | sed 's/^/  /'; F=1; fi
[ "$F" = 0 ] && echo "No v0.11.0 migration findings." || echo "See MIGRATION.md."
exit $F
