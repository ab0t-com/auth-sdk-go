#!/usr/bin/env python3
# SUPERSEDED by scripts/field-drift.py (operation-based, type-aware).
# Retained for reference; `make field-drift` now runs field-drift.py. This name-based checker is
# a LOWER BOUND (blind to the name-mismatch class, e.g. Actor<->TokenValidationResponse).
"""field-coverage.py — FIELD-level drift between this SDK and the auth OpenAPI.

`spec-coverage.py` checks that every server PATH has an SDK method. It says
nothing about whether the request/response SHAPES match — and that is exactly the
gap the 2026-08-27 contract-drift investigation found: `make drift` reported
283/283 (100%) while `Authorize()` dropped resource scoping, `Actor` dropped every
delegation field, and `GET /health` surfaced 2 of 13 fields. This tool closes that
blind spot: it compares the json tags on the SDK's Go structs against the
`properties` of the OpenAPI schema of the same name.

    make field-drift                    # check the live auth service
    python3 scripts/field-coverage.py --spec /tmp/openapi.json
    (deprecated — use scripts/field-drift.py)

It reports, per struct that shares a name with a schema:
  REQ-MISSING   a field the schema marks *required* that the Go struct lacks
                (on a response = data the server always sends and the SDK drops;
                 on a request = a body the server rejects)
  MISSING       a schema field the Go struct lacks (not required)
  PHANTOM       a Go field absent from the schema (a field no backend returns)

LIMITATION — this matches Go structs to schemas BY NAME. That is a LOWER BOUND:
the CRITICAL F-02 finding (Go `Actor` vs schema `TokenValidationResponse`) is
invisible to name matching. Upgrading to operation-based matching (path+verb ->
schema -> the Go type at the call site) is tracked as a follow-up task. It is
dependency-free (stdlib only) like the SDK and `spec-coverage.py`.

Exit is 0 (a scoreboard, not a gate) unless --strict is passed, which exits 1 if
any non-allowlisted REQ-MISSING remains.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import urllib.request

PYTHON_URL = "https://auth.service.ab0t.com/openapi.json"
ALT_URL = os.environ.get("AUTH_ALT_SPEC_URL", "")

# Field-level divergences known and tracked in tickets/20260827_sdk_contract_drift.
# Each entry is (GoStructName, "field") -> keeps it out of the --strict gate while
# it is worked. Shrinks to empty as the per-domain child tickets land. Seed it with
# a domain's whole set by adding (Name, "*").
# Bulk per-domain field remediation is still open across the SDK (child tickets in
# tickets/20260827_sdk_contract_drift/children/). Until a file's child ticket lands,
# its whole file is wildcard-allowed so --strict does not fail on known, tracked
# drift. Each fixed file's REQ-MISSING types are additionally protected by unit
# tests (contract_drift_test.go). DELETE a file's wildcard when its child ticket
# closes — the allowlist shrinks to empty as remediation completes.
KNOWN_FIELD_GAPS: set[tuple[str, str]] = {
    ("*", f) for f in (
        "admin.go", "providers.go", "orgs.go", "email.go", "saml.go",
        "passwordless.go", "hosted.go", "apikeys.go", "users.go", "roles.go",
        "quotas.go", "oauth.go", "network.go", "events.go", "system.go",
        "types.go", "forwardauth.go", "authzmodel.go", "permissions.go",
    )
}


def fetch(url: str, dest: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            data = r.read()
        d = json.loads(data)
        if not isinstance(d.get("paths"), dict):
            return False
        with open(dest, "wb") as f:
            f.write(data)
        return True
    except Exception as e:  # noqa: BLE001
        print(f"  (could not fetch {url}: {e})", file=sys.stderr)
        return False


def schema_props(schemas: dict) -> dict[str, tuple[set, set]]:
    """name -> (all property names, required names), resolving allOf one level."""
    def resolve(name, seen=None):
        seen = seen or set()
        if name in seen or name not in schemas:
            return set(), set()
        seen.add(name)
        s = schemas[name]
        p = set(s.get("properties", {}))
        r = set(s.get("required", []))
        for sub in s.get("allOf", []):
            if "$ref" in sub:
                pp, rr = resolve(sub["$ref"].split("/")[-1], seen)
                p |= pp
                r |= rr
            else:
                p |= set(sub.get("properties", {}))
                r |= set(sub.get("required", []))
        return p, r
    return {n: resolve(n) for n in schemas}


STRUCT_RE = re.compile(r"^type\s+(\w+)\s+struct\s*\{")
TAG_RE = re.compile(r"`[^`]*json:\"([^\"]+)\"")
EMBED_RE = re.compile(r"^\t\*?([A-Z]\w*)\s*$")


def parse_go(sdk_dir: str) -> dict[str, tuple[str, dict, list]]:
    """name -> (file, {jsontag: line}, [embedded type names])."""
    out: dict[str, tuple[str, dict, list]] = {}
    for path in sorted(glob.glob(os.path.join(sdk_dir, "*.go"))):
        if path.endswith("_test.go"):
            continue
        lines = open(path).read().split("\n")
        i = 0
        while i < len(lines):
            m = STRUCT_RE.match(lines[i])
            if not m:
                i += 1
                continue
            name, fields, embeds, depth = m.group(1), {}, [], 1
            i += 1
            while i < len(lines) and depth > 0:
                line = lines[i]
                depth += line.count("{") - line.count("}")
                if depth <= 0:
                    break
                t = TAG_RE.search(line)
                if t:
                    tag = t.group(1).split(",")[0]
                    if tag and tag != "-":
                        fields[tag] = i + 1
                else:
                    e = EMBED_RE.match(line)
                    if e:
                        embeds.append(e.group(1))
                i += 1
            out[name] = (os.path.basename(path), fields, embeds)
            i += 1
    return out


def flat_fields(name, go, seen=None) -> set:
    seen = seen or set()
    if name in seen or name not in go:
        return set()
    seen.add(name)
    _, fields, embeds = go[name]
    out = set(fields)
    for e in embeds:
        out |= flat_fields(e, go, seen)
    return out


def allowlisted(struct: str, gofile: str, field: str) -> bool:
    return (
        ("*", gofile) in KNOWN_FIELD_GAPS
        or (struct, "*") in KNOWN_FIELD_GAPS
        or (struct, field) in KNOWN_FIELD_GAPS
    )


def check(spec_path: str, sdk_dir: str, label: str, strict: bool) -> int:
    spec = json.load(open(spec_path))
    schemas = spec.get("components", {}).get("schemas", {})
    props = schema_props(schemas)
    go = parse_go(sdk_dir)

    req_miss, miss, phantom = [], [], []
    for name in sorted(set(go) & set(props)):
        gofile, _, _ = go[name]
        gf = flat_fields(name, go)
        p, req = props[name]
        if not p:
            continue
        for f in sorted(p - gf):
            if f in req:
                req_miss.append((name, gofile, f))
            else:
                miss.append((name, gofile, f))
        for f in sorted(gf - p):
            phantom.append((name, gofile, f))

    print(f"\n=== {label}: {spec.get('info', {}).get('title')} "
          f"{spec.get('info', {}).get('version')} ===")
    print(f"    {len(set(go) & set(props))} structs matched by name "
          f"(LOWER BOUND — name-based; see file header)")
    gated = [r for r in req_miss if not allowlisted(*r)]
    print(f"    REQ-MISSING: {len(req_miss)} ({len(gated)} outside the allowlist)")
    print(f"    MISSING:     {len(miss)}")
    print(f"    PHANTOM:     {len(phantom)}")
    for name, gofile, f in gated:
        print(f"      REQ-MISSING  {name} ({gofile}) lacks required {f!r}")
    for name, gofile, f in phantom:
        print(f"      PHANTOM      {name} ({gofile}) declares {f!r} (no backend)")
    return 1 if (strict and gated) else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", help="a saved openapi.json (skips fetching)")
    ap.add_argument("--python-url", default=PYTHON_URL)
    ap.add_argument("--alt-url", default=ALT_URL)
    ap.add_argument("--sdk", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if any non-allowlisted REQ-MISSING remains")
    args = ap.parse_args()

    rc = 0
    if args.spec:
        rc |= check(args.spec, args.sdk, os.path.basename(args.spec), args.strict)
    else:
        tmp = "/tmp/auth-field-cov"
        os.makedirs(tmp, exist_ok=True)
        for label, url in (("auth service", args.python_url), ("alt", args.alt_url)):
            dest = os.path.join(tmp, f"{label}.json")
            if fetch(url, dest):
                rc |= check(dest, args.sdk, label, args.strict)
            else:
                print(f"    (skipped {label}: not reachable)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
