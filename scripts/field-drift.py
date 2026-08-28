#!/usr/bin/env python3
"""field-drift.py — the SDK<->auth-server contract gate: FIELDS *and* VALUES, both backends.

Supersedes the name-based `field-coverage.py`. Three checks the earlier gates could not do:

  1. OPERATION-BASED presence — match each Client method by ROUTE (verb+path) -> the server
     schema -> the Go type USED AT THE CALL SITE. This catches the NAME-MISMATCH class that
     name-based matching is blind to (e.g. Go `Actor` <-> schema `TokenValidationResponse`,
     Go `APIKeyValidation` <-> `TokenValidationResponse`), which hid the CRITICAL F-02/F-09.
  2. TYPE/VALUE — compare the Go field KIND to the schema property KIND for shared fields. A
     field present in both but mis-typed (Go string vs a numeric `timestamp`, Go array vs an
     object map) silently mis-decodes — and in Go a single type error fails the WHOLE response.
     This is the F-12 class (`/health` timestamp; quota usage/tiers) — invisible to presence.
  3. REQUIRED-MISSING — a field the schema marks *required* that the SDK type lacks (response =
     data the server always sends and the SDK drops; request = a body the server rejects).

    make field-drift            # both backends (Python live + goauth)
    make field-drift-strict     # exit 1 on any non-allowlisted required-missing OR type mismatch
    python3 scripts/field-drift.py --spec /tmp/openapi.json
    python3 scripts/field-drift.py --python-url ... --goauth-url ...

Dependency-free (stdlib only), like the SDK and `spec-coverage.py`. Exit 0 (a scoreboard) unless
--strict. Derived from tickets/20260827_sdk_contract_drift/{opaudit,typeaudit}.py.
"""
from __future__ import annotations
import argparse, glob, json, os, re, sys, urllib.request

PYTHON_URL = "https://auth.service.ab0t.com/openapi.json"
GOAUTH_URL = "http://localhost:8028/openapi.json"

# --- Allowlist: known, TRACKED gaps that must not fail --strict while remediation is in flight.
# Each entry keeps a (method-or-struct, field) out of the gate. Wildcards: ("METHOD","*") allows a
# whole method; ("*","field") allows a field everywhere. Every entry MUST cite its tracking finding.
#
# EMPTY as of 2026-08-28: the F-04/F-09/F-12 fixes plus the F-10 per-domain response-strip pass
# (ticket 20260827_sdk_contract_drift) closed every gate-worthy gap on BOTH backends, so there is
# nothing to allow. Keeping it empty means any NEW required-field or type regression fails --strict
# immediately. Add an entry ONLY for a deliberately-deferred gap, with its ticket reference, e.g.:
#     KNOWN_FIELD_GAPS.add(("SomeMethod", "*"))  # F-XX, tracked in children/NN_domain.md
KNOWN_FIELD_GAPS: set[tuple[str, str]] = set()


def allowlisted(method: str, field: str) -> bool:
    return (
        (method, "*") in KNOWN_FIELD_GAPS
        or ("*", field) in KNOWN_FIELD_GAPS
        or (method, field) in KNOWN_FIELD_GAPS
    )


def fetch(url: str, dest: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            data = r.read()
        json.loads(data)
        with open(dest, "wb") as f:
            f.write(data)
        return True
    except Exception as e:  # noqa: BLE001 — a scoreboard never crashes on an unreachable backend
        print(f"  (could not fetch {url}: {e})", file=sys.stderr)
        return False


# ---------- schema side ----------
def build_schema_index(spec: dict):
    schemas = spec.get("components", {}).get("schemas", {})

    def props_req(name, seen=None):
        seen = seen or set()
        if name in seen or name not in schemas:
            return set(), set()
        seen.add(name)
        s = schemas[name]
        p = set(s.get("properties", {})); r = set(s.get("required", []))
        for sub in s.get("allOf", []):
            if "$ref" in sub:
                pp, rr = props_req(sub["$ref"].split("/")[-1], seen); p |= pp; r |= rr
            else:
                p |= set(sub.get("properties", {})); r |= set(sub.get("required", []))
        return p, r

    def kind(node, depth=0):
        if depth > 6 or not isinstance(node, dict):
            return "any"
        if "$ref" in node:
            return kind(schemas.get(node["$ref"].split("/")[-1], {}), depth + 1)
        for k in ("anyOf", "oneOf", "allOf"):
            if k in node:
                kinds = {kind(s, depth + 1) for s in node[k]
                         if not (isinstance(s, dict) and s.get("type") == "null")}
                kinds.discard("any")
                return kinds.pop() if len(kinds) == 1 else ("any" if not kinds else sorted(kinds)[0])
        t = node.get("type")
        if isinstance(t, list):
            t = [x for x in t if x != "null"]; t = t[0] if t else "any"
        return {"integer": "number", "number": "number", "boolean": "boolean",
                "array": "array", "object": "object", "string": "string"}.get(
            t, "object" if "properties" in node else "any")

    def types(name, seen=None):
        seen = seen or set()
        if name in seen or name not in schemas:
            return {}
        seen.add(name); s = schemas[name]; out = {}
        for pn, pv in s.get("properties", {}).items():
            out[pn] = kind(pv)
        for sub in s.get("allOf", []):
            if "$ref" in sub:
                out.update(types(sub["$ref"].split("/")[-1], seen))
        return out

    props = {n: props_req(n) for n in schemas}
    tkinds = {n: types(n) for n in schemas}

    def norm(p):
        return re.sub(r"\{[^}]*\}", "{}", re.sub(r"/+", "/", p))

    op_index = {}
    for path, item in spec.get("paths", {}).items():
        for verb, op in item.items():
            if verb not in ("get", "post", "put", "patch", "delete", "head"):
                continue
            req = None
            sch = op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
            if "$ref" in sch:
                req = sch["$ref"].split("/")[-1]
            resp = None
            for code in ("200", "201"):
                c = op.get("responses", {}).get(code, {}).get("content", {}).get("application/json", {}).get("schema", {})
                if "$ref" in c:
                    resp = c["$ref"].split("/")[-1]; break
                if c.get("type") == "array" and "$ref" in c.get("items", {}):
                    resp = "[]" + c["items"]["$ref"].split("/")[-1]; break
            op_index[(verb.upper(), norm(path))] = (req, resp)
    return props, tkinds, op_index, norm


# ---------- Go side ----------
def go_kind(t: str) -> str:
    t = t.strip().lstrip("*")
    if t.startswith("[]"):
        return "array"
    if t.startswith("map["):
        return "object"
    if t == "string" or t == "time.Time":
        return "string"
    if re.match(r"^(u?int\d*|float\d+|byte|rune)$", t):
        return "number"
    if t == "bool":
        return "boolean"
    if t in ("any", "interface{}", "json.RawMessage"):
        return "any"
    if t and t[0].isupper():
        return "object"
    return "any"


def parse_go(sdk_dir: str):
    sre = re.compile(r"^type\s+(\w+)\s+struct\s*\{")
    fieldre = re.compile(r"^\s*(\w+)\s+([\w\.\*\[\]{}]+)\s+`[^`]*json:\"([^\"]+)\"")
    emb = re.compile(r"^\t\*?([A-Z]\w*)\s*$")
    raw = {}
    for path in sorted(glob.glob(os.path.join(sdk_dir, "*.go"))):
        if path.endswith("_test.go"):
            continue
        L = open(path).read().split("\n"); i = 0
        while i < len(L):
            m = sre.match(L[i])
            if not m:
                i += 1; continue
            name, fields, embs, depth = m.group(1), {}, [], 1; i += 1
            while i < len(L) and depth > 0:
                ln = L[i]; depth += ln.count("{") - ln.count("}")
                if depth <= 0:
                    break
                fm = fieldre.match(ln)
                if fm:
                    tag = fm.group(3).split(",")[0]
                    if tag and tag != "-":
                        fields[tag] = go_kind(fm.group(2))
                else:
                    e = emb.match(ln)
                    if e:
                        embs.append(e.group(1))
                i += 1
            raw[name] = (fields, embs); i += 1

    def flat(n, seen=None):
        seen = seen or set()
        if n in seen or n not in raw:
            return {}
        seen.add(n); f, eb = raw[n]; out = dict(f)
        for e in eb:
            for k, v in flat(e, seen).items():
                out.setdefault(k, v)
        return out

    return raw, flat


def parse_methods(sdk_dir: str, norm):
    src = "\n".join(open(f).read() for f in sorted(glob.glob(os.path.join(sdk_dir, "*.go")))
                    if not f.endswith("_test.go"))
    methods = []
    for m in re.finditer(r"func \(c \*Client\) (\w+)\(", src):
        name = m.group(1); br = src.find("{", m.end()); sig = src[m.start():br]
        depth = 0; j = br; end = br
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    end = j; break
            j += 1
        body = src[br:end]
        rm = re.search(r"\)\s*\(\s*\*?(\w+)\s*,\s*error\s*\)\s*$", sig.replace("\n", " "))
        ret = rm.group(1) if rm else None
        am = re.search(r'doJSON\(ctx,\s*"(\w+)",\s*([^,]+),\s*([^,]+),\s*&?(\w+)', body)
        ag = re.search(r"doGet\(ctx,\s*([^,]+),\s*&?(\w+)", body)
        verb = pe = bodyvar = None
        if am:
            verb, pe, bodyvar = am.group(1), am.group(2), am.group(3).strip()
        elif ag:
            verb, pe = "GET", ag.group(1)
        methods.append((name, ret, verb, pe, bodyvar, body))

    def normgo(pe):
        if not pe:
            return None
        lits = re.findall(r'"([^"]*)"', pe)
        if not lits:
            return None
        p = "".join(lits)
        if "+" in pe:
            p += "{}"
        return norm(re.sub(r"\{[^}]*\}", "{}", p))

    return methods, normgo


def route_key(verb, np, op_index):
    for k in ((verb, np), (verb, (np or "").rstrip("/")), (verb, (np or "") + "/")):
        if k in op_index:
            return k
    return None


def check(spec_path: str, sdk_dir: str, label: str, strict: bool) -> int:
    spec = json.load(open(spec_path))
    props, tkinds, op_index, norm = build_schema_index(spec)
    raw, flat = parse_go(sdk_dir)
    methods, normgo = parse_methods(sdk_dir, norm)

    # Per (method) accumulation. A RESPONSE required-missing is gate-worthy only when the Go type
    # genuinely OVERLAPS the schema (a real partial strip of a bound type). Zero-overlap cases are
    # name/wrapper collisions (e.g. a method returning a generic MessageResponse) — reported as
    # informational name-mismatches, not gated, to keep the gate meaningful.
    resp_reqmiss, resp_typemiss, req_reqmiss, name_mismatch = [], [], [], []
    for name, ret, verb, pe, bodyvar, body in methods:
        if not verb:
            continue
        np = normgo(pe)
        key = route_key(verb, np, op_index)
        if not key:
            continue
        reqS, respS = op_index[key]
        if ret and respS and not respS.startswith("[]"):
            gf_kinds = flat(ret); gf_names = set(gf_kinds)
            p, r = props.get(respS, (set(), set()))
            if p:
                miss = p - gf_names
                overlap = bool(p & gf_names)
                reqmiss = sorted(r & miss)
                if reqmiss and overlap:
                    resp_reqmiss.append((name, ret, respS, reqmiss))
                elif ret != respS and miss and not overlap:
                    name_mismatch.append((name, ret, respS, sorted(miss)[:8]))
                for f, sk in tkinds.get(respS, {}).items():
                    gk = gf_kinds.get(f)
                    if gk and gk != "any" and sk != "any" and gk != sk:
                        resp_typemiss.append((name, f, gk, sk, ret, respS))
        if reqS and bodyvar:
            sm = (re.search(r"\b" + re.escape(bodyvar) + r"\s+([A-Z]\w+)\b", body)
                  or re.search(r"\b" + re.escape(bodyvar) + r"\s*:?=\s*([A-Z]\w+)\{", body))
            if sm:
                t = sm.group(1); gf = set(flat(t)); p, r = props.get(reqS, (set(), set()))
                if p:
                    rm = sorted(r & (p - gf))
                    if rm:
                        req_reqmiss.append((name, t, reqS, rm))

    g_resp = [x for x in resp_reqmiss if not allowlisted(x[0], "*") and
              any(not allowlisted(x[0], f) for f in x[3])]
    g_type = [x for x in resp_typemiss if not allowlisted(x[0], x[1])]
    g_req = [x for x in req_reqmiss if not allowlisted(x[0], "*")]

    print(f"\n=== {label}: {spec.get('info', {}).get('title')} "
          f"{spec.get('info', {}).get('version')} ===")
    print(f"    methods with a response required-field strip: {len(resp_reqmiss)} "
          f"({len(g_resp)} outside allowlist)")
    print(f"    TYPE mismatches (mis-decode risk):            {len(resp_typemiss)} "
          f"({len(g_type)} outside allowlist)")
    print(f"    request required-missing:                     {len(req_reqmiss)} "
          f"({len(g_req)} outside allowlist)")
    print(f"    name/wrapper-mismatch responses (info only):  {len(name_mismatch)}")
    for name, f, gk, sk, ret, sch in g_type:
        print(f"      TYPE   {name}: `{ret}`.{f} is Go {gk} but server sends {sk} (schema {sch})")
    for name, t, sch, rm in g_req:
        print(f"      REQ    {name}: request `{t}` lacks required {', '.join(rm)} ({sch})")
    for name, ret, sch, rm in g_resp:
        print(f"      RESP   {name}: `{ret}` lacks required {', '.join(rm)} (schema {sch})")

    gated = len(g_resp) + len(g_type) + len(g_req)
    return 1 if (strict and gated) else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Field+type contract gate vs both auth backends.")
    ap.add_argument("--spec", help="a saved openapi.json (skips fetching both backends)")
    ap.add_argument("--python-url", default=PYTHON_URL)
    ap.add_argument("--goauth-url", default=GOAUTH_URL)
    ap.add_argument("--sdk", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if any non-allowlisted required-missing OR type mismatch remains")
    ap.add_argument("--no-allowlist", action="store_true",
                    help="ignore KNOWN_FIELD_GAPS (to see the true gap set / verify the gate can fail)")
    args = ap.parse_args()
    if args.no_allowlist:
        KNOWN_FIELD_GAPS.clear()

    if args.spec:
        return check(args.spec, args.sdk, os.path.basename(args.spec), args.strict)

    rc = 0
    reached = 0
    tmp = "/tmp/auth-field-drift"
    os.makedirs(tmp, exist_ok=True)
    for label, url in (("python", args.python_url), ("goauth", args.goauth_url)):
        dest = os.path.join(tmp, f"{label}.json")
        if fetch(url, dest):
            reached += 1
            rc |= check(dest, args.sdk, label, args.strict)
        else:
            print(f"    (skipped {label}: not reachable — {url})", file=sys.stderr)
    if reached == 0:
        print("!! neither backend reachable; pass --spec <saved openapi.json> to run offline.",
              file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
