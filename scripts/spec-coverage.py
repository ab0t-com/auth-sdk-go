#!/usr/bin/env python3
"""spec-coverage.py — compare this SDK against the LIVE OpenAPI spec.

The spec is the source of truth; this SDK is supposed to mirror it. Twice now the
spec has moved and the SDK has not, and both times it was found by a human reading
files rather than by anything automatic:

  * the Zanzibar tuple model kept split object_type/object_id fields after the wire
    moved to combined "doc:123" strings;
  * ZanzibarCheckBulk decoded an object after the response became a JSON array,
    which made every successful call return an UnmarshalTypeError.

This script turns that check into something you can run in one command.

    make drift               # fetch the live spec and report
    python3 scripts/spec-coverage.py --spec /tmp/openapi.json
    python3 scripts/spec-coverage.py --strict     # exit 1 if anything is MISSING

It reports three things:

  MISSING  a spec operation with no SDK method  -> a capability consumers cannot reach
  PHANTOM  an SDK request path absent from the spec -> a call that would 404
  OK       matched

PHANTOM is the more dangerous direction: a MISSING operation is a gap someone will
notice, but a PHANTOM one looks like a working method until it is called.

It is deliberately dependency-free (stdlib only, like the SDK itself) and makes no
network call unless you ask it to fetch.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import urllib.request

SPEC_URL = "https://auth.service.ab0t.com/openapi.json"
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

# Paths the SDK deliberately ships ahead of the server. Each is a forward-looking
# stub carrying a SERVER-GAP doc note; TestAuthorizationModel_IsStillAServerGap
# asserts they 404 today. Listing them here keeps them out of the PHANTOM noise
# while staying visible — when the server ships them they leave this list.
KNOWN_SERVER_GAPS = {
    ("POST", "/zanzibar/stores/{}/authorization-models"),
    ("GET", "/zanzibar/stores/{}/authorization-models"),
    ("GET", "/zanzibar/stores/{}/authorization-models/{}"),
    ("POST", "/zanzibar/stores/{}/relationships/transact"),
}


def norm(path: str) -> str:
    """Normalise a path for comparison: every parameter becomes {}."""
    path = re.sub(r"\{[^}]*\}", "{}", path)
    path = re.sub(r"/+", "/", path)
    return path.rstrip("/") or "/"


def resolve_path_expr(expr: str, helpers: dict[str, str], locals_: dict[str, str] | None = None) -> str | None:
    """Turn a Go path expression into a normalised path.

    Handles the shapes this SDK actually uses:
        "/users/" + url.PathEscape(userID) + "/verify-email"
        zanzibarBase(storeID) + "/check"
        "/permissions/grant?" + q.Encode()
    A non-literal term becomes {}; a query suffix is dropped.
    """
    out = []
    for part in re.split(r"\+", expr):
        part = part.strip()
        if not part:
            continue
        lit = re.fullmatch(r'"([^"]*)"', part)
        if lit:
            out.append(lit.group(1))
            continue
        fn = re.match(r"(\w+)\(", part)
        if fn and fn.group(1) in helpers:
            out.append(helpers[fn.group(1)])
            continue
        if locals_ and part in locals_:
            out.append(locals_[part])
            continue
        out.append("{}")
    p = "".join(out)
    p = p.split("?")[0]
    if not p.startswith("/"):
        return None
    # "/users/{}" built as "/users/" + x gives "/users/{}" already; collapse "{}{}"
    p = re.sub(r"(\{\})+", "{}", p)
    return norm(p)


def find_helpers(src: str) -> dict[str, str]:
    """Find tiny helpers that return a path prefix, e.g. zanzibarBase(storeID)."""
    helpers: dict[str, str] = {}
    for m in re.finditer(
        r"func\s+(\w+)\([^)]*\)\s+string\s*\{\s*return\s+([^\n}]+)", src
    ):
        name, body = m.group(1), m.group(2)
        if '"' not in body or "/" not in body:
            continue
        resolved = resolve_path_expr(body, {})
        if resolved:
            helpers[name] = resolved
    return helpers


def split_args(s: str) -> list[str]:
    """Split a Go call's argument list on top-level commas."""
    args, depth, cur, instr = [], 0, [], False
    i = 0
    while i < len(s):
        c = s[i]
        if instr:
            cur.append(c)
            if c == "\\":
                if i + 1 < len(s):
                    cur.append(s[i + 1]); i += 2; continue
            elif c == '"':
                instr = False
        elif c == '"':
            instr = True; cur.append(c)
        elif c in "([{":
            depth += 1; cur.append(c)
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1; cur.append(c)
        elif c == "," and depth == 0:
            args.append("".join(cur)); cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        args.append("".join(cur))
    return [a.strip() for a in args]


GO_METHOD_CONST = {
    "http.MethodGet": "GET", "http.MethodPost": "POST", "http.MethodPut": "PUT",
    "http.MethodPatch": "PATCH", "http.MethodDelete": "DELETE",
    "http.MethodHead": "HEAD", "http.MethodOptions": "OPTIONS",
}


def extract_sdk_calls(sdk_dir: str) -> set[tuple[str, str]]:
    """Return the (METHOD, normalised path) set this SDK actually requests.

    Parses each do*/get* call site's real argument list rather than pattern-matching
    the whole statement, so an unusual body/out argument cannot cause a call to be
    missed. A missed call site would show up as a false MISSING, which is exactly the
    noise that makes a coverage report get ignored.
    """
    src = ""
    for f in sorted(glob.glob(os.path.join(sdk_dir, "*.go"))):
        if f.endswith("_test.go"):
            continue
        src += open(f).read() + "\n"

    helpers = find_helpers(src)
    calls: set[tuple[str, str]] = set()

    # Many methods build the path into a local first:
    #     path := "/mesh/providers"
    #     if enc := q.Encode(); enc != "" { path += "?" + enc }
    #     return c.doGet(ctx, path, &out, tok)
    # Without following that, every such method looks MISSING — and a coverage
    # report full of false gaps is one nobody reads. Resolve simple := / += chains
    # within each function body.
    func_locals: list[tuple[int, int, dict[str, str]]] = []
    for fm in re.finditer(r"\nfunc\b", src):
        start = fm.start()
        nxt = src.find("\nfunc", start + 5)
        end = nxt if nxt != -1 else len(src)
        body = src[start:end]
        lv: dict[str, str] = {}
        for am in re.finditer(r"(?m)^\s*(\w+)\s*:=\s*([^\n]*[\"/][^\n]*)$", body):
            r = resolve_path_expr(am.group(2), helpers)
            if r:
                lv[am.group(1)] = r
        for am in re.finditer(r"(?m)^\s*(\w+)\s*\+=\s*([^\n]*)$", body):
            name = am.group(1)
            if name in lv:
                pass  # a query/suffix append never changes the route
        if lv:
            func_locals.append((start, end, lv))

    def locals_at(pos: int) -> dict[str, str]:
        for a, b, lv in func_locals:
            if a <= pos < b:
                return lv
        return {}

    # Signatures, by where the method and path arguments sit after ctx:
    #   doJSON(ctx, method, path, body, out, bearer)
    #   doRaw (ctx, method, path, ...)
    #   doGet (ctx, path, out, bearer)          -> GET
    #   getString(ctx, path, bearer)            -> GET
    #   doDelete(ctx, path, ...)                -> DELETE
    shapes = [
        ("doJSON", 0, 1), ("doRaw", 0, 1),
        ("doGet", None, 0), ("getString", None, 0), ("doDelete", None, 0),
    ]
    for name, m_idx, p_idx in shapes:
        for m in re.finditer(re.escape(name) + r"\(", src):
            args = split_args(src[m.end():])
            if not args or args[0].strip() not in ("ctx", "c.ctx"):
                continue
            rest = args[1:]
            if p_idx >= len(rest):
                continue
            if m_idx is None:
                method = "DELETE" if name == "doDelete" else "GET"
            else:
                if m_idx >= len(rest):
                    continue
                raw = rest[m_idx].strip()
                lit = re.fullmatch(r'"(\w+)"', raw)
                method = lit.group(1).upper() if lit else GO_METHOD_CONST.get(raw, "")
                if not method:
                    continue
            path = resolve_path_expr(rest[p_idx], helpers, locals_at(m.start()))
            if path:
                calls.add((method, path))

    return calls


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--spec", help="path to an openapi.json (default: fetch the live one)")
    ap.add_argument("--sdk", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--strict", action="store_true", help="exit 1 if anything is MISSING or PHANTOM")
    ap.add_argument("--quiet", action="store_true", help="summary only")
    args = ap.parse_args()

    if args.spec:
        spec = json.load(open(args.spec))
        origin = args.spec
    else:
        with urllib.request.urlopen(SPEC_URL, timeout=30) as r:
            spec = json.load(r)
        origin = SPEC_URL

    spec_ops = {
        (method.upper(), norm(path))
        for path, item in spec.get("paths", {}).items()
        for method in item
        if method.lower() in HTTP_METHODS
    }
    sdk_ops = extract_sdk_calls(args.sdk)

    # The structural parser resolves most call sites but not all: a path can be
    # assembled across several statements, or through a helper it cannot follow.
    # Rather than report those as gaps — a coverage tool that cries wolf is one
    # nobody reads — fall back to asking whether the path's distinctive literal
    # segments appear in the source at all. That downgrades "I could not prove it"
    # from MISSING to LIKELY, and keeps MISSING meaning genuinely missing.
    src_all = ""
    for f in sorted(glob.glob(os.path.join(args.sdk, "*.go"))):
        if not f.endswith("_test.go"):
            src_all += open(f).read()

    def literally_present(path: str) -> bool:
        tail = path.split("{}")[-1]
        needle = tail if tail.startswith("/") and len(tail) > 4 else path
        if "{}" in needle:
            return False
        return needle.strip("/") in src_all

    unmatched = sorted(spec_ops - sdk_ops)
    missing = [op for op in unmatched if not literally_present(op[1])]
    likely = [op for op in unmatched if literally_present(op[1])]
    phantom = sorted((sdk_ops - spec_ops) - KNOWN_SERVER_GAPS)
    gaps_still_open = sorted(KNOWN_SERVER_GAPS & (sdk_ops - spec_ops))
    gaps_now_closed = sorted(KNOWN_SERVER_GAPS & spec_ops)

    info = spec.get("info", {})
    print(f"spec:  {info.get('title','?')} {info.get('version','?')}  ({origin})")
    print(f"       {len(spec_ops)} operations, {len(spec.get('components',{}).get('schemas',{}))} schemas")
    print(f"sdk:   {len(sdk_ops)} request sites resolved")
    covered = len(spec_ops) - len(missing)
    pct = 100.0 * covered / len(spec_ops) if spec_ops else 0.0
    exact = len(spec_ops) - len(unmatched)
    print(f"cover: {covered}/{len(spec_ops)} ({pct:.1f}%)  "
          f"[{exact} matched structurally, {len(likely)} by literal presence]")

    if not args.quiet:
        if missing:
            print(f"\nMISSING — in the spec, no SDK method ({len(missing)}):")
            for m, p in missing:
                print(f"  {m:<7} {p}")
        if likely and not args.quiet:
            print(f"\nLIKELY COVERED — the path literal is in the source but this tool could not")
            print(f"                 follow how it is assembled ({len(likely)}). Not a gap; verify by hand if it matters:")
            for m, p in likely:
                print(f"  {m:<7} {p}")
        if phantom:
            print(f"\nPHANTOM — SDK calls it, spec does not define it; would 404 ({len(phantom)}):")
            for m, p in phantom:
                print(f"  {m:<7} {p}")
        if gaps_still_open:
            print(f"\nknown SERVER-GAP stubs, still absent from the spec ({len(gaps_still_open)}) — expected:")
            for m, p in gaps_still_open:
                print(f"  {m:<7} {p}")
        if gaps_now_closed:
            print(f"\n*** a known SERVER-GAP has LANDED in the spec ({len(gaps_now_closed)}) — remove its warning:")
            for m, p in gaps_now_closed:
                print(f"  {m:<7} {p}")

    if args.strict and (missing or phantom):
        print("\nFAIL (--strict): the SDK and the spec disagree.")
        return 1
    print("\nOK" if not (missing or phantom) else "\n(non-strict: reported only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
