# Contributing

## The one rule that matters

**The live OpenAPI spec is the source of truth**, not this SDK's types and not its
documentation:

```
https://auth.service.ab0t.com/openapi.json
```

Every request/response type here is supposed to mirror a schema in that document.
When they disagree, the spec wins and this SDK has a bug.

This is not a theoretical concern. Two of the defects fixed in v0.1.0 —
`ZanzibarCheckBulk` decoding the wrong shape, and the Zanzibar tuple model using
split `object_type`/`object_id` fields where the wire uses combined `"doc:123"`
strings — were both cases of the SDK drifting from a spec that had moved. So:

**Before changing a type, re-fetch the spec and check.**

```bash
curl -sS https://auth.service.ab0t.com/openapi.json -o /tmp/spec.json
jq '.components.schemas.CheckPermissionResponse' /tmp/spec.json
jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[] | "\(.key|ascii_upcase) \($p)"' /tmp/spec.json | sort
```

## Constraints

- **Standard library only.** This module has no `require` block and must keep it
  that way. It is embedded in other people's binaries; a dependency here becomes a
  dependency everywhere. This is enforced by consumers' tests, not just by
  convention.
- **Depend on interfaces.** `Validator` and `Authorizer` exist so callers can mock
  authentication and authorization without a live service. Keep them small and
  keep `*Client` satisfying them.
- **Fail closed.** Any new helper that returns a boolean decision must return
  `false` on error, on an empty result, and on an out-of-range index. Never invent
  an "allow" the server did not give you.
- **Mark server gaps.** If you add a method for a route the service does not
  expose yet, give it a `SERVER-GAP` doc paragraph naming the missing route, and
  add it to the gap test so the gap is recorded executably.

## Workflow

```bash
make test      # go test ./...
make vet       # go vet ./...
make check     # fmt + vet + test + the stdlib-only assertion
```

Every change needs a test. A test that cannot fail proves nothing — make sure
yours fails before your fix and passes after.

Update `CHANGELOG.md` in the same commit. Mark breaking changes **BREAKING** and
say what a consumer has to do about it.
