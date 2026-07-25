# Releasing

**Every change that reaches `main` gets a version bump.** Not "significant" changes — every one.

## Why this is a rule and not a judgement call

On 2026-07-25 this SDK was published as `v0.1.0`. A fix landed on `main` shortly after. Every local
test passed; `make check` was clean. Then a clean-room test — a fresh module, `go get` by tag, run
the documented surface — printed:

```
untyped guard: <nil>
```

The guard was not there. It had been committed *after* the tag, so nobody consuming the published
version had it. Nothing was broken and nothing was wrong locally; the work simply had not been
released, and there was no signal to say so.

That is the failure this file exists to prevent. It cannot be fixed by remembering harder, because
the local state always looks correct. It is fixed by making the bump part of shipping.

## Three things must agree

| Thing | Where | Why it matters |
|---|---|---|
| `Version` | `version.go` | goes out in the `User-Agent` of every request, so the service can attribute traffic and spot a client running a known-bad contract |
| A changelog section | `CHANGELOG.md` | the only place a consumer learns what changed and whether it breaks them |
| The git tag | `vX.Y.Z` | the only thing `go get` can actually fetch |

`TestVersionMatchesChangelog` fails if the first two disagree. `make release` refuses if any of the
three would be left behind.

## How to release

```bash
make release VERSION=0.4.0
```

It refuses, before touching anything, if:

- the working tree is dirty — a release must be reproducible from the tag alone;
- `CHANGELOG.md` has no `## [0.4.0]` section — write it *first*, while you still remember what you
  changed and, more importantly, who it breaks;
- the tag already exists — re-tagging silently changes what a consumer already fetched;
- `make check` fails (gofmt, vet, tests, the stdlib-only assertion).

Then it updates `version.go`, commits, tags, and pushes both.

## Which number to bump

Pre-1.0, so the middle number carries breaking changes.

| Bump | When |
|---|---|
| **minor** (`0.3.0` → `0.4.0`) | the default. Any new method, any behaviour change, any fix a consumer could notice. When in doubt, minor. |
| **patch** (`0.3.0` → `0.3.1`) | genuinely invisible to consumers: a typo in a doc comment, a test-only change, tooling that ships no API. |

Prefer minor. A version number costs nothing; a consumer running code you thought you had shipped
costs an afternoon of debugging the wrong thing.

**Mark breaking changes explicitly in the changelog**, with what a consumer has to do about it. Being
pre-1.0 permits a break; it does not excuse an unannounced one.

## After releasing

The Go module proxy takes a few minutes to index a new tag. Until it does,
`go get …@vX.Y.Z` may return:

```
verifying module: reading https://sum.golang.org/lookup/…: 500 Internal Server Error
```

That is the checksum database still catching up, not a broken release. Retry.

Then verify from the outside — the whole point is that local success proved nothing:

```bash
cd $(mktemp -d) && go mod init loadtest
go get github.com/ab0t-com/auth-sdk-go@vX.Y.Z
go list -m all        # must be exactly this module and nothing else
```

Write a few lines exercising whatever you just shipped and run them. If the new behaviour is not
there, the tag is wrong — which is precisely how the v0.1.0 gap was found.
