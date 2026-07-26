# Changelog

All notable changes to the ab0t Auth Service Go SDK.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] — 2026-07-26

### Fixed — a silent contract bug in the org hierarchy

- **`OrgHierarchyResponse` decoded to zero values.** The SDK declared it as
  `{root, organizations}`; the service has never returned that shape. The real
  contract is `{organization, teams, children, user_count, team_count}`, recursive
  through `children` — which is how **companies of companies** are represented.
  JSON decoding does not complain about names it does not recognise, so
  `GetOrgHierarchy` returned an empty struct, silently, forever. The old test
  asserted the wrong shape and therefore passed. Same class as the bulk-check bug
  in v0.2.0; the reason `make drift` exists.
  Added `OrgInfo`, `HierarchyTeam`, `HierarchyUser`, and `WalkOrgTree` for the
  recursion every caller would otherwise write by hand.

### Added — the CLI is multi-tenant now, because the service always was

The service is multi-tenant by default: users belong to many organizations,
organizations nest via `parent_id`, and a session can be switched between them.
The CLI stored **one flat credential file** — a single-tenant store for a
multi-tenant product. That is how a staging login ends up running against
production an hour later without a single wrong command being typed.

- **Tenant profiles.** `$XDG_CONFIG_HOME/ab0t/auth-sdk-go/profiles/<name>.json`,
  one file per tenant, 0600 inside 0700, written atomically, namespaced per tool
  so several ab0t clients can share the config root. Each profile carries its
  credential *and its tenancy* — org, slug, service — which is what lets `whoami`
  answer "which tenant am I in" rather than only "who am I". Matches the house
  convention (`connect-cli`'s `connect-auth`: login, API keys, dev/prod, headless).
  A legacy `auth.json` is imported as `default` and renamed aside, never deleted.
- **`profile`** — list, use, remove; plus a global `--profile` and `$AB0T_PROFILE`.
- **`orgs`** — organizations this credential belongs to, with your role and
  `[default]` / `[personal]` / `[sub-org of …]` / `[workspace]` markers.
- **`org-tree`** — the organization hierarchy as an indented tree.

## [0.8.0] — 2026-07-26

### Added — from 105 further customer journeys (15 per hat, all automated)

- **`help --json`** — the capability catalogue as data, whole or per verb. Every
  other surface was machine-readable and this one was not, so an agent
  discovering the tool had to regex prose. That was the one place we forced a
  machine to behave like a human, in the hat we otherwise serve best.
- **`--dry-run`** on `grant`, `revoke` and `revoke-all` — prints exactly what
  would change and sends nothing. Every evaluator was inventing their own safe
  path (usually a throwaway store) because none was offered; a write verb with no
  rehearsal is one people are afraid of.
- **`--expires`** on `grant`, taking a duration (`24h`) or an RFC3339 instant.
  Support engineers were granting **permanent** access for temporary needs because
  the CLI had no expiry, though the service supports it — a permissions leak
  created by our own interface. Also `ZanzibarStore.RelateUntil` in the SDK.
- **`revoke-all <object>`** — removes every relationship on an object. Offboarding
  was a manual loop that required already knowing every relation; anything
  forgotten stayed granted, silently. Object-scoped; the per-principal case is
  named as still open rather than left to be rediscovered.
- **`about`** — licence, source, issues, security contact, changelog, the Go SDK
  import line, and the dependency count. Three separate hats were leaving the tool
  to find basic facts.

### Fixed
- `can`'s help now documents that exit code 2 is an **answer**, not an error, and
  gives the capture-first idiom — `set -e` / `set -o pipefail` otherwise abort a
  script on a perfectly good DENIED. The expanded harness tripped over this itself.

## [0.7.1] — 2026-07-26

### Fixed
- `ab0t-auth --json version` and `--<flag> help <verb>` failed with
  `unknown command`. Leading global flags were hoisted *after* the `help` and
  `version` special cases, so those two never saw the reordered arguments. Found
  by the clean-room check on v0.7.0 — the local build was fine, which is precisely
  why that check exists.
- `version` now honours `--json`, so an agent pinning a version does not have to
  special-case the one command that spoke only prose.

## [0.7.0] — 2026-07-26

### Added — the CLI now behaves like an interactive support page

A user-journey product review walked 28 customer journeys cold against the real
binary. 20 of 28 stalled on the same class of defect: **the tool knew what the
customer would want next and did not say it.** None of it was a missing feature —
it was information already in the binary, withheld.

- **Deep help for every verb, reachable both ways.** `help <verb>` and
  `<verb> --help` now render the same document: what it's FOR, a worked example
  **with real output**, the failures you will actually hit and what they mean, and
  what people usually run next. Previously `help can` printed the generic
  top-level page **and exited 0** — the customer asked one question, got a
  different answer, and was told it succeeded.
- **A common-commands surface.** The bare invocation now says what the tool is for
  before what it can do, lists the ~10 things people actually do (ordered by when a
  newcomer meets them, not alphabetically), and carries a four-step NEW HERE? path.
  `doctor` is first, because stuck people do not read to the bottom of a list.
- **Next-step hints.** After a command, at most two things people usually do next.
  A DENIED now points at `why` — six journeys across four hats stalled on exactly
  that. Hints go to **stderr**, and are silent under `--json` and `--quiet`: a
  script did not ask for advice, and a hint must never contaminate a piped result.

### Fixed

- **Global flags now work before OR after the verb.** `ab0t-auth --server X health`
  previously failed with `unknown command "--server"`. `git`, `docker` and
  `kubectl` all accept the leading form. Found when the journey harness — written
  by the same person who wrote the CLI — made exactly that mistake on its first run.
- **A flag in command position** gets a message naming the real problem instead of
  "unknown command", which sent people looking for a command that never existed.
- **`health` printed a raw Go struct** (`status: &{healthy map[]}`) — a pointer
  dump in the command recommended as the safe first thing to run.

## [0.6.0] — 2026-07-25

### Added
- **`ab0t-auth` — a command-line client.**

  ```bash
  go install github.com/ab0t-com/auth-sdk-go/cmd/ab0t-auth@latest
  ab0t-auth doctor
  ab0t-auth can user:alice view doc:123 --store my-store
  ```

  Answers from a terminal the questions that otherwise need a Go program: is this
  token valid, who am I, can alice read this document and why not, is the service
  up, and what is wrong with my configuration.

  **Still zero dependencies.** A CLI would normally reach for cobra; that would add
  cobra and pflag to this module and break the stdlib-only guarantee for every
  consumer, none of whom asked for a CLI. Subcommand dispatch is written against
  the stdlib `flag` package instead, so `go install` pulls exactly nothing else.

  **Accessibility is built in, not bolted on**, and each property has a test
  because a regression in any of them is invisible to a sighted developer at an
  interactive terminal:
  - `NO_COLOR` (any non-empty value) means **no ANSI at all**, not less colour;
    a non-TTY, `TERM=dumb` and `--json` each disable colour too.
  - **Colour is never the only signal** — strip every escape sequence and the
    output is byte-identical to the plain rendering. Verified by a test.
  - `--json` on every command, with the same facts as the text output.
  - Data on stdout, diagnostics on stderr, so `cmd --json > out.json` yields a
    parseable file and the human still sees the errors.
  - No spinners, progress bars, cursor movement or box drawing anywhere.
  - Every prompt has a non-interactive equivalent; a prompt that would block in CI
    is skipped rather than hanging.
  - Exit codes: `0` ok/ALLOWED, `1` error, `2` DENIED, `3` no credential — so
    `if ab0t-auth can …; then` works in a script.

  Credential storage follows the house pattern: a JSON file at **0600 inside a
  0700 directory**, written atomically, resolved `--token` → `$AB0T_AUTH_TOKEN` →
  `$AUTH_SERVICE_KEY` → file. No command ever prints a credential in full.

  `doctor` reports every check rather than stopping at the first failure — the
  second failure is often what explains the first.

## [0.5.0] — 2026-07-25

### Added
- **`WithObserver(fn)` — an observability seam.** One `RequestInfo` per completed
  HTTP attempt: method, endpoint, status, duration, attempt number, whether a retry
  follows, error, and the service's request id. **Retries are visible** — a retry
  storm that looks like one slow call is the thing you most need to see.

  Deliberately a callback, not a logger: a logger in a library imposes three
  decisions on the consumer (which package, which format, which level) and would
  add a dependency to a module whose defining property is having none. This feeds
  slog, zap, OTel or a test assertion equally.

  It carries **no headers and no bodies**. This client's job is handling
  credentials, and an observability hook is exactly what ends up in a log
  aggregator; a path and a status cannot leak a token. The endpoint has its query
  string stripped, so it is usable as a metric label.

- **`authclienttest` — exported test doubles.** `Fake` (implements both interfaces,
  records calls) plus ready-made `Allow()`, `Deny()` and **`Unavailable()`**, and
  `Server`, an httptest-backed fake auth service for exercising the *real* client.

  `Unavailable()` is the point. Every consumer writes allow and deny fakes; almost
  nobody tests what their handler does when the auth service is unreachable — the
  one path where a mistake means an outage silently unlocks the write surface. Now
  it is one line. A separate package, so the root's dependency surface is untouched.

- **`authmw` — the HTTP middleware, promoted out of `examples/`.** `Authenticate`
  (attach identity; missing credential stays anonymous, invalid is 401, unreachable
  is 503) and `Require(action, resourceType)` (401 / 403 / 503 / handler), plus
  `RequireFunc` for routers that compose `func(http.Handler) http.Handler`.

  It lived only in an example, which meant every consumer copy-pasted it, inherited
  whatever was wrong with it that day, and got none of the fixes — the wrong
  distribution mechanism for a component whose failure mode is "the write surface
  is silently unlocked". **Fail-closed is the default and cannot be forgotten:**
  `FailOpen` must be set deliberately, and a test asserts the default has not
  drifted.

## [0.4.0] — 2026-07-25

### Added
- **A release SOP that is enforced rather than remembered.** `make release VERSION=x.y.z`
  refuses on a dirty tree, a missing changelog section, an existing tag, or a
  failing `make check`, then bumps `version.go`, commits, tags and pushes.
  `TestVersionMatchesChangelog` fails if `Version` has no changelog section behind
  it. See `RELEASING.md`.

  This exists because v0.1.0 shipped without a fix that was already on `main` — it
  had been committed after the tag. Every local test passed; only a clean-room
  `go get` by tag revealed it. Remembering harder does not fix that; a guard does.

## [0.3.0] — 2026-07-25

### Added
- **`Client.Store(storeID, token)` — the ergonomic Zanzibar surface.** The raw methods
  mirror the HTTP API exactly, which is the right foundation but makes a one-line
  question cost six lines of ceremony and a repeated store id and token on every
  call. `ZanzibarStore` binds them once and exposes the questions people actually
  ask: `Can`, `CanAll`, `CanAny`, `Why`, `WhatCan` ("which docs can alice view" —
  the filtered index page), `WhoCan` ("who can view this" — the sharing dialog,
  groups expanded), `RelationsOn`, `Relate`, `Unrelate`, plus `*ID` variants and a
  `Check(...)` batch builder and `As(token)` for per-request tokens.

  Types are separate arguments (`"user", "alice"`) rather than something the caller
  concatenates, because a mistyped combined id produces a silent DENY, not an error.

  Every boolean fails closed: an error is false, an **empty batch is false**
  ("nothing was asked" is not "everything is permitted"), and a bulk response whose
  length does not match the request is an error rather than a guess. `Relate` and
  `Unrelate` treat `success:false` as an error even on a 200 — a write reported as
  refused is not a write.

  It is a layer over the raw methods, never a replacement: everything the service
  can do stays reachable.

## [0.2.0] — 2026-07-25

### Added
- Zanzibar combined ids are now validated before the request. `ZanzibarCheck` and
  `ZanzibarCheckBulk` return `*ErrUntypedID` when a `subject` or `object` is
  missing its `type:` prefix, instead of sending a request that can only come back
  `allowed:false`. A bare `"alice"` where `"user:alice"` was meant is
  indistinguishable, server-side, from an id it has simply never seen — so the
  caller reads a legitimate DENY and debugs the wrong thing. The bulk form names
  the offending index (`check 2: …`).
- `make drift` / `scripts/spec-coverage.py` — compares this SDK against the live
  OpenAPI spec in both directions and reports MISSING (a capability consumers
  cannot reach) and PHANTOM (a call that would 404). Current: 283/283 operations
  reachable. Stdlib-only; no network unless you ask it to fetch.

### Changed
- The staged CI workflow is **manual-dispatch only** (`workflow_dispatch`, no
  `push`/`pull_request`), so installing it does not start anything running.
  Dropped the CI status badge, which would have advertised a workflow that never
  fires.

## [0.1.0] — 2026-07-25

First public release. Extracted from a private in-repo client, reconciled against
the live ab0t Auth Service OpenAPI 3.1 spec, and published under its own module
path `github.com/ab0t-com/auth-sdk-go`.

### Added
- `DeleteCurrentUser` — `DELETE /users/me`, the GDPR / right-to-erasure
  self-delete flow, guarded by a confirm-email match. Previously the endpoint had
  no representation in the SDK at all, so a consumer offering "delete my account"
  had to hand-roll the call and re-derive the confirmation contract.
- `/mesh/providers` service-discovery surface — `ListMeshProviders`,
  `GetMeshProvider`, `PublishMeshProvider`, with `MeshProvider`,
  `MeshProviderPublishRequest/Response` and the tier types. The whole subsystem
  was previously absent.
- `BulkCheckResults.Allowed(i)` and `.AllAllowed()` helpers. Both fail CLOSED:
  an out-of-range index and an empty result set are `false`, because "nothing was
  checked" is not "everything is permitted".
- `Version`, reported in the `User-Agent` of every request so the service can
  attribute traffic and identify clients running a version with a known-bad
  contract.

### Fixed
- **`ZanzibarCheckBulk` returned an error on every successful call.** The live
  spec defines the `check/bulk` 200 as a bare JSON **array** of
  `CheckPermissionResponse`; the SDK decoded it into a struct with a `results`
  map, so every response failed with `json.UnmarshalTypeError` even when the
  server had answered correctly. This was an honest best-effort guess made while
  the server had no declared response schema — the server has since declared one.
- **The JWKS cache was unbounded.** `OrgJWKS` keyed one entry per organization
  and nothing ever evicted, so a long-lived multi-tenant process grew the map by
  one entry per distinct org ever seen, for the life of the process. It is now
  bounded (512 entries) with stalest-first eviction; eviction only ever costs a
  refetch.

### Changed
- **BREAKING:** module path is `github.com/ab0t-com/auth-sdk-go`.
- **BREAKING:** `ZanzibarCheckBulk` now returns `BulkCheckResults`
  (`[]CheckPermissionResponse`, in request order) instead of `*BulkCheckResponse`.
  The old type is removed; it could not decode a real response.
- `User-Agent` no longer names one particular consumer.

### Known gaps
- Four `authzmodel.go` methods (`ReadAuthorizationModel`,
  `ListAuthorizationModels`, `WriteAuthorizationModel`,
  `WriteAndDeleteRelationships`) target routes the auth service does not expose
  yet. They are shipped as forward-looking stubs, each carrying a `SERVER-GAP`
  doc note, and `TestAuthorizationModel_IsStillAServerGap` records executably
  that they 404 today. When the server ships those routes, that test starts
  failing — which is the signal to remove the warnings.
- Non-idempotent `POST`s are retried on 429/5xx. This is deliberate and tested,
  but it means a create call whose write committed before the response was lost
  can be applied twice on an endpoint with no natural dedup key. Use
  `WithMaxRetries(0)` on calls where once-only semantics matter. See README.

### Note for anyone on v0.1.0
The typed-id guard is a behaviour change: a `ZanzibarCheck` that previously sent a
request with an untyped id now returns `*ErrUntypedID` without sending it. If you
were relying on that request going out, it could only ever have come back
`allowed:false` — the guard turns a silent wrong deny into a clear error.

[0.9.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.9.0
[0.8.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.8.0
[0.7.1]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.7.1
[0.7.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.7.0
[0.6.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.6.0
[0.5.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.5.0
[0.4.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.4.0
[0.3.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.3.0
[0.2.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.2.0
[0.1.0]: https://github.com/ab0t-com/auth-sdk-go/releases/tag/v0.1.0
