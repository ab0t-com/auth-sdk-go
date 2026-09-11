# On-behalf-of (OBO) token exchange — RFC 8693

**The pattern.** App or agent **A** holds end user **U**'s access token and needs
to call mesh service **B** *as U* — with an audit trail attributing the call to
"A acting for U" and with least privilege (read-only unless granted more). OBO
is **OAuth 2.0 Token Exchange** ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)):
A exchanges U's token for a short-lived **delegation token** minted for B, then
presents that token to B.

This is already implemented server-side on both engines (appv2 and goauth) with
no feature flag. The SDK helper below is a typed wrapper over the raw
`OAuthToken` form path — it does not add or change any server behavior.

> Grounding: all server-side facts here cite the code investigation in
> `auth/output/tickets/20260907_ordo_obo_token_exchange/FINDINGS.md`.

---

## The call

```go
c := auth.New("https://auth.service.ab0t.com")

resp, err := c.ExchangeToken(ctx,
    userAccessToken,   // subject_token — U's token (the party being acted for)
    "resource-service", // audience — the target mesh service B
    auth.WithScope("resource:read"), // requested scope (narrowed fail-closed)
)
if err != nil {
    // e.g. invalid_target (see prerequisites) or an empty-scope denial
}

// resp.AccessToken     — the delegated token to present to B (as U)
// resp.IssuedTokenType  — urn:...:access_token  (surfaced; TokenResponse drops it)
// resp.TokenType        — "Bearer"
// resp.ExpiresIn        — ~900s (15-minute delegation token)
// resp.Scope            — the granted (possibly narrowed) scope
```

A complete, runnable example is in **[`examples/obo`](../examples/obo/main.go)**.

### Why a dedicated response type

`ExchangeToken` returns `ExchangeResponse`, not `TokenResponse`. The RFC 8693
§2.2.1 body carries **`issued_token_type`** (the type of the returned token),
which the plain `TokenResponse` silently drops (`oauth.go:37-44`). The raw
`OAuthToken(form)` path still works for token exchange, but it cannot surface
`issued_token_type` — that is the reason this helper exists.

### The form

`TokenExchangeForm(subjectToken, audience, opts...)` builds the RFC 8693 form
(mirroring `RefreshTokenForm`):

| field | value |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` (`GrantTypeTokenExchange`) |
| `subject_token` | U's token |
| `subject_token_type` | default `urn:...:access_token` — override with `WithSubjectTokenType` |
| `requested_token_type` | default `urn:...:access_token` — override with `WithRequestedTokenType` |
| `audience` | B (omitted if empty) |
| `scope` | optional, via `WithScope` |
| `actor_token` (+ `actor_token_type`) | optional, via `WithActorToken` |

---

## The two prerequisites (do these first)

An exchange only mints a token when **both** are provisioned for U's org.
Missing either is the usual cause of a failed exchange.

1. **B is registered as the org's `service_audience`.**
   `aud=B` is honored only if B is the org's registered `service_audience`;
   otherwise the exchange returns **`invalid_target`**
   (appv2 `auth_service_base.py:3356-3371`). This is the confused-deputy guard —
   A cannot mint a token for an arbitrary service.

2. **A read-only `may_act` delegation grant exists (A may act for U).**
   A same-realm `may_act` grant bounds the exchange
   (appv2 `permission_service.py:806-835`). Without a grant, A has no authority
   to act for U (except the break-glass case below).

These two are tribal knowledge today; Phase 3 of the productization ticket turns
them into one repeatable provisioning step.

---

## The rules that keep it safe

- **Org-bound.** `may_act` / act-as is **org-bound**
  (`permission_service.py:806-817`, error `delegation_wrong_org`). Delegation
  alone cannot cross an org boundary.
- **Audience-keyed on top.** Token exchange adds audience-keying
  (`auth_service_base.py:3356-3371`) over the same org-bound `may_act` store — so
  to reach a `service_audience`-owner-only resource, A needs **both** the
  same-realm `may_act` grant **and** B registered as that org's service audience.
- **Fail-closed scope narrowing.** The requested `scope` is bounded by
  (1) the `DELEGATION#{actor}#{target}` grant ceiling
  (`permission_service.py:830-835`), (2) the subject's authority, and
  (3) `narrow_scope` (`token_exchange.py:58`) — **never widened**, and an **empty
  resulting scope is denied**. Read-only is delivered via this ceiling, not a
  per-OAuth-client hard allow-list.
- **Attribution.** The minted token is `type:"delegation"` with a nested
  `act` (RFC 8693 §4.1) + `may_act` (§4.4)
  (`auth_service_base.py:3087-3099`), and the exchange emits an
  `auth.token_exchange.issued` audit event (`:3384-3390`). "A acted for U" is
  attributable.

### Break-glass caveat (`*`)

An actor holding `users.impersonate` / `users.admin` / `*` with **no** delegation
record is granted `scope=["*"]` (`permission_service.py:840-848`). Do not rely on
this for normal OBO — grant a scoped `may_act` instead. Treat any `resp.Scope`
of `*` as a privileged/break-glass path.

---

## What breaks and why

| Symptom | Cause | Fix |
|---|---|---|
| `invalid_target` (400) | B is not the org's registered `service_audience` (`auth_service_base.py:3356-3371`) | Register B as the org's service audience (prerequisite 1) |
| Empty-scope / denied | no `may_act` grant, or requested scope narrows to empty (`token_exchange.py:58`) | Create a read-only `may_act` grant (prerequisite 2); request a scope within the grant ceiling |
| `unsupported_grant_type` (400) | server build predates the exchange endpoint / URN | Deploy a current build (URN added 2026-08-17; endpoint since 2026-07-07) |
| `delegation_wrong_org` | the grant is in a different org than the subject (`permission_service.py:806-817`) | Grant `may_act` in the subject's realm |

> **goauth caveat.** A goauth-minted delegation token is currently **rejected by
> the mesh validate path**: `oauthexch.go:32-66` computes `act`/`scope`/`may_act`
> and returns them in the §2.2.1 body, but `token.Claims` cannot embed them and
> the PDP hardcodes `Type:"access"`. OBO is end-to-end on **appv2** today; goauth
> engine parity is a separate (deferred) work item.

---

## Worked example (agent → resource-service, sanitized)

An AI companion (**A**) acts for user **U** to read U's resources in
`resource-service` (**B**):

1. **Provision once (prereqs):** register `resource-service` as U's org's
   `service_audience`, and create a read-only `may_act` grant (A → U).
2. **Get U's token** the normal way (the user's access token).
3. **Exchange:**
   ```go
   resp, err := c.ExchangeToken(ctx, uToken, "resource-service",
       auth.WithScope("resource:read"))
   ```
4. **Call B** with `resp.AccessToken` as the bearer. B sees a `type:"delegation"`
   token whose `act`/`may_act` attribute the call to "A acting for U", scoped
   read-only. The exchange is recorded as `auth.token_exchange.issued`.

If step 3 returns `invalid_target`, prerequisite 1 is missing; if it denies on an
empty scope, prerequisite 2 (the grant) is missing or too narrow.
