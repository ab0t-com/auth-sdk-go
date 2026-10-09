# Tokens for other mesh services — `TokenFor` (and on-behalf-of token exchange)

**The pattern.** App or agent **A** needs to call mesh service **B**. Either A calls B **as itself**
(no person involved), or A calls B **for a signed-in person U** — with the call attributed to
"A acting for U" and limited to what U may do and allowed. Both are standard OAuth on the wire:

| A calls B… | Standard | `TokenFor` session argument |
|---|---|---|
| as itself | client credentials (RFC 6749 §4.4) + resource indicator (RFC 8707) | `nil` |
| for person U | token exchange (RFC 8693): U's token is the `subject_token` | U's session with A |

`TokenFor` is the one call for both. `ExchangeToken` / `OAuthToken` remain for callers that need the
raw form post.

---

## The call

```go
c := auth.New(authURL, auth.WithClientCredentials(clientID, clientSecret)) // A's OAuth client, sent as HTTP Basic

// as the service itself
tok, err := c.TokenFor(ctx, "https://b.service.example", "b.documents.read", nil)

// for the signed-in person (session = the person's session with A; StaticSession adapts a token)
tok, err = c.TokenFor(ctx, "https://b.service.example", "b.documents.read", auth.StaticSession(personToken))

req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
```

`Token` carries `AccessToken`, `TokenType`, `Resource`, `Scope` (granted) and `ExpiresAt`.

- **One resource per token.** Send it only to the resource it was requested for. Never forward a token
  you received to another service — get your own with `TokenFor`.
- **Cached.** Each token is served from memory until 30 s before it expires; the key is the pattern, the
  resource, the scope set and (for a person) a hash of the person's token — a new sign-in is a new key.
  A derived token is never served past the person's own token expiry. The cache is bounded
  (`WithTokenCacheSize`, least recently used dropped first), concurrent callers for one key share one
  request, and errors are never cached. Call `TokenFor` per request.
- **No refresh tokens.** Neither pattern returns one; renewing is asking again.
- **Only client credentials reach the token endpoint.** A client also configured `WithAPIKey` does not
  send that key on these calls.

A complete, runnable program: **[`examples/obo`](../examples/obo/main.go)**.

---

## Today's services: the bridge (`WithLegacyActorExchange`)

The person-present request TokenFor sends by default is the target shape (RFC 8693 §2.1):

```
POST /auth/oauth/token   Authorization: Basic <A's client_id:client_secret>
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<U's access token>&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&resource=<B>&scope=<scope>                       (no actor_token — the authenticated client IS the actor)
```

Auth services that do not accept that yet exchange a person's token with **A's own token as the
`actor_token`** and an `audience`. Turn that chain on behind the same call:

```go
c := auth.New(authURL,
    auth.WithClientCredentials(clientID, clientSecret),
    auth.WithLegacyActorExchange("SELF:<org id>"), // or the org's registered service audience
)
tok, err := c.TokenFor(ctx, "SELF:<org id>", "users.read", auth.StaticSession(personToken))
```

TokenFor then (1) mints A's own token with client credentials (HTTP Basic, cached), and (2) exchanges
U's token with `actor_token` = that token, `actor_token_type` = access_token, `audience` = the value
you gave (empty → the `resource` argument) and your `scope`. When the service supports the target
request, delete the option — nothing else in your code changes.

### One-time setup for the bridge

1. **A's identity in the org whose resource it calls.** An admin of that org creates a service account
   and a confidential OAuth client bound to it (grant type `client_credentials`). `authsetup obo-actor`
   does both and prints the service account's **user id** (the actor id) and the client id + secret
   (shown once). The actor id — not the client id — is what a grant names.
2. **Each person grants A, once,** with their own token, from a session **in that same org** (a grant
   created from a session in a child/workspace org is accepted but never used — switch first with
   `SwitchOrganization`):
   ```go
   hours := 720
   _, err := c.GrantDelegation(ctx, auth.DelegationGrant{ActorID: actorID, Scope: []string{"users.read"},
       ExpiresInHours: &hours}, personToken)
   ```
   `authsetup obo-enable` creates the same grant and checks that the person's token audience matches;
   it does not register an audience.
3. **The audience** in `WithLegacyActorExchange` must be one the acting org recognises: its registered
   service audience, or `SELF:<org id>`. Anything else is `invalid_target`.

Scopes are mesh permissions in dotted form (`<service>.<action>.<resource>` or e.g. `users.read`), and
they must be ones the person holds and granted.

---

## What the answers mean

All token-endpoint errors are `{"error": "...", "error_description": "..."}`. TokenFor classifies by the
HTTP status and `error` / `suberror` only (never the free-text description). Test with `errors.Is`
(sentinels) and `errors.As` (`*auth.ConsentRequired`, `*auth.APIError` — always still reachable).

| Wire | TokenFor returns | You do |
|---|---|---|
| 400 `invalid_request` **or** `invalid_grant` (for a person) | `ErrReauthenticate` | the person's token was not accepted (expired, revoked, not for your app, they left the org). Sign them in again; retry once. On the bridge it also covers "no grant from this person" — the service deliberately does not say which |
| 400 `invalid_target` + `"suberror":"consent_required"` | `*ConsentRequired` | the person can approve: send them to `consent.AuthorizationURL(redirectURI, state, challenge)` once (`NewPKCE` makes the challenge), then retry |
| 400 `invalid_target` | `ErrNoConnection` | no usable connection to that resource, or the resource / audience is unknown or malformed — an admin must fix it |
| 400 `invalid_scope` | `ErrScopeNotAllowed` | asked for more than the client / grant allows — ask for less |
| 401 `invalid_client` | `ErrClientAuth` | your client credentials are wrong — fix or rotate the secret |
| 400 `unauthorized_client` | `ErrClientNotEnabled` | your client is not registered for that grant type |
| 5xx, 429, network failure, cancelled context | `ErrUnavailable` | back off and retry; never treat as allowed, never reuse an expired token |
| 400 `unsupported_grant_type` | the raw `*APIError` | the service does not support the grant |

Services are moving the person-token rejections from `invalid_grant` to `invalid_request` (RFC 8693
§2.2.2); TokenFor treats both alike so your code does not change. On the machine pattern an
`invalid_request` is a malformed request and is returned as the raw `*APIError`.

`ConsentRequired.AuthorizationURL` is built from the auth service's RFC 8414 metadata
(`authorization_endpoint`) with `response_type=code`, your `client_id`, `redirect_uri`, `scope`,
`resource`, `state`, the PKCE S256 challenge and `prompt=consent`. The token endpoint never hands out a
URL.

---

## The raw call (`ExchangeToken`)

`ExchangeToken(ctx, subjectToken, audience, opts...)` posts the RFC 8693 form and returns
`ExchangeResponse` (it keeps `issued_token_type`, which `TokenResponse` drops). On today's services an
exchange for a person **must** carry the actor token — without one the answer is
`400 invalid_request`:

```go
actor, err := c.OAuthToken(ctx, url.Values{"grant_type": {"client_credentials"},
    "client_id": {clientID}, "client_secret": {clientSecret}})
resp, err := c.ExchangeToken(ctx, personToken, "SELF:<org id>",
    auth.WithActorToken(actor.AccessToken), auth.WithScope("users.read"))
```

`TokenExchangeForm(subjectToken, audience, opts...)` builds the form:

| field | value |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` (`GrantTypeTokenExchange`) |
| `subject_token` | U's token |
| `subject_token_type` | default `urn:...:access_token` — `WithSubjectTokenType` |
| `requested_token_type` | default `urn:...:access_token` — `WithRequestedTokenType` |
| `audience` | the target (omitted if empty) |
| `resource` | `WithResource` (RFC 8707) |
| `scope` | `WithScope` — name it; a scope beyond what may be delegated is `invalid_scope` |
| `actor_token` (+ `actor_token_type`) | `WithActorToken` |

Prefer `TokenFor`: it does the client authentication, the caching and the error classification.

---

## The rules that keep it safe

- **Bounded, never widened.** The exchanged token's scope is at most what the person holds, what they
  granted, and what you asked for. A scope outside that is refused, not silently granted.
- **Org-bound.** On the bridge, the grant, the actor and the exchange all live in one org; a grant cannot
  reach across an org boundary.
- **Audience-keyed.** A token is minted only for a target the acting org recognises, so A cannot mint a
  token for an arbitrary service (the confused-deputy guard).
- **Short-lived, no refresh token.** About 15 minutes; asking again re-checks everything.
- **One hop at a time.** A nested `act` chain on a token records earlier actors; only the current actor's
  grant was enforced at mint time. Do not treat the chain as N enforced delegations.
- **Privileged actors.** An actor holding an impersonation / admin / `*` permission can be granted `*`
  without a grant. Do not rely on that for normal app-to-app access; treat a granted scope of `*` as
  privileged.

---

## `sub` is not always a human

`sub` is "the principal this token represents":

- **client credentials** → `sub` = the service account (a machine);
- **token exchange for a person** → `sub` = the person; the acting app is identified separately —
  `client_id` (where the service emits it) names the app, and `act.sub` names the actor on delegation
  tokens today;
- **normal sign-in** → `sub` = the person.

Key user records on `iss` + `sub` (never on email). Before attributing an action to a person, check
whether the token was issued to an app acting for them (`client_id` / `act`), and log both.
