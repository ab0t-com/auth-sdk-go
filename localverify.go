package authclient

// localverify.go — verify an access token LOCALLY (signature + claims against
// the cached JWKS), with no call to the auth service on the hot path.
//
// READ THIS BEFORE CHOOSING IT OVER ValidateToken
//
// The auth service's access tokens are SESSION-BACKED. Logout, a revoked
// session, a deactivated user, or a removed org membership invalidate the token
// at the service immediately. A local check cannot see any of that: it proves
// the token was issued by the auth service, for this audience, and has not
// expired — nothing more. So VerifyAccessTokenLocal keeps accepting a
// logged-out token until its exp (access tokens live about 15 minutes).
//
// That is why it is a separate, explicit method and ValidateToken was NOT
// changed to use it. Pick per route:
//
//	VerifyAccessTokenLocal  no network, no auth load; revocation bounded by exp
//	ValidateToken           one call (cached 15 s by default); sees logout
//	ValidateToken + WithFreshValidation(ctx)   always asks; for sensitive actions
//
// WHAT IS CHECKED (all must pass; anything else is rejected)
//
//   - Shape: a JWS compact token, bounded in size.
//   - Header: alg is exactly RS256 ("none", HS*, ES*, PS* are all rejected — the
//     alg is never taken from the token as a choice of algorithm); no `crit`;
//     typ, if present, is JWT or at+jwt; a kid is present.
//   - Key: the kid is in the auth service's JWKS (cached 10 min). An unknown kid
//     triggers at most ONE refetch per minute (key rotation without letting
//     random kids amplify into JWKS fetches). The key must be RSA, for signing,
//     and at least 2048 bits.
//   - Signature: RSASSA-PKCS1-v1_5 with SHA-256 over header.payload.
//   - Claims: exp is required and not passed, nbf/iat not in the future (each
//     with a leeway, default 30 s, never more than 60 s); iss is one of the
//     accepted issuers; aud contains the expected audience when one is
//     expected; sub is present; the token `type` is an access token ("access",
//     or absent on tokens that predate the claim). A refresh token is never
//     accepted; a delegation token only with AllowDelegation.
//
// FAILURE SHAPES
//
// A token that fails a check yields an error matching ErrInvalidAccessToken
// (errors.Is), as an *AccessTokenError with a stable Reason — that is a domain
// fact: answer 401. A failure to obtain the key set (auth service unreachable on
// a cold cache) is returned as that underlying error and does NOT match
// ErrInvalidAccessToken — that is "could not evaluate": answer 503, never 401.

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

// LegacyAccessTokenIssuer is the `iss` the auth service mints when it has no
// issuer URL configured. It is accepted by default alongside the client's base
// URL (see LocalVerifyOptions.Issuers).
const LegacyAccessTokenIssuer = "ab0t-auth-service"

// DefaultLocalVerifyLeeway is the clock skew VerifyAccessTokenLocal tolerates on
// exp / nbf / iat when LocalVerifyOptions.Leeway is zero.
const DefaultLocalVerifyLeeway = 30 * time.Second

// MaxLocalVerifyLeeway is the largest clock skew VerifyAccessTokenLocal will
// tolerate; a larger LocalVerifyOptions.Leeway is clamped to it.
const MaxLocalVerifyLeeway = 60 * time.Second

// maxLocalVerifyTokenBytes bounds the token VerifyAccessTokenLocal will parse.
// Real access tokens are ~1 KB; anything this large is not one, and parsing it
// would only cost CPU on the caller's hot path.
const maxLocalVerifyTokenBytes = 16 << 10

// minRSAKeyBits is the smallest RSA modulus accepted for signature verification.
const minRSAKeyBits = 2048

// ErrInvalidAccessToken is matched (errors.Is) by every error
// VerifyAccessTokenLocal returns for a token that FAILED verification. An error
// that does not match it means the token could not be evaluated (e.g. the key
// set could not be fetched) — treat that as unavailable (503), not as 401.
var ErrInvalidAccessToken = errors.New("authclient: invalid access token")

// AccessTokenError is the concrete error for a token that failed local
// verification. Reason is a stable, machine-readable code: "malformed",
// "too_large", "unsupported_alg", "unsupported_header", "missing_kid",
// "unknown_kid", "unsupported_key", "bad_signature", "expired",
// "not_yet_valid", "issuer", "audience", "token_type", "missing_claim".
//
// The message never contains the token or any claim value, so it is safe to log.
type AccessTokenError struct {
	Reason string
}

func (e *AccessTokenError) Error() string {
	return "authclient: invalid access token: " + e.Reason
}

// Is makes errors.Is(err, ErrInvalidAccessToken) true for every AccessTokenError.
func (e *AccessTokenError) Is(target error) bool { return target == ErrInvalidAccessToken }

func invalidToken(reason string) error { return &AccessTokenError{Reason: reason} }

// LocalVerifyOptions configures VerifyAccessTokenLocal. The zero value is the
// safe default.
type LocalVerifyOptions struct {
	// Audience, when non-empty, must be one of the token's `aud` values (exact
	// string match). Empty falls back to the client's WithExpectedAudience; when
	// both are empty the audience is not checked.
	Audience string
	// Issuers is the set of accepted `iss` values. Nil or empty means the
	// default set: LegacyAccessTokenIssuer and the client's base URL.
	Issuers []string
	// Leeway is the clock skew tolerated on exp / nbf / iat. Zero means
	// DefaultLocalVerifyLeeway (30 s); anything above MaxLocalVerifyLeeway (60 s)
	// is clamped to it; negative means no leeway.
	Leeway time.Duration
	// AllowDelegation accepts delegation tokens (claim type "delegation": a party
	// acting on behalf of the subject, RFC 8693). Off by default because a local
	// check cannot re-read the delegation grant, and a caller that treats `sub`
	// as the acting party would hand the delegate the subject's full authority.
	// When on, inspect Claims.Actor and Claims.Scope and enforce the scope.
	AllowDelegation bool

	// now is time.Now, replaceable in tests.
	now func() time.Time
}

// AccessTokenClaims is what VerifyAccessTokenLocal returns for a token that
// passed every check. It carries identity, not permissions: the auth service's
// access tokens do not embed the subject's permissions — use Authorize for a
// permission decision.
type AccessTokenClaims struct {
	// Subject is the user id (`sub`).
	Subject string
	// Email, Name and OrgID are the auth service's identity claims, when present.
	Email string
	Name  string
	OrgID string
	// Issuer is `iss`; Audience is `aud` (always a slice, whichever JSON shape).
	Issuer   string
	Audience []string
	// ExpiresAt is `exp`. IssuedAt (`iat`) and NotBefore (`nbf`) are zero when
	// absent.
	ExpiresAt time.Time
	IssuedAt  time.Time
	NotBefore time.Time
	// SessionID is `jti` — the server-side session the token is bound to. A
	// local check cannot tell whether that session still exists.
	SessionID string
	// Type is the token's `type` claim: "access", "" on tokens that predate the
	// claim, or "delegation" (only with AllowDelegation).
	Type string
	// ClientID is the RFC 9068 `client_id`, when present.
	ClientID string
	// Scope is the `scope` claim as a list (a JSON list or an RFC 9068
	// space-delimited string). Delegation tokens carry the delegated scope here.
	Scope []string
	// Actor is the RFC 8693 `act` claim of a delegation token (nil otherwise).
	Actor map[string]any
	// KeyID is the `kid` of the key that verified the signature.
	KeyID string
	// Raw is every claim, decoded with json.Number for numbers.
	Raw map[string]any
}

// IsDelegation reports whether the token is a delegation token (someone acting
// on behalf of Subject).
func (c *AccessTokenClaims) IsDelegation() bool { return c != nil && c.Type == "delegation" }

// VerifyAccessTokenLocal verifies an auth-service access token LOCALLY — RS256
// signature against the service's JWKS (cached 10 min; an unknown kid refetches
// at most once a minute), plus iss, aud (when expected), exp / nbf with a
// bounded clock skew, and the token type — and returns its claims. On the hot
// path it makes no network call at all.
//
// IMPORTANT — it cannot see logout. The service's access tokens are
// session-backed: logout, a revoked session, a deactivated user or a removed
// membership invalidate the token at the service immediately, but a local check
// keeps accepting it until its exp (access tokens live about 15 minutes). Use
// ValidateToken where that matters; it asks the service. See localverify.go for
// the full list of checks.
//
// A token that fails verification returns an error matching
// ErrInvalidAccessToken (answer 401). Any other error means the key set could
// not be obtained (answer 503).
func (c *Client) VerifyAccessTokenLocal(ctx context.Context, token string, opts LocalVerifyOptions) (*AccessTokenClaims, error) {
	now := time.Now
	if opts.now != nil {
		now = opts.now
	}
	leeway := opts.Leeway
	switch {
	case leeway == 0:
		leeway = DefaultLocalVerifyLeeway
	case leeway < 0:
		leeway = 0
	case leeway > MaxLocalVerifyLeeway:
		leeway = MaxLocalVerifyLeeway
	}

	// ---- shape ----
	if len(token) > maxLocalVerifyTokenBytes {
		return nil, invalidToken("too_large")
	}
	if !LooksLikeJWT(token) {
		return nil, invalidToken("malformed")
	}
	parts := strings.Split(token, ".")
	headerJSON, err := b64url(parts[0])
	if err != nil {
		return nil, invalidToken("malformed")
	}
	payloadJSON, err := b64url(parts[1])
	if err != nil {
		return nil, invalidToken("malformed")
	}
	sig, err := b64url(parts[2])
	if err != nil {
		return nil, invalidToken("malformed")
	}

	// ---- header ----
	var hdr struct {
		Alg  *string         `json:"alg"`
		Kid  string          `json:"kid"`
		Typ  string          `json:"typ"`
		Crit json.RawMessage `json:"crit"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, invalidToken("malformed")
	}
	// The algorithm is fixed by this verifier, never chosen by the token: only
	// RS256 is accepted, so "none" and HS256-with-the-public-key confusion are
	// both impossible.
	if hdr.Alg == nil || *hdr.Alg != "RS256" {
		return nil, invalidToken("unsupported_alg")
	}
	if len(hdr.Crit) > 0 {
		// RFC 7515 §4.1.11: a critical extension this verifier does not
		// understand MUST cause rejection.
		return nil, invalidToken("unsupported_header")
	}
	switch strings.ToLower(hdr.Typ) {
	case "", "jwt", "at+jwt", "application/at+jwt":
	default:
		return nil, invalidToken("unsupported_header")
	}
	if hdr.Kid == "" {
		return nil, invalidToken("missing_kid")
	}

	// ---- key ----
	const jwksPath = "/.well-known/jwks.json"
	set, err := c.jwks.get(ctx, jwksPath, false)
	if err != nil {
		return nil, err // could not evaluate — NOT ErrInvalidAccessToken
	}
	jwk, ok := set.Key(hdr.Kid)
	if !ok {
		refreshed, did, err := c.jwks.refreshForUnknownKid(ctx, jwksPath)
		if err != nil {
			return nil, err
		}
		if did {
			jwk, ok = refreshed.Key(hdr.Kid)
		}
		if !ok {
			return nil, invalidToken("unknown_kid")
		}
	}
	pub, err := rsaPublicKey(jwk)
	if err != nil {
		return nil, invalidToken("unsupported_key")
	}

	// ---- signature ----
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, invalidToken("bad_signature")
	}

	// ---- claims (only now that the signature is good) ----
	raw := map[string]any{}
	dec := json.NewDecoder(strings.NewReader(string(payloadJSON)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, invalidToken("malformed")
	}
	out := &AccessTokenClaims{Raw: raw, KeyID: hdr.Kid}

	t := now()
	exp, present, err := numericDate(raw, "exp")
	if err != nil {
		return nil, invalidToken("malformed")
	}
	if !present {
		return nil, invalidToken("missing_claim")
	}
	// RFC 7519 §4.1.4: must not be accepted ON or after exp.
	if !t.Before(exp.Add(leeway)) {
		return nil, invalidToken("expired")
	}
	out.ExpiresAt = exp
	if nbf, present, err := numericDate(raw, "nbf"); err != nil {
		return nil, invalidToken("malformed")
	} else if present {
		if t.Add(leeway).Before(nbf) {
			return nil, invalidToken("not_yet_valid")
		}
		out.NotBefore = nbf
	}
	if iat, present, err := numericDate(raw, "iat"); err != nil {
		return nil, invalidToken("malformed")
	} else if present {
		if t.Add(leeway).Before(iat) {
			return nil, invalidToken("not_yet_valid")
		}
		out.IssuedAt = iat
	}

	var strErr bool
	str := func(k string) string {
		v, ok := raw[k]
		if !ok || v == nil {
			return ""
		}
		s, ok := v.(string)
		if !ok {
			strErr = true
		}
		return s
	}
	out.Issuer = str("iss")
	out.Subject = str("sub")
	out.Type = str("type")
	out.Email = str("email")
	out.Name = str("name")
	out.OrgID = str("org_id")
	out.SessionID = str("jti")
	out.ClientID = str("client_id")
	if strErr {
		return nil, invalidToken("malformed")
	}

	issuers := opts.Issuers
	if len(issuers) == 0 {
		issuers = []string{LegacyAccessTokenIssuer, c.baseURL}
	}
	if out.Issuer == "" || !containsString(issuers, out.Issuer) {
		return nil, invalidToken("issuer")
	}

	aud, err := audienceClaim(raw["aud"])
	if err != nil {
		return nil, invalidToken("malformed")
	}
	out.Audience = aud
	wantAud := opts.Audience
	if wantAud == "" {
		wantAud = c.expectedAudience
	}
	if wantAud != "" && !containsString(aud, wantAud) {
		return nil, invalidToken("audience")
	}

	if out.Subject == "" {
		return nil, invalidToken("missing_claim")
	}

	switch out.Type {
	case "", "access":
	case "delegation":
		if !opts.AllowDelegation {
			return nil, invalidToken("token_type")
		}
	default:
		// "refresh" above all: a refresh token is a long-lived session credential,
		// never an access credential. Every other type is not one we accept here.
		return nil, invalidToken("token_type")
	}

	if scope, err := scopeClaim(raw["scope"]); err != nil {
		return nil, invalidToken("malformed")
	} else {
		out.Scope = scope
	}
	if act, ok := raw["act"].(map[string]any); ok {
		out.Actor = act
	} else if raw["act"] != nil {
		return nil, invalidToken("malformed")
	}
	if out.IsDelegation() && out.Actor == nil {
		// A delegation token without its actor cannot be bound to who is acting.
		return nil, invalidToken("missing_claim")
	}
	return out, nil
}

// ---- helpers ----

func b64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// rsaPublicKey builds a verification key from a JWK, refusing anything that is
// not an RSA signing key of adequate size.
func rsaPublicKey(k JWK) (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, errors.New("not an RSA key")
	}
	if k.Use != "" && k.Use != "sig" {
		return nil, errors.New("not a signing key")
	}
	if k.Alg != "" && k.Alg != "RS256" {
		return nil, errors.New("key not for RS256")
	}
	nb, err := b64url(k.N)
	if err != nil || len(nb) == 0 {
		return nil, errors.New("bad modulus")
	}
	eb, err := b64url(k.E)
	if err != nil || len(eb) == 0 || len(eb) > 4 {
		return nil, errors.New("bad exponent")
	}
	n := new(big.Int).SetBytes(nb)
	if n.BitLen() < minRSAKeyBits {
		return nil, errors.New("modulus too small")
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e < 3 || e%2 == 0 {
		return nil, errors.New("bad exponent")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// numericDate reads a NumericDate claim (seconds since the epoch, possibly
// fractional). present=false when absent or null; err when present but not a
// number.
func numericDate(m map[string]any, k string) (time.Time, bool, error) {
	v, ok := m[k]
	if !ok || v == nil {
		return time.Time{}, false, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, true, errors.New("not a number")
	}
	f, err := n.Float64()
	if err != nil || f < 0 {
		return time.Time{}, true, errors.New("not a NumericDate")
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC(), true, nil
}

// audienceClaim accepts `aud` as a string or a list of strings (RFC 7519 §4.1.3).
func audienceClaim(v any) ([]string, error) {
	switch a := v.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{a}, nil
	case []any:
		out := make([]string, 0, len(a))
		for _, x := range a {
			s, ok := x.(string)
			if !ok {
				return nil, errors.New("aud element not a string")
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, errors.New("aud not a string or list")
	}
}

// scopeClaim accepts `scope` as a space-delimited string (RFC 9068 §2.2.3) or a
// list of strings (the shape delegation tokens carry today).
func scopeClaim(v any) ([]string, error) {
	switch s := v.(type) {
	case nil:
		return nil, nil
	case string:
		return strings.Fields(s), nil
	case []any:
		out := make([]string, 0, len(s))
		for _, x := range s {
			str, ok := x.(string)
			if !ok {
				return nil, errors.New("scope element not a string")
			}
			out = append(out, str)
		}
		return out, nil
	default:
		return nil, errors.New("scope not a string or list")
	}
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
