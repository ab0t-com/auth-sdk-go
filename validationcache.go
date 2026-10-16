package authclient

// validationcache.go — a TTL-bounded cache for credential validation and
// permission decisions. ON BY DEFAULT since v0.12.0 (see below); opt out with
// WithValidationCache(0).
//
// WHY THIS EXISTS
//
// ValidateToken, ValidateAPIKey and Authorize are each an unconditional POST to
// the auth service. On a request-per-validation surface — a gateway, an ingest
// door, any hot path — that is one extra network round trip on every single
// request, and it is the dominant cost in the request budget long before the
// service's own work is. Only the JWKS key set was cached; the validation
// decisions were not. A hot path that re-derives its own cache per service is
// how a subtle, security-relevant object gets written five times, four of them
// badly, so it is written ONCE, here, in the shared SDK.
//
// WHY IT IS NOW ON BY DEFAULT — AND WHAT THAT COSTS
//
// Until v0.12.0 this cache was opt-in, by design: caching a validation decision
// extends the useful life of a credential that has been revoked, or of a
// permission that has been removed, by up to the TTL. That is a change to a
// SECURITY property, and the original position was that a consumer should not
// acquire it by upgrading a library.
//
// The owner revisited that trade-off and decided to turn the cache on by default,
// with short, per-question TTLs, because in practice almost every service sits on
// a hot path and was paying one auth round trip per request. The cost is stated
// here plainly, because it is the whole decision:
//
//	question                                   remembers "yes" for   remembers "no" for
//	API-key identity (ValidateAPIKey,           60 s                  10 s
//	  ValidateToken with an ab0t_sk_ key)
//	JWT identity (ValidateToken /               15 s, never past the  5 s
//	  ValidateTokenWith)                        token's own exp
//	any permission decision (Authorize, or a    15 s                  5 s
//	  validation with RequiredPermissions)
//
// The positive TTL IS the revocation latency of this process: a revoked API key
// can keep validating here for up to 60 s, a removed permission or a logged-out
// session for up to 15 s. A consumer that cannot accept that has three ways out:
//
//   - WithValidationCache(0) turns the cache off for the whole client (the
//     pre-v0.12.0 behaviour, byte for byte: every validation is an HTTP call);
//   - WithFreshValidation(ctx) bypasses it for one call — use it on sensitive
//     operations (admin actions, money movement, ownership changes);
//   - InvalidateValidation(cred) drops what this process knows about a credential
//     the moment the process learns it is no longer good.
//
// A consumer that configured the cache explicitly (WithValidationCache(ttl) or
// WithValidationCacheOptions) keeps exactly what it configured: one TTL for every
// question, and — as before — the resource-scoped PDP decision inside Authorize is
// not cached. The defaults above apply only to a client that said nothing.
//
// THE THREE WAYS A VALIDATION CACHE GOES WRONG, AND WHAT IS DONE ABOUT EACH
//
//  1. It caches the wrong answer for a credential. The key is a SHA-256 over
//     every input that can change the answer — credential, expected audience,
//     required permissions, resource, and the include-permissions flag — each
//     length-prefixed so no two distinct inputs can produce the same byte
//     stream. A credential is never itself a map key, so it does not sit in
//     process memory in plaintext any longer than the request needs it.
//
//  2. It fails OPEN. An error is never cached — that includes 429 and every 5xx
//     — and, unlike the JWKS cache, which deliberately serves a stale key set
//     through a transient outage, an EXPIRED entry is never served after a failed
//     refresh. During an auth outage this cache stops answering rather than
//     extending every credential it has seen. Failing closed is the correct
//     direction for an authorization decision. (One answer arrives as an error
//     but is not a failure: a definite 401 from validate-token says "this token
//     is not valid". It is cached exactly like a {valid:false} — negative TTL —
//     and handed back as the same error. It can only ever deny.)
//
//  3. It outlives the credential. A positive entry's TTL is additionally capped
//     by the token's own expiry — the ExpiresAt the service reports, and for a
//     JWT the `exp` claim read from the token itself — so the cache can never
//     make an expired token look valid. (The `exp` read here is not a trust
//     decision: it can only SHORTEN an entry, never lengthen or create one.) A
//     negative decision gets its own, shorter TTL: a "no" that becomes a "yes"
//     (a permission just granted) should not take the full TTL to be noticed,
//     and negatives are the cheap side of the trade.
//
// Entries are bounded (a cache keyed by credential is otherwise a slow leak
// keyed by tenant), and a single flight per key collapses a cold-start stampede
// into one round trip.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default per-question TTLs, applied when the client is constructed WITHOUT
// WithValidationCache / WithValidationCacheOptions. Each positive TTL is the
// revocation latency of that question in this process; see the file comment.
const (
	// DefaultAPIKeyValidationTTL is how long an API key's "valid" is trusted.
	// A revoked API key can keep validating in this process for up to this long.
	DefaultAPIKeyValidationTTL = 60 * time.Second
	// DefaultAPIKeyValidationNegativeTTL is how long an API key's "not valid"
	// is trusted.
	DefaultAPIKeyValidationNegativeTTL = 10 * time.Second

	// DefaultTokenValidationTTL is how long a JWT's "valid" is trusted (and never
	// past the token's own exp). A logged-out session can keep validating in this
	// process for up to this long.
	DefaultTokenValidationTTL = 15 * time.Second
	// DefaultTokenValidationNegativeTTL is how long a JWT's "not valid" is trusted.
	DefaultTokenValidationNegativeTTL = 5 * time.Second

	// DefaultAuthorizeTTL is how long a permission decision's "allowed" is
	// trusted — Authorize, and any validation carrying RequiredPermissions. A
	// removed permission can keep being allowed in this process for up to this
	// long.
	DefaultAuthorizeTTL = 15 * time.Second
	// DefaultAuthorizeNegativeTTL is how long a permission decision's "denied"
	// is trusted.
	DefaultAuthorizeNegativeTTL = 5 * time.Second
)

// DefaultValidationCacheTTL is a suggested single TTL for a consumer that
// configures the cache EXPLICITLY with WithValidationCache. It is a SUGGESTION,
// not a fallback — a non-positive TTL disables the cache rather than
// substituting this value, so "off" cannot be reached by accident and cannot be
// left ambiguous. (A client that configures nothing gets the per-question
// defaults above, not this value.)
const DefaultValidationCacheTTL = 30 * time.Second

// DefaultValidationCacheNegativeTTL is the TTL applied to a NEGATIVE decision
// (the service answered, and said no) when an explicit configuration does not
// choose one. It is deliberately much shorter than the positive TTL: a denial
// that has just been fixed by granting a permission should start working
// promptly, and caching denials aggressively buys little — a denied caller is
// not usually a hot path.
const DefaultValidationCacheNegativeTTL = 5 * time.Second

// DefaultValidationCacheMaxEntries bounds the number of distinct cached
// decisions. Entries are keyed by credential (hashed) plus request shape, so an
// unbounded map grows by one entry per distinct credential ever seen and never
// shrinks — a leak keyed by tenant. The bound is generous; eviction costs only a
// revalidation.
const DefaultValidationCacheMaxEntries = 4096

// ValidationCacheOptions configures the validation cache EXPLICITLY. Passing it
// (or WithValidationCache) replaces the per-question defaults with one TTL for
// every question. A zero TTL disables the cache entirely.
type ValidationCacheOptions struct {
	// TTL is how long a POSITIVE (valid) decision is trusted. Non-positive
	// disables the cache.
	TTL time.Duration
	// NegativeTTL is how long a NEGATIVE (answered, but not valid) decision is
	// trusted. Zero means DefaultValidationCacheNegativeTTL, clamped to never
	// exceed TTL. Negative disables caching of negatives (they always re-ask).
	NegativeTTL time.Duration
	// MaxEntries bounds the cache. Zero means DefaultValidationCacheMaxEntries.
	MaxEntries int
}

// ValidationCacheStats reports cache activity. It exists so a consumer can prove
// the cache is doing what it claims — a hot path that believes it is cached and
// is not has simply bought a dependency for nothing.
type ValidationCacheStats struct {
	// Enabled reports whether a cache is configured at all.
	Enabled bool
	// Hits is the number of validations served without an HTTP request.
	Hits uint64
	// Misses is the number of validations that had to call the auth service
	// (a cold key, an expired entry, or a WithFreshValidation call).
	Misses uint64
	// Entries is the number of cached decisions currently held, live or expired.
	Entries int
}

// WithValidationCache configures the in-process cache for ValidateToken,
// ValidateTokenWith, ValidateAPIKey and Authorize EXPLICITLY, using ttl for
// every positive decision and the package defaults for everything else.
//
// Without this option the cache is ON with per-question defaults (API key 60 s,
// JWT 15 s, permission decision 15 s; see validationcache.go). Use this option to
// choose one TTL yourself, or to turn the cache off:
//
//	client := authclient.New("", authclient.WithValidationCache(0)) // off: every validation is an HTTP call
//
// A non-positive ttl disables the cache — that is the documented way to turn it
// off, including in a config-driven service that wants the knob to exist.
//
// READ THIS BEFORE CHOOSING A TTL. The TTL is the maximum time a revoked
// credential, a removed permission, or a deleted API key can continue to be
// accepted by this process. Choose it against your revocation requirement, not
// against your latency target, and call InvalidateValidation when you revoke
// something you know about locally.
func WithValidationCache(ttl time.Duration) Option {
	return WithValidationCacheOptions(ValidationCacheOptions{TTL: ttl})
}

// WithValidationCacheOptions is WithValidationCache with full control over the
// negative TTL and the entry bound. Like WithValidationCache, it replaces the
// per-question defaults; a non-positive TTL disables the cache.
func WithValidationCacheOptions(o ValidationCacheOptions) Option {
	return func(c *Client) {
		c.vcacheConfigured = true
		if o.TTL <= 0 {
			c.vcache = nil
			return
		}
		neg := o.NegativeTTL
		switch {
		case neg == 0:
			neg = DefaultValidationCacheNegativeTTL
		case neg < 0:
			neg = 0 // explicit opt-out of caching negatives
		}
		if neg > o.TTL {
			neg = o.TTL
		}
		max := o.MaxEntries
		if max <= 0 {
			max = DefaultValidationCacheMaxEntries
		}
		v := &validationCache{
			explicit:   true,
			maxEntries: max,
			entries:    make(map[string]*validationEntry),
			now:        time.Now,
		}
		for i := range v.policy {
			v.policy[i] = ttlPolicy{pos: o.TTL, neg: neg}
		}
		c.vcache = v
	}
}

// newDefaultValidationCache is the cache a client gets when it configures none:
// the owner-approved per-question TTLs (see the file comment).
func newDefaultValidationCache() *validationCache {
	v := &validationCache{
		maxEntries: DefaultValidationCacheMaxEntries,
		entries:    make(map[string]*validationEntry),
		now:        time.Now,
	}
	v.policy[classToken] = ttlPolicy{pos: DefaultTokenValidationTTL, neg: DefaultTokenValidationNegativeTTL}
	v.policy[classAPIKey] = ttlPolicy{pos: DefaultAPIKeyValidationTTL, neg: DefaultAPIKeyValidationNegativeTTL}
	v.policy[classDecision] = ttlPolicy{pos: DefaultAuthorizeTTL, neg: DefaultAuthorizeNegativeTTL}
	return v
}

// WithFreshValidation returns a context that makes ValidateToken,
// ValidateTokenWith, ValidateAPIKey and Authorize skip the validation cache for
// calls made with it: the auth service is always asked, and its answer then
// refreshes the cached entry for everyone else.
//
// Use it on sensitive operations where the cache's revocation latency is not
// acceptable — admin actions, money movement, ownership changes:
//
//	ok, err := client.Authorize(authclient.WithFreshValidation(r.Context()), tok, "billing.refund", res)
//
// It changes nothing when the cache is disabled (every call is already fresh).
func WithFreshValidation(ctx context.Context) context.Context {
	return context.WithValue(ctx, freshValidationKey{}, true)
}

type freshValidationKey struct{}

func isFreshValidation(ctx context.Context) bool {
	v, _ := ctx.Value(freshValidationKey{}).(bool)
	return v
}

// ValidationCacheStats returns a snapshot of cache activity. Safe to call
// concurrently; cheap enough to export as a metric.
func (c *Client) ValidationCacheStats() ValidationCacheStats {
	v := c.vcache
	if v == nil {
		return ValidationCacheStats{}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return ValidationCacheStats{
		Enabled: true,
		Hits:    v.hits,
		Misses:  v.misses,
		Entries: len(v.entries),
	}
}

// InvalidateValidation drops every cached decision for one credential, across
// every request shape it was validated under (identity, permission decisions and
// resource-scoped Authorize decisions alike).
//
// Use it the moment this process learns a credential is no longer good — it
// revoked the key itself, it handled a revocation webhook, a user logged out.
// That turns the TTL into a bound on how long an UNNOTICED revocation lingers,
// rather than a bound on every revocation.
func (c *Client) InvalidateValidation(cred string) {
	v := c.vcache
	if v == nil || cred == "" {
		return
	}
	prefix := credentialFingerprint(cred)
	v.mu.Lock()
	defer v.mu.Unlock()
	for k := range v.entries {
		if strings.HasPrefix(k, prefix) {
			delete(v.entries, k)
		}
	}
}

// ResetValidationCache drops every cached decision. Intended for tests and for a
// deliberate "trust nothing" reset; ordinary revocation should use
// InvalidateValidation, which does not punish every other credential.
func (c *Client) ResetValidationCache() {
	v := c.vcache
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.entries = make(map[string]*validationEntry)
}

// ---- internals ----

// cacheClass names the QUESTION a cached decision answers; each class has its own
// TTL pair. The class follows the credential and the question, not the method
// name: ValidateToken with an ab0t_sk_ key is an API-key identity question, and
// any call carrying RequiredPermissions is a permission decision.
type cacheClass int

const (
	classToken    cacheClass = iota // JWT identity
	classAPIKey                     // API-key identity
	classDecision                   // a permission decision
	numCacheClasses
)

type ttlPolicy struct {
	pos time.Duration // positive ("valid" / "allowed")
	neg time.Duration // negative ("not valid" / "denied"); 0 = do not cache negatives
}

type validationCache struct {
	policy     [numCacheClasses]ttlPolicy
	maxEntries int

	// explicit is true when the consumer configured the cache itself. It keeps
	// the pre-v0.12.0 scope exactly: the resource-scoped PDP decision inside
	// Authorize is not cached under an explicit configuration.
	explicit bool

	// now is time.Now, replaceable in tests so TTL behaviour is asserted
	// deterministically rather than by sleeping.
	now func() time.Time

	mu      sync.Mutex
	entries map[string]*validationEntry
	hits    uint64
	misses  uint64
}

type validationEntry struct {
	// flight serializes refreshes of this one key, so a cold cache under load
	// makes one auth call rather than one per in-flight request.
	flight sync.Mutex

	actor *Actor
	// err, when non-nil, is a cached DEFINITE negative that the service
	// delivered as an error (a 401 from validate-token). Only getWith's
	// negativeErr classifier puts an error here; no other error is ever stored.
	err     error
	expires time.Time
}

// credentialFingerprint is the cache-key prefix derived from the credential
// alone. Keying on a digest rather than the credential keeps the plaintext out
// of the map, and having the credential occupy a fixed-length PREFIX is what
// makes InvalidateValidation able to drop every request shape for one
// credential without holding a second index.
func credentialFingerprint(cred string) string {
	sum := sha256.Sum256([]byte("ab0t-auth-sdk/cred\x00" + cred))
	return hex.EncodeToString(sum[:]) + "|"
}

// validationKey builds the full cache key: the credential fingerprint followed
// by a digest of every other input that can change the answer.
//
// Each component is length-prefixed before hashing so that no two distinct
// inputs can serialize to the same bytes — without it, permissions
// {"a","bc"} and {"ab","c"} would collide, and a collision in this cache is an
// authorization decision applied to the wrong request.
//
// Required permissions are NOT sorted. Sorting would raise the hit rate by
// merging orderings, but it would also be this SDK asserting that the service
// treats the list as an unordered set. It is not this SDK's fact to assert.
func validationKey(kind, cred, audience string, perms []string, includePerms bool) string {
	var b strings.Builder
	writeField := func(s string) {
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
		b.WriteByte(0x1e)
	}
	writeField(kind)
	writeField(audience)
	writeField(strconv.Itoa(len(perms)))
	for _, p := range perms {
		writeField(p)
	}
	writeField(strconv.FormatBool(includePerms))
	sum := sha256.Sum256([]byte(b.String()))
	return credentialFingerprint(cred) + hex.EncodeToString(sum[:])
}

// entryFor returns the entry for key, creating (and bounding) as needed.
func (v *validationCache) entryFor(key string) *validationEntry {
	v.mu.Lock()
	defer v.mu.Unlock()
	if e := v.entries[key]; e != nil {
		return e
	}
	v.evictIfFullLocked()
	e := &validationEntry{}
	v.entries[key] = e
	return e
}

// evictIfFullLocked keeps the cache bounded. Caller must hold v.mu.
//
// Expired entries go first — they are free to drop and dropping them is not even
// a cache miss. Only if that clears nothing does it evict a live entry, choosing
// the one closest to expiry, so the freshest decisions survive. Dropping any
// entry is always safe: the cost is one revalidation.
func (v *validationCache) evictIfFullLocked() {
	if len(v.entries) < v.maxEntries {
		return
	}
	now := v.now()
	freed := false
	for k, e := range v.entries {
		if !e.flight.TryLock() {
			continue
		}
		expired := (e.actor == nil && e.err == nil) || !now.Before(e.expires)
		e.flight.Unlock()
		if expired {
			delete(v.entries, k)
			freed = true
		}
	}
	if freed {
		return
	}
	var victim string
	var soonest time.Time
	first := true
	for k, e := range v.entries {
		if !e.flight.TryLock() {
			continue
		}
		exp := e.expires
		e.flight.Unlock()
		if first || exp.Before(soonest) {
			victim, soonest, first = k, exp, false
		}
	}
	if !first {
		delete(v.entries, victim)
	}
}

// get runs fetch under the cache, returning a cached *Actor when one is live.
//
// class selects the TTL pair for the question being asked. notAfter, when
// non-zero, is an extra cap on a POSITIVE entry (the credential's own expiry as
// known to the caller); it can only shorten an entry. A context marked with
// WithFreshValidation skips the read (always fetches) but still stores the fresh
// answer, so the next caller benefits from it.
//
// The returned Actor is always a COPY: the cache hands the same decision to
// every caller, and a caller that appended to Permissions would otherwise
// corrupt the cached entry for everyone else.
func (v *validationCache) get(ctx context.Context, key string, class cacheClass, notAfter time.Time, fetch func(context.Context) (*Actor, error)) (*Actor, error) {
	return v.getWith(ctx, key, class, notAfter, fetch, nil)
}

// getWith is get with one addition: an error for which negativeErr reports true
// is a DEFINITE negative answer delivered as an error (validate-token's 401),
// not a failure. It is cached for the class's negative TTL — exactly like a
// {valid:false} — and a hit returns a copy of the same error. A nil negativeErr
// caches no error at all; every error it does not match is never cached.
func (v *validationCache) getWith(ctx context.Context, key string, class cacheClass, notAfter time.Time, fetch func(context.Context) (*Actor, error), negativeErr func(error) bool) (*Actor, error) {
	e := v.entryFor(key)

	e.flight.Lock()
	defer e.flight.Unlock()

	now := v.now()
	if !isFreshValidation(ctx) && now.Before(e.expires) {
		if e.actor != nil {
			v.count(true)
			return copyActor(e.actor), nil
		}
		if e.err != nil {
			v.count(true)
			return nil, copyError(e.err)
		}
	}

	v.count(false)
	actor, err := fetch(ctx)
	if err != nil {
		if negativeErr != nil && negativeErr(err) {
			// A definite "not valid", delivered as an error. Remember it for the
			// negative TTL (it can only deny) and hand back the same error.
			if neg := v.policy[class].neg; neg > 0 {
				e.actor, e.err, e.expires = nil, copyError(err), now.Add(neg)
			} else {
				e.actor, e.err, e.expires = nil, nil, time.Time{}
			}
			return nil, err
		}
		// Never cache an error (a 429, a 5xx, a network failure), and never serve
		// a stale decision through one. An auth-service outage must not extend the
		// life of every credential this process has seen.
		return nil, err
	}
	if actor == nil {
		return nil, nil
	}

	p := v.policy[class]
	ttl := p.pos
	if !actor.Valid {
		ttl = p.neg
	}
	if ttl <= 0 {
		// Caching disabled for this class of answer (negatives, when the caller
		// opted out). Drop any stale entry so it cannot be served later.
		e.actor, e.err, e.expires = nil, nil, time.Time{}
		return actor, nil
	}

	expires := now.Add(ttl)
	// A positive decision must never outlive the credential itself.
	if actor.Valid {
		if exp, ok := parseActorExpiry(actor.ExpiresAt); ok && exp.Before(expires) {
			expires = exp
		}
		if !notAfter.IsZero() && notAfter.Before(expires) {
			expires = notAfter
		}
	}
	if !expires.After(now) {
		e.actor, e.err, e.expires = nil, nil, time.Time{}
		return actor, nil
	}

	e.actor, e.err, e.expires = copyActor(actor), nil, expires
	return actor, nil
}

// copyError hands out a cached error so no caller can alter the shared entry: an
// *APIError is copied (same type, same fields); anything else is returned as is.
func copyError(err error) error {
	if ae, ok := err.(*APIError); ok && ae != nil {
		cp := *ae
		return &cp
	}
	return err
}

func (v *validationCache) count(hit bool) {
	v.mu.Lock()
	if hit {
		v.hits++
	} else {
		v.misses++
	}
	v.mu.Unlock()
}

func copyActor(a *Actor) *Actor {
	if a == nil {
		return nil
	}
	out := *a
	if a.Permissions != nil {
		out.Permissions = append([]string(nil), a.Permissions...)
	}
	if a.Audience != nil {
		out.Audience = append([]string(nil), a.Audience...)
	}
	if a.DelegationScope != nil {
		out.DelegationScope = append([]string(nil), a.DelegationScope...)
	}
	if a.DelegationChain != nil {
		out.DelegationChain = append([]string(nil), a.DelegationChain...)
	}
	return &out
}

// parseActorExpiry interprets the service's expires_at. It accepts RFC 3339 with
// or without an offset, and a bare Unix-seconds integer, because both shapes
// have been observed on the wire. An unrecognized value yields ok=false, and the
// TTL then stands alone — an unparseable expiry must not silently become "no
// expiry", nor must it be treated as already expired.
func parseActorExpiry(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			if t.Location() == time.UTC || strings.ContainsAny(s, "Z+") {
				return t, true
			}
			// A layout with no zone parses as UTC; the auth service emits naive
			// UTC, so that is the right reading.
			return t.UTC(), true
		}
	}
	if secs, err := strconv.ParseInt(s, 10, 64); err == nil && secs > 0 {
		return time.Unix(secs, 0).UTC(), true
	}
	return time.Time{}, false
}
