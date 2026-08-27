package authclient

// validationcache.go — an opt-in, TTL-bounded cache for credential validation.
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
// WHY IT IS OPT-IN AND NOT ON BY DEFAULT
//
// Caching a validation decision extends the useful life of a credential that has
// been revoked, expired, or had a permission removed, by up to the TTL. That is
// a change to a SECURITY property, not a performance tuning knob, and it is not
// something a consumer should acquire by upgrading a library. So: no cache
// unless the consumer asks for one (WithValidationCache), and the TTL it gets is
// the one it named. Disabling is a zero TTL, and a disabled cache is not merely
// bypassed — it is not allocated.
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
//  2. It fails OPEN. An error is never cached, and — unlike the JWKS cache,
//     which deliberately serves a stale key set through a transient outage — an
//     EXPIRED entry is never served after a failed refresh. During an auth
//     outage this cache stops answering rather than extending every credential
//     it has seen. Failing closed is the correct direction for an authorization
//     decision.
//
//  3. It outlives the credential. A positive entry's TTL is additionally capped
//     by the token's own ExpiresAt when the service reports one, so the cache
//     can never make an expired token look valid. A negative decision gets its
//     own, shorter TTL: a "no" that becomes a "yes" (a permission just granted)
//     should not take the full TTL to be noticed, and negatives are the cheap
//     side of the trade.
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

// DefaultValidationCacheTTL is the recommended starting point for a hot path:
// short enough that a revocation is noticed in seconds, long enough that a
// service under load makes one validation call per credential per interval
// instead of one per request. It is a SUGGESTION, not a fallback — a
// non-positive TTL disables the cache rather than substituting this value, so
// "off" cannot be reached by accident and cannot be left ambiguous.
const DefaultValidationCacheTTL = 30 * time.Second

// DefaultValidationCacheNegativeTTL is the TTL applied to a NEGATIVE decision
// (the service answered, and said no) when the caller does not choose one. It is
// deliberately much shorter than the positive TTL: a denial that has just been
// fixed by granting a permission should start working promptly, and caching
// denials aggressively buys little — a denied caller is not usually a hot path.
const DefaultValidationCacheNegativeTTL = 5 * time.Second

// DefaultValidationCacheMaxEntries bounds the number of distinct cached
// decisions. Entries are keyed by credential (hashed) plus request shape, so an
// unbounded map grows by one entry per distinct credential ever seen and never
// shrinks — a leak keyed by tenant. The bound is generous; eviction costs only a
// revalidation.
const DefaultValidationCacheMaxEntries = 4096

// ValidationCacheOptions configures the validation cache. A zero TTL disables
// the cache entirely.
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
	// (a cold key, or an expired entry).
	Misses uint64
	// Entries is the number of cached decisions currently held, live or expired.
	Entries int
}

// WithValidationCache enables an in-process TTL cache for ValidateToken,
// ValidateTokenWith, ValidateAPIKey and Authorize, using ttl for positive
// decisions and the package defaults for everything else.
//
// A non-positive ttl disables the cache — that is the documented way to turn it
// off, including in a config-driven service that wants the knob to exist.
//
//	client := authclient.New("", authclient.WithValidationCache(authclient.DefaultValidationCacheTTL))
//
// READ THIS BEFORE ENABLING. The TTL is the maximum time a revoked credential,
// a removed permission, or a deleted API key can continue to be accepted by this
// process. Choose it against your revocation requirement, not against your
// latency target, and call InvalidateValidation when you revoke something you
// know about locally.
func WithValidationCache(ttl time.Duration) Option {
	return WithValidationCacheOptions(ValidationCacheOptions{TTL: ttl})
}

// WithValidationCacheOptions is WithValidationCache with full control over the
// negative TTL and the entry bound.
func WithValidationCacheOptions(o ValidationCacheOptions) Option {
	return func(c *Client) {
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
		c.vcache = &validationCache{
			ttl:        o.TTL,
			negTTL:     neg,
			maxEntries: max,
			entries:    make(map[string]*validationEntry),
			now:        time.Now,
		}
	}
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
// every request shape it was validated under.
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

type validationCache struct {
	ttl        time.Duration
	negTTL     time.Duration
	maxEntries int

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

	actor   *Actor
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
func validationKey(kind, cred, audience string, perms []string, resourceType, resourceID string, includePerms bool) string {
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
	writeField(resourceType)
	writeField(resourceID)
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
		expired := e.actor == nil || !now.Before(e.expires)
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
// The returned Actor is always a COPY: the cache hands the same decision to
// every caller, and a caller that appended to Permissions would otherwise
// corrupt the cached entry for everyone else.
func (v *validationCache) get(ctx context.Context, key string, fetch func(context.Context) (*Actor, error)) (*Actor, error) {
	e := v.entryFor(key)

	e.flight.Lock()
	defer e.flight.Unlock()

	now := v.now()
	if e.actor != nil && now.Before(e.expires) {
		v.count(true)
		return copyActor(e.actor), nil
	}

	v.count(false)
	actor, err := fetch(ctx)
	if err != nil {
		// Never cache an error, and never serve a stale decision through one.
		// An auth-service outage must not extend the life of every credential
		// this process has seen.
		return nil, err
	}
	if actor == nil {
		return nil, nil
	}

	ttl := v.ttl
	if !actor.Valid {
		ttl = v.negTTL
	}
	if ttl <= 0 {
		// Caching disabled for this class of answer (negatives, when the caller
		// opted out). Drop any stale entry so it cannot be served later.
		e.actor, e.expires = nil, time.Time{}
		return actor, nil
	}

	expires := now.Add(ttl)
	// A positive decision must never outlive the credential itself.
	if actor.Valid {
		if exp, ok := parseActorExpiry(actor.ExpiresAt); ok && exp.Before(expires) {
			expires = exp
		}
	}
	if !expires.After(now) {
		e.actor, e.expires = nil, time.Time{}
		return actor, nil
	}

	e.actor, e.expires = copyActor(actor), expires
	return actor, nil
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
