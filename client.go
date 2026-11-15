package jwks

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
)

const (
	// defaultFetchTimeout bounds a single request to the source. A source
	// that has not answered by then is given up on, even if it ignores its
	// context, so that it cannot block further requests forever.
	defaultFetchTimeout = 15 * time.Second

	// backgroundRefreshWindow is how long a cached key that is due for a
	// refresh is still served without waiting, while the key set is fetched
	// in the background. A key that is due for longer than that (it was not
	// requested in the meantime, or the refresh did not finish) is checked
	// against the source before it is served.
	backgroundRefreshWindow = 10 * time.Second

	// maxFailureBackoff is the longest pause between two requests to a
	// failing source.
	maxFailureBackoff = time.Second
)

// DefaultMinFetchInterval is the default minimum interval between two
// requests to the source, see WithMinFetchInterval.
const DefaultMinFetchInterval = 10 * time.Second

// ErrKeyNotFound is returned (wrapped) when the key set has no key with the
// requested id and use.
var ErrKeyNotFound = errors.New("JWK is not found")

type JWKSClient interface {
	GetKey(ctx context.Context, keyId string, use string) (*jose.JSONWebKey, error)
	GetEncryptionKey(ctx context.Context, keyId string) (*jose.JSONWebKey, error)
	GetSignatureKey(ctx context.Context, keyId string) (*jose.JSONWebKey, error)
}

// Option configures a client created by NewClient or NewDefaultClient.
type Option func(*jWKSClient)

// WithMinFetchInterval sets the minimum interval between two successful
// requests to the source. A key set that was fetched less than d ago is
// reused instead of being fetched again, so a key that is not in it is
// reported as not found without contacting the source. This limits the load
// that requests with unknown key ids can put on the key server; the price is
// that a key added to the key set may stay unknown for up to d. Cached keys
// are not refreshed more often than that either.
//
// After a failed request the source is not queried again for one second, or
// for d if that is shorter; the error is returned in the meantime.
//
// The default is DefaultMinFetchInterval. Zero or a negative value disables
// both limits: every cache miss then queries the source (concurrent misses
// still share one request).
func WithMinFetchInterval(d time.Duration) Option {
	return func(c *jWKSClient) {
		c.minFetchInterval = d
	}
}

type jWKSClient struct {
	source           JWKSSource
	cache            Cache
	refresh          time.Duration
	minFetchInterval time.Duration
	fetchTimeout     time.Duration
	now              func() time.Time

	refreshing atomic.Bool
	// last key set fetched successfully
	current atomic.Pointer[keySetSnapshot]

	mu       sync.Mutex
	inflight *fetchCall // request to the source in progress, if any
	// outcome of the last request to the source, if it failed
	lastErr  error
	failedAt time.Time
}

type keySetSnapshot struct {
	keySet     *jose.JSONWebKeySet
	fetchedAt  time.Time
	generation uint64
}

// fetchCall is a request to the source shared by everyone who needs the key
// set while it is in progress.
type fetchCall struct {
	done     chan struct{}
	snapshot *keySetSnapshot
	err      error
	waiters  int
}

// cacheEntry is a key together with the key set it was last seen in.
//
// An entry with a nil jwk marks a key that was cached and then disappeared
// from the key set. Cache has no way to delete an entry, so it is overwritten
// with such a marker instead.
type cacheEntry struct {
	jwk        *jose.JSONWebKey
	checkedAt  time.Time
	generation uint64
}

// Creates a new client with default cache implementation
func NewDefaultClient(source JWKSSource, refresh time.Duration, ttl time.Duration, opts ...Option) JWKSClient {
	if refresh >= ttl {
		panic(fmt.Sprintf("invalid refresh: %v greater or equal to ttl: %v", refresh, ttl))
	}
	if refresh < 0 {
		panic(fmt.Sprintf("invalid refresh: %v", refresh))
	}
	return NewClient(source, DefaultCache(ttl), refresh, opts...)
}

func NewClient(source JWKSSource, cache Cache, refresh time.Duration, opts ...Option) JWKSClient {
	c := &jWKSClient{
		source:           source,
		cache:            cache,
		refresh:          refresh,
		minFetchInterval: DefaultMinFetchInterval,
		fetchTimeout:     defaultFetchTimeout,
		now:              time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

func (c *jWKSClient) GetSignatureKey(ctx context.Context, keyId string) (*jose.JSONWebKey, error) {
	return c.GetKey(ctx, keyId, "sig")
}

func (c *jWKSClient) GetEncryptionKey(ctx context.Context, keyId string) (*jose.JSONWebKey, error) {
	return c.GetKey(ctx, keyId, "enc")
}

// GetKey returns the key with the given id and "use" ("sig" or "enc"), or a
// key with the given id that has no "use". A key that declares a different
// "use" is not returned. An empty use matches any key.
//
// If there is no such key, the error wraps ErrKeyNotFound.
//
// The returned JSONWebKey is the caller's own: changing its fields, or the
// contents of its slices, does not affect the key that other callers get.
// What it points to is shared and must not be modified: an RSA or EC key in
// Key, the certificates in Certificates, and CertificatesURL.
func (c *jWKSClient) GetKey(ctx context.Context, keyId string, use string) (*jose.JSONWebKey, error) {
	cached, err := c.getKey(ctx, keyId, use)
	if err != nil {
		return nil, err
	}
	// The key lives in the cache and is handed to every caller: give each
	// one a copy, so that none of them can change it for the others.
	key := *cached
	key.Certificates = slices.Clone(cached.Certificates)
	key.CertificateThumbprintSHA1 = slices.Clone(cached.CertificateThumbprintSHA1)
	key.CertificateThumbprintSHA256 = slices.Clone(cached.CertificateThumbprintSHA256)
	// some keys are slices themselves
	switch material := cached.Key.(type) {
	case ed25519.PublicKey:
		key.Key = slices.Clone(material)
	case ed25519.PrivateKey:
		key.Key = slices.Clone(material)
	case []byte:
		key.Key = slices.Clone(material)
	}
	return &key, nil
}

func (c *jWKSClient) getKey(ctx context.Context, keyId string, use string) (*jose.JSONWebKey, error) {
	val, found := c.cache.Get(cacheKey(keyId, use))
	if !found {
		return c.loadKey(ctx, keyId, use)
	}
	entry := val.(*cacheEntry)
	if entry.jwk == nil {
		return c.loadKey(ctx, keyId, use)
	}
	jwk, checkedAt := entry.jwk, entry.checkedAt

	// A key set fetched since the key was cached is already in memory:
	// whatever it says about the key takes precedence.
	if snapshot := c.current.Load(); snapshot != nil && snapshot.generation != entry.generation {
		var err error
		if jwk, err = c.readKey(snapshot, keyId, use); err != nil {
			c.drop(keyId, use, err)
			return nil, err
		}
		checkedAt = snapshot.fetchedAt
	}

	// The key set is not fetched more often than minFetchInterval, so
	// there is no point in refreshing a key more often than that.
	maxAge := max(c.refresh, c.minFetchInterval)
	age := c.now().Sub(checkedAt)
	if age <= maxAge {
		return jwk, nil
	}
	if age <= maxAge+backgroundRefreshWindow || c.sourceFailing() {
		c.refreshInBackground(ctx)
		return jwk, nil
	}

	// The key was last seen in the key set too long ago to trust it.
	fresh, err := c.loadKey(ctx, keyId, use)
	switch {
	case err == nil:
		return fresh, nil
	case errors.Is(err, ErrKeyNotFound):
		c.drop(keyId, use, err)
		return nil, err
	case ctx.Err() != nil:
		return nil, err
	}
	// The source is unavailable: better an old key than none.
	return jwk, nil
}

// refreshInBackground fetches the key set without making the caller wait.
// Cached keys pick the new key set up the next time they are requested.
func (c *jWKSClient) refreshInBackground(ctx context.Context) {
	if !c.refreshing.CompareAndSwap(false, true) {
		return
	}
	c.mu.Lock()
	snapshot, err := c.recentOutcome()
	c.mu.Unlock()
	if snapshot != nil || err != nil {
		// too early for another request to the source
		c.refreshing.Store(false)
		return
	}
	go func() {
		defer c.refreshing.Store(false)
		// The caller's context is usually cancelled as soon as its request
		// completes; keep its values (tracing etc.) but not its cancellation.
		// A failure is logged by fetch.
		_, _ = c.loadKeySet(context.WithoutCancel(ctx))
	}()
}

// loadKey looks the key up in the key set and caches it if it is there.
// Nothing is cached for a key that is not: key ids come from untrusted
// tokens, so there may be any number of them.
func (c *jWKSClient) loadKey(ctx context.Context, keyId string, use string) (*jose.JSONWebKey, error) {
	snapshot, err := c.loadKeySet(ctx)
	if err != nil {
		return nil, err
	}
	return c.readKey(snapshot, keyId, use)
}

func (c *jWKSClient) readKey(snapshot *keySetSnapshot, keyId string, use string) (*jose.JSONWebKey, error) {
	jwk, err := findKey(snapshot.keySet, keyId, use)
	if err != nil {
		return nil, err
	}
	c.cache.Set(cacheKey(keyId, use), &cacheEntry{
		jwk:        jwk,
		checkedAt:  snapshot.fetchedAt,
		generation: snapshot.generation,
	})
	return jwk, nil
}

// drop removes a cached key that is no longer in the key set.
func (c *jWKSClient) drop(keyId string, use string, reason error) {
	c.cache.Set(cacheKey(keyId, use), &cacheEntry{})
	logf("key removed from cache: %v", reason)
}

// loadKeySet returns the key set fetched within the last minFetchInterval,
// or else fetches it from the source. Concurrent callers share one request.
func (c *jWKSClient) loadKeySet(ctx context.Context) (*keySetSnapshot, error) {
	c.mu.Lock()
	if snapshot, err := c.recentOutcome(); snapshot != nil || err != nil {
		c.mu.Unlock()
		return snapshot, err
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	call := c.inflight
	if call == nil {
		call = &fetchCall{done: make(chan struct{})}
		c.inflight = call
		// The request serves every caller that joins it, so it must not die
		// with the context of the caller that happened to start it.
		go c.fetch(context.WithoutCancel(ctx), call)
	}
	call.waiters++
	c.mu.Unlock()

	select {
	case <-call.done:
		return call.snapshot, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// recentOutcome returns the result of the last request to the source if it
// is too early for another one, and nils if a request is due. c.mu must be
// held.
func (c *jWKSClient) recentOutcome() (*keySetSnapshot, error) {
	now := c.now()
	if snapshot := c.current.Load(); snapshot != nil && now.Sub(snapshot.fetchedAt) < c.minFetchInterval {
		return snapshot, nil
	}
	if c.lastErr != nil && now.Sub(c.failedAt) < min(c.minFetchInterval, maxFailureBackoff) {
		return nil, c.lastErr
	}
	return nil, nil
}

func (c *jWKSClient) sourceFailing() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastErr != nil
}

func (c *jWKSClient) fetch(ctx context.Context, call *fetchCall) {
	ctx, cancel := context.WithTimeout(ctx, c.fetchTimeout)
	defer cancel()

	keySet, err := c.querySource(ctx)

	c.mu.Lock()
	if err == nil {
		call.snapshot = &keySetSnapshot{keySet: keySet, fetchedAt: c.now(), generation: 1}
		if previous := c.current.Load(); previous != nil {
			call.snapshot.generation = previous.generation + 1
		}
		c.current.Store(call.snapshot)
	} else {
		call.err = err
		c.failedAt = c.now()
	}
	c.lastErr = err
	c.inflight = nil
	c.mu.Unlock()
	close(call.done)

	if err != nil {
		logf("unable to fetch JWKS: %v", err)
	}
}

// querySource asks the source for the key set and makes sure that an answer
// comes back by the deadline of ctx, whatever the source does.
func (c *jWKSClient) querySource(ctx context.Context) (*jose.JSONWebKeySet, error) {
	type result struct {
		keySet *jose.JSONWebKeySet
		err    error
	}
	results := make(chan result, 1)
	go func() {
		// reported if the source exits the goroutine without returning
		res := result{err: errors.New("JWKS source did not return")}
		defer func() {
			// A panic here would otherwise take the whole process down
			// and could not be recovered by the callers.
			if r := recover(); r != nil {
				res = result{err: fmt.Errorf("JWKS source panicked: %v", r)}
			}
			results <- res
		}()
		keySet, err := c.source.JSONWebKeySet(ctx)
		res = result{keySet, err}
	}()

	var res result
	select {
	case res = <-results:
	case <-ctx.Done():
		return nil, fmt.Errorf("JWKS source did not respond: %w", ctx.Err())
	}
	if res.err != nil {
		return nil, res.err
	}
	// A key server always has keys. An empty answer is a malfunction (or
	// an error body that happens to parse) and must not pass for "all keys
	// are revoked".
	if res.keySet == nil || len(res.keySet.Keys) == 0 {
		return nil, errors.New("JWKS source returned no keys")
	}
	// The source may keep using the key set it returned.
	return &jose.JSONWebKeySet{Keys: slices.Clone(res.keySet.Keys)}, nil
}

func findKey(keySet *jose.JSONWebKeySet, keyId string, use string) (*jose.JSONWebKey, error) {
	keys := keySet.Key(keyId)
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, quoteUntrusted(keyId))
	}

	// Prefer a key with the requested "use"; fall back to a key without
	// "use" (the parameter is optional and often omitted). A key that
	// declares a different "use" is never returned.
	var fallback *jose.JSONWebKey
	for i := range keys {
		switch keys[i].Use {
		case use:
			return &keys[i], nil
		case "":
			if fallback == nil {
				fallback = &keys[i]
			}
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	if use == "" {
		// no particular use requested
		return &keys[0], nil
	}
	return nil, fmt.Errorf("%w: %s, use: %s", ErrKeyNotFound, quoteUntrusted(keyId), quoteUntrusted(use))
}

// maxUntrustedLen is how much of an untrusted value is quoted in a message.
const maxUntrustedLen = 100

// quoteUntrusted makes a value that this process does not control, such as a
// key id, safe to put into an error or a log message. Key ids come from
// tokens that are not verified yet and errors tend to end up in logs, so a
// value must not be able to break out of its line or to flood the log.
//
// The value is cut to maxUntrustedLen bytes and then quoted; quoting escapes
// control and non-printable characters, so the result can be several times
// longer than that, but it is bounded.
func quoteUntrusted(value string) string {
	if len(value) <= maxUntrustedLen {
		return strconv.Quote(value)
	}
	// do not cut a character in half
	cut := maxUntrustedLen
	for i := 0; i < utf8.UTFMax-1 && !utf8.RuneStart(value[cut]); i++ {
		cut--
	}
	return strconv.Quote(value[:cut]) + "..."
}

// cacheKey makes cache entries specific to the requested use, so that a key
// fetched for one use is never served for another.
func cacheKey(keyId string, use string) string {
	return use + ":" + keyId
}
