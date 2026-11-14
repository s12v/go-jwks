package jwks

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// fetchTimeout bounds a single request to the source, so that a hanging
// source cannot block further fetches forever.
const fetchTimeout = 15 * time.Second

// DefaultMinFetchInterval is the default minimum interval between two
// requests to the source, see WithMinFetchInterval.
const DefaultMinFetchInterval = 10 * time.Second

// ErrKeyNotFound is returned (wrapped) when the key set has no key with the
// requested id and use. Any other error means that the key set could not be
// loaded.
var ErrKeyNotFound = errors.New("JWK is not found")

type JWKSClient interface {
	GetKey(ctx context.Context, keyId string, use string) (*jose.JSONWebKey, error)
	GetEncryptionKey(ctx context.Context, keyId string) (*jose.JSONWebKey, error)
	GetSignatureKey(ctx context.Context, keyId string) (*jose.JSONWebKey, error)
}

// Option configures a client created by NewClient or NewDefaultClient.
type Option func(*jWKSClient)

// WithMinFetchInterval sets the minimum interval between two requests to the
// source. A key set that was fetched less than d ago is reused instead of
// being fetched again, so a key that is not in it is reported as not found
// without contacting the source. This limits the load that requests with
// unknown key ids can put on the key server to one request per d; the price
// is that a key added to the key set may stay unknown for up to d.
//
// The default is DefaultMinFetchInterval. Zero or a negative value disables
// the limit: every cache miss then queries the source (concurrent misses
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
	refreshing       atomic.Bool
	now              func() time.Time

	mu        sync.Mutex
	inflight  *fetchCall          // request to the source in progress, if any
	keySet    *jose.JSONWebKeySet // last key set fetched successfully
	fetchedAt time.Time
}

// fetchCall is a request to the source shared by everyone who needs the key
// set while it is in progress.
type fetchCall struct {
	done   chan struct{}
	keySet *jose.JSONWebKeySet
	err    error
}

// cacheEntry with a nil jwk marks a key that was cached and then disappeared
// from the key set. Cache has no way to delete an entry, so it is overwritten
// with such a marker instead.
type cacheEntry struct {
	jwk     *jose.JSONWebKey
	refresh int64
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
		now:              time.Now,
	}
	for _, opt := range opts {
		opt(c)
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
func (c *jWKSClient) GetKey(ctx context.Context, keyId string, use string) (jwk *jose.JSONWebKey, err error) {
	if val, found := c.cache.Get(cacheKey(keyId, use)); found {
		if entry := val.(*cacheEntry); entry.jwk != nil {
			if c.now().After(time.Unix(entry.refresh, 0)) && c.refreshing.CompareAndSwap(false, true) {
				go c.refreshKey(ctx, keyId, use)
			}
			return entry.jwk, nil
		}
	}
	return c.loadKey(ctx, keyId, use)
}

// refreshKey reloads a cached key in the background. A key that is gone from
// the key set is dropped from the cache; if the key set cannot be loaded, the
// cached key stays.
func (c *jWKSClient) refreshKey(ctx context.Context, keyId string, use string) {
	defer c.refreshing.Store(false)
	// The caller's context is usually cancelled as soon as its request
	// completes; keep its values (tracing etc.) but not its cancellation.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
	defer cancel()

	_, err := c.loadKey(ctx, keyId, use)
	switch {
	case errors.Is(err, ErrKeyNotFound):
		c.cache.Set(cacheKey(keyId, use), &cacheEntry{})
		logger.Printf("key removed from cache: %v", err)
	case err != nil:
		logger.Printf("unable to refresh key: %v", err)
	}
}

// loadKey looks the key up in the key set and caches it if it is there.
// Nothing is cached for a key that is not: key ids come from untrusted
// tokens, so there may be any number of them.
func (c *jWKSClient) loadKey(ctx context.Context, keyId string, use string) (*jose.JSONWebKey, error) {
	keySet, err := c.loadKeySet(ctx)
	if err != nil {
		return nil, err
	}
	jwk, err := findKey(keySet, keyId, use)
	if err != nil {
		return nil, err
	}

	c.cache.Set(cacheKey(keyId, use), &cacheEntry{
		jwk:     jwk,
		refresh: c.now().Add(c.refresh).Unix(),
	})
	return jwk, nil
}

// loadKeySet returns the key set fetched within the last minFetchInterval,
// or else fetches it from the source. Concurrent callers share one request.
func (c *jWKSClient) loadKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	c.mu.Lock()
	if c.keySet != nil && c.now().Sub(c.fetchedAt) < c.minFetchInterval {
		keySet := c.keySet
		c.mu.Unlock()
		return keySet, nil
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
	c.mu.Unlock()

	select {
	case <-call.done:
		return call.keySet, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *jWKSClient) fetch(ctx context.Context, call *fetchCall) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	defer func() {
		// A panic here would otherwise take the whole process down and
		// could not be recovered by the callers.
		if r := recover(); r != nil {
			call.keySet, call.err = nil, fmt.Errorf("JWKS source panicked: %v", r)
		}
		c.mu.Lock()
		if call.err == nil {
			c.keySet, c.fetchedAt = call.keySet, c.now()
		}
		c.inflight = nil
		c.mu.Unlock()
		close(call.done)
	}()

	call.keySet, call.err = c.source.JSONWebKeySet(ctx)
	if call.err == nil && call.keySet == nil {
		call.err = errors.New("JWKS source returned no key set")
	}
}

func findKey(keySet *jose.JSONWebKeySet, keyId string, use string) (*jose.JSONWebKey, error) {
	keys := keySet.Key(keyId)
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyId)
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
	return nil, fmt.Errorf("%w: %s, use: %s", ErrKeyNotFound, keyId, use)
}

// cacheKey makes cache entries specific to the requested use, so that a key
// fetched for one use is never served for another.
func cacheKey(keyId string, use string) string {
	return use + ":" + keyId
}
