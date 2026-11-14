package jwks

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestJWKSClient_GetKey(t *testing.T) {
	keyId := "test-4317493287"
	sourceMock := NewDummySource(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		KeyID: keyId,
	}}})
	cacheMock := NewMockCache()
	ctx := context.TODO()

	client := NewClient(sourceMock, cacheMock, time.Minute)

	jwk, err := client.GetKey(ctx, keyId, "sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if jwk.KeyID != keyId {
		t.Fatalf("unexpected keyID: %v", jwk.KeyID)
	}
}

func TestJWKSClient_GetKeyWithPrefetch(t *testing.T) {
	keyId := "test-4317493287"
	mockJwk := jose.JSONWebKey{
		KeyID:     keyId,
		Use:       "sig",
		Algorithm: "cached",
	}
	sourceMock := NewDummySource(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		KeyID:     keyId,
		Use:       "sig",
		Algorithm: "fetched",
	}}})
	cacheMock := NewMockCache()
	cacheMock.SetWithExpiration(
		cacheKey(keyId, "sig"),
		&cacheEntry{
			refresh: 0,
			jwk:     &mockJwk,
		},
		time.Unix(0, 0),
	)
	ctx := context.TODO()

	client := NewClient(sourceMock, cacheMock, time.Minute)

	key1, err := client.GetKey(ctx, keyId, "sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key1.Algorithm != "cached" {
		t.Fatalf("expected the cached key, got alg=%q", key1.Algorithm)
	}

	// the key is refreshed in the background; wait for it
	deadline := time.Now().Add(time.Second)
	for {
		key2, _ := cacheMock.Get(cacheKey(keyId, "sig"))
		if key2.(*cacheEntry).jwk.Algorithm == "fetched" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("key should be updated in cache")
		}
		time.Sleep(time.Millisecond)
	}
}

// ctxAwareSource fails when the context it is called with is already done,
// like a real HTTP source would.
type ctxAwareSource struct {
	jwks *jose.JSONWebKeySet
}

func (s *ctxAwareSource) JSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.jwks, nil
}

// Regression test for #16: the caller's context is typically cancelled right
// after GetKey returns, which must not break the background refresh.
func TestJWKSClient_BackgroundRefreshWithCancelledContext(t *testing.T) {
	keyId := "test-4317493287"
	source := &ctxAwareSource{&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		KeyID:     keyId,
		Use:       "sig",
		Algorithm: "fetched",
	}}}}
	cacheMock := NewMockCache()
	cacheMock.Set(cacheKey(keyId, "sig"), &cacheEntry{refresh: 0, jwk: &jose.JSONWebKey{KeyID: keyId, Use: "sig", Algorithm: "cached"}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := NewClient(source, cacheMock, time.Minute)
	if _, err := client.GetKey(ctx, keyId, "sig"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		entry, _ := cacheMock.Get(cacheKey(keyId, "sig"))
		if entry.(*cacheEntry).jwk.Algorithm == "fetched" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("key should be refreshed despite the cancelled caller context")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestJWKSClient_GetKeyPrefersUse(t *testing.T) {
	keyId := "shared-kid"
	sourceMock := NewDummySource(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{KeyID: keyId, Use: "enc"},
		{KeyID: keyId, Use: "sig"},
	}})
	ctx := context.TODO()

	client := NewClient(sourceMock, NewMockCache(), time.Minute)

	jwk, err := client.GetSignatureKey(ctx, keyId)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jwk.Use != "sig" {
		t.Fatalf("expected the 'sig' key, got use=%q", jwk.Use)
	}

	// no key with the requested use and none without use
	client = NewClient(sourceMock, NewMockCache(), time.Minute)
	if jwk, err = client.GetKey(ctx, keyId, "other"); err == nil {
		t.Fatalf("expected an error, got use=%q", jwk.Use)
	}
}

func TestJWKSClient_GetKeyRejectsOtherUse(t *testing.T) {
	keyId := "enc-only"
	sourceMock := NewDummySource(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{KeyID: keyId, Use: "enc"},
	}})
	client := NewClient(sourceMock, NewMockCache(), time.Minute)

	if jwk, err := client.GetSignatureKey(context.TODO(), keyId); err == nil {
		t.Fatalf("expected an error, got use=%q", jwk.Use)
	}
}

func TestJWKSClient_GetKeyFallsBackToKeyWithoutUse(t *testing.T) {
	keyId := "shared-kid"
	sourceMock := NewDummySource(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{KeyID: keyId, Use: "enc"},
		{KeyID: keyId},
	}})
	client := NewClient(sourceMock, NewMockCache(), time.Minute)

	jwk, err := client.GetSignatureKey(context.TODO(), keyId)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jwk.Use != "" {
		t.Fatalf("expected the key without use, got use=%q", jwk.Use)
	}
}

func TestJWKSClient_GetKeyAnyUse(t *testing.T) {
	keyId := "enc-only"
	sourceMock := NewDummySource(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{KeyID: keyId, Use: "enc"},
	}})
	client := NewClient(sourceMock, NewMockCache(), time.Minute)

	jwk, err := client.GetKey(context.TODO(), keyId, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jwk.Use != "enc" {
		t.Fatalf("unexpected use: %q", jwk.Use)
	}
}

// A key cached for one use must not be served for another.
func TestJWKSClient_CachePerUse(t *testing.T) {
	keyId := "shared-kid"
	sourceMock := NewDummySource(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{KeyID: keyId, Use: "enc"},
		{KeyID: keyId, Use: "sig"},
	}})
	ctx := context.TODO()
	client := NewClient(sourceMock, NewMockCache(), time.Minute)

	enc, err := client.GetEncryptionKey(ctx, keyId)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enc.Use != "enc" {
		t.Fatalf("expected the 'enc' key, got use=%q", enc.Use)
	}

	sig, err := client.GetSignatureKey(ctx, keyId)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig.Use != "sig" {
		t.Fatalf("expected the 'sig' key, got use=%q", sig.Use)
	}
}

func TestJWKSClient_GetKeyNotFound(t *testing.T) {
	sourceMock := NewDummySource(&jose.JSONWebKeySet{})
	client := NewClient(sourceMock, NewMockCache(), time.Minute)

	if _, err := client.GetKey(context.TODO(), "missing", "sig"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestNewDefaultClient_InvalidNegativeRefresh(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected a panic")
		}
	}()
	sourceMock := NewDummySource(&jose.JSONWebKeySet{})
	NewDefaultClient(sourceMock, time.Second, -1)
}

func TestNewDefaultClient_InvalidRefreshBiggerThanTtl(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected a panic")
		}
	}()
	sourceMock := NewDummySource(&jose.JSONWebKeySet{})
	NewDefaultClient(sourceMock, time.Minute, time.Second)
}

// countingSource counts the requests it gets and can be told to block, fail
// or change its key set.
type countingSource struct {
	mu    sync.Mutex
	jwks  *jose.JSONWebKeySet
	err   error
	calls int
	// if set, every request waits until it is closed
	block chan struct{}
}

func newCountingSource(keys ...jose.JSONWebKey) *countingSource {
	return &countingSource{jwks: &jose.JSONWebKeySet{Keys: keys}}
}

func (s *countingSource) JSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	s.mu.Lock()
	s.calls++
	jwks, err, block := s.jwks, s.err, s.block
	s.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return jwks, err
}

func (s *countingSource) set(err error, keys ...jose.JSONWebKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwks, s.err = &jose.JSONWebKeySet{Keys: keys}, err
}

func (s *countingSource) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newTestClient returns a client that reads the time from the returned clock.
func newTestClient(source JWKSSource, refresh time.Duration, opts ...Option) (*jWKSClient, *fakeClock) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	client := NewClient(source, NewMockCache(), refresh, opts...).(*jWKSClient)
	client.now = clock.Now
	return client, clock
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// Concurrent cache misses must share a single request to the source.
func TestJWKSClient_ConcurrentMissesShareOneFetch(t *testing.T) {
	source := newCountingSource(jose.JSONWebKey{KeyID: "known", Use: "sig"})
	source.block = make(chan struct{})
	client, _ := newTestClient(source, time.Minute)

	const n = 50
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		keyId := "known"
		if i%2 == 1 {
			keyId = fmt.Sprintf("random-%d", i)
		}
		go func() {
			jwk, err := client.GetSignatureKey(context.Background(), keyId)
			switch {
			case keyId == "known" && err != nil:
				errs <- fmt.Errorf("unexpected error: %w", err)
			case keyId == "known" && jwk.KeyID != keyId:
				errs <- fmt.Errorf("unexpected key: %v", jwk.KeyID)
			case keyId != "known" && !errors.Is(err, ErrKeyNotFound):
				errs <- fmt.Errorf("expected ErrKeyNotFound for %s, got: %v", keyId, err)
			default:
				errs <- nil
			}
		}()
	}

	waitFor(t, "the request to the source", func() bool { return source.callCount() > 0 })
	// let the other callers reach the source, if they are going to
	time.Sleep(50 * time.Millisecond)
	close(source.block)

	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	if calls := source.callCount(); calls != 1 {
		t.Fatalf("expected 1 request to the source, got %d", calls)
	}
}

// Unknown key ids must not make the client fetch the key set on every request.
func TestJWKSClient_UnknownKeysDoNotRefetch(t *testing.T) {
	source := newCountingSource(jose.JSONWebKey{KeyID: "known", Use: "sig"})
	client, clock := newTestClient(source, time.Hour, WithMinFetchInterval(10*time.Second))
	ctx := context.Background()

	for i := 0; i < 100; i++ {
		if _, err := client.GetSignatureKey(ctx, fmt.Sprintf("random-%d", i)); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("expected ErrKeyNotFound, got: %v", err)
		}
	}
	if calls := source.callCount(); calls != 1 {
		t.Fatalf("expected 1 request to the source, got %d", calls)
	}

	// a key that is in the key set is served from it as well
	if _, err := client.GetSignatureKey(ctx, "known"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls := source.callCount(); calls != 1 {
		t.Fatalf("expected 1 request to the source, got %d", calls)
	}

	// nothing is remembered per unknown key id
	if n := len(client.cache.(*mockCache).m); n != 1 {
		t.Fatalf("expected only the known key in the cache, got %d entries", n)
	}

	// once the interval has passed, the key set is fetched again
	clock.Advance(10 * time.Second)
	for i := 0; i < 100; i++ {
		if _, err := client.GetSignatureKey(ctx, fmt.Sprintf("random-%d", i)); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("expected ErrKeyNotFound, got: %v", err)
		}
	}
	if calls := source.callCount(); calls != 2 {
		t.Fatalf("expected 2 requests to the source, got %d", calls)
	}
}

// A key added to the key set is found once the minimum interval has passed.
func TestJWKSClient_NewKeyIsFoundAfterMinFetchInterval(t *testing.T) {
	source := newCountingSource(jose.JSONWebKey{KeyID: "old", Use: "sig"})
	client, clock := newTestClient(source, time.Hour, WithMinFetchInterval(10*time.Second))
	ctx := context.Background()

	if _, err := client.GetSignatureKey(ctx, "new"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}

	source.set(nil, jose.JSONWebKey{KeyID: "old", Use: "sig"}, jose.JSONWebKey{KeyID: "new", Use: "sig"})
	clock.Advance(9 * time.Second)
	if _, err := client.GetSignatureKey(ctx, "new"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}

	clock.Advance(time.Second)
	if _, err := client.GetSignatureKey(ctx, "new"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestJWKSClient_MinFetchIntervalDisabled(t *testing.T) {
	source := newCountingSource()
	client, _ := newTestClient(source, time.Hour, WithMinFetchInterval(0))

	for i := 0; i < 3; i++ {
		if _, err := client.GetSignatureKey(context.Background(), "missing"); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("expected ErrKeyNotFound, got: %v", err)
		}
	}
	if calls := source.callCount(); calls != 3 {
		t.Fatalf("expected 3 requests to the source, got %d", calls)
	}
}

// A failed fetch must not be mistaken for a missing key, and must not be
// remembered.
func TestJWKSClient_SourceErrorIsNotCached(t *testing.T) {
	source := newCountingSource(jose.JSONWebKey{KeyID: "known", Use: "sig"})
	source.set(errors.New("boom"))
	client, _ := newTestClient(source, time.Hour)
	ctx := context.Background()

	if _, err := client.GetSignatureKey(ctx, "known"); err == nil || errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected the source error, got: %v", err)
	}

	source.set(nil, jose.JSONWebKey{KeyID: "known", Use: "sig"})
	if _, err := client.GetSignatureKey(ctx, "known"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A key that disappears from the key set stops being served after the next
// refresh, not after the cache ttl.
func TestJWKSClient_RevokedKeyIsDropped(t *testing.T) {
	source := newCountingSource(jose.JSONWebKey{KeyID: "revoked", Use: "sig"})
	client, clock := newTestClient(source, time.Minute, WithMinFetchInterval(10*time.Second))
	ctx := context.Background()

	if _, err := client.GetSignatureKey(ctx, "revoked"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	source.set(nil)
	clock.Advance(2 * time.Minute)

	// the request that triggers the refresh still gets the cached key
	if _, err := client.GetSignatureKey(ctx, "revoked"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitFor(t, "the key to be dropped", func() bool {
		_, err := client.GetSignatureKey(ctx, "revoked")
		return errors.Is(err, ErrKeyNotFound)
	})

	// a dropped key does not cause a fetch on every request either
	calls := source.callCount()
	for i := 0; i < 10; i++ {
		if _, err := client.GetSignatureKey(ctx, "revoked"); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("expected ErrKeyNotFound, got: %v", err)
		}
	}
	if source.callCount() != calls {
		t.Fatalf("expected no more requests to the source, got %d", source.callCount()-calls)
	}

	// if the key comes back, it is served again
	source.set(nil, jose.JSONWebKey{KeyID: "revoked", Use: "sig"})
	clock.Advance(10 * time.Second)
	if _, err := client.GetSignatureKey(ctx, "revoked"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// If the source is unavailable, cached keys keep being served.
func TestJWKSClient_CachedKeySurvivesSourceError(t *testing.T) {
	source := newCountingSource(jose.JSONWebKey{KeyID: "known", Use: "sig"})
	client, clock := newTestClient(source, time.Minute)
	ctx := context.Background()

	if _, err := client.GetSignatureKey(ctx, "known"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	source.set(errors.New("boom"))
	clock.Advance(2 * time.Minute)

	if _, err := client.GetSignatureKey(ctx, "known"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitFor(t, "the failed refresh", func() bool {
		return source.callCount() == 2 && !client.refreshing.Load()
	})
	if _, err := client.GetSignatureKey(ctx, "known"); err != nil {
		t.Fatalf("the cached key should survive a failed refresh, got: %v", err)
	}
}

// A caller that gives up must not break the request for the others waiting
// for it.
func TestJWKSClient_CancelledCallerDoesNotCancelSharedFetch(t *testing.T) {
	source := newCountingSource(jose.JSONWebKey{KeyID: "known", Use: "sig"})
	source.block = make(chan struct{})
	client, _ := newTestClient(source, time.Minute)

	ctx1, cancel1 := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := client.GetSignatureKey(ctx1, "known")
		first <- err
	}()
	waitFor(t, "the request to the source", func() bool { return source.callCount() == 1 })

	second := make(chan error, 1)
	go func() {
		_, err := client.GetSignatureKey(context.Background(), "known")
		second <- err
	}()

	cancel1()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}

	close(source.block)
	if err := <-second; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls := source.callCount(); calls != 1 {
		t.Fatalf("expected 1 request to the source, got %d", calls)
	}
}

type panickingSource struct{}

func (panickingSource) JSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	panic("boom")
}

func TestJWKSClient_SourcePanicIsReturnedAsError(t *testing.T) {
	client := NewClient(panickingSource{}, NewMockCache(), time.Minute)

	for i := 0; i < 2; i++ {
		if _, err := client.GetSignatureKey(context.Background(), "any"); err == nil || errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("expected the panic as an error, got: %v", err)
		}
	}
}

func TestJWKSClient_SourceReturningNil(t *testing.T) {
	client := NewClient(NewDummySource(nil), NewMockCache(), time.Minute)

	if _, err := client.GetSignatureKey(context.Background(), "any"); err == nil || errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected an error, got: %v", err)
	}
}
