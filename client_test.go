package jwks

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	// due for a refresh
	cacheMock.Set(cacheKey(keyId, "sig"), &cacheEntry{
		jwk:       &mockJwk,
		checkedAt: time.Now().Add(-time.Minute - time.Second),
	})
	ctx := context.TODO()

	client := NewClient(sourceMock, cacheMock, time.Minute)

	key1, err := client.GetKey(ctx, keyId, "sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key1.Algorithm != "cached" {
		t.Fatalf("expected the cached key, got alg=%q", key1.Algorithm)
	}

	// the key set is refreshed in the background; wait for it
	waitFor(t, "the refreshed key", func() bool {
		key2, err := client.GetKey(ctx, keyId, "sig")
		return err == nil && key2.Algorithm == "fetched"
	})
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
	cacheMock.Set(cacheKey(keyId, "sig"), &cacheEntry{
		jwk:       &jose.JSONWebKey{KeyID: keyId, Use: "sig", Algorithm: "cached"},
		checkedAt: time.Now().Add(-time.Minute - time.Second),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := NewClient(source, cacheMock, time.Minute)
	if _, err := client.GetKey(ctx, keyId, "sig"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	waitFor(t, "the key to be refreshed despite the cancelled caller context", func() bool {
		jwk, err := client.GetKey(ctx, keyId, "sig")
		return err == nil && jwk.Algorithm == "fetched"
	})
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

func (s *countingSource) setBlock(block chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.block = block
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
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitForWaiters waits until n callers wait for the request in progress.
func waitForWaiters(t *testing.T, client *jWKSClient, n int) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%d callers to wait for the source", n), func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return client.inflight != nil && client.inflight.waiters == n
	})
}

// waitForIdle waits until the source has been asked n times and nothing is
// in progress.
func waitForIdle(t *testing.T, client *jWKSClient, source *countingSource, n int) {
	t.Helper()
	waitFor(t, fmt.Sprintf("request %d to the source to finish", n), func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return source.callCount() == n && client.inflight == nil && !client.refreshing.Load()
	})
}

func sigKey(keyId string) jose.JSONWebKey {
	return jose.JSONWebKey{KeyID: keyId, Use: "sig"}
}

func expectKey(t *testing.T, client JWKSClient, keyId string) {
	t.Helper()
	// fail rather than hang if the client waits for a blocked source
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	jwk, err := client.GetSignatureKey(ctx, keyId)
	if err != nil {
		t.Fatalf("unexpected error for %s: %v", keyId, err)
	}
	if jwk.KeyID != keyId {
		t.Fatalf("expected key %s, got %s", keyId, jwk.KeyID)
	}
}

func expectNotFound(t *testing.T, client JWKSClient, keyId string) {
	t.Helper()
	if _, err := client.GetSignatureKey(context.Background(), keyId); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound for %s, got: %v", keyId, err)
	}
}

// expectSourceError expects an error that is not "key not found".
func expectSourceError(t *testing.T, client JWKSClient, keyId string) {
	t.Helper()
	if _, err := client.GetSignatureKey(context.Background(), keyId); err == nil || errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected a source error for %s, got: %v", keyId, err)
	}
}

func expectCalls(t *testing.T, source *countingSource, n int) {
	t.Helper()
	if calls := source.callCount(); calls != n {
		t.Fatalf("expected %d requests to the source, got %d", n, calls)
	}
}

func TestNewClient_Defaults(t *testing.T) {
	client := NewClient(newCountingSource(), NewMockCache(), time.Minute, nil).(*jWKSClient)
	if client.minFetchInterval != DefaultMinFetchInterval || DefaultMinFetchInterval != 10*time.Second {
		t.Fatalf("unexpected min fetch interval: %v", client.minFetchInterval)
	}
	if client.fetchTimeout != 15*time.Second {
		t.Fatalf("unexpected fetch timeout: %v", client.fetchTimeout)
	}
}

// Concurrent cache misses must share a single request to the source.
func TestJWKSClient_ConcurrentMissesShareOneFetch(t *testing.T) {
	source := newCountingSource(sigKey("known"))
	source.block = make(chan struct{})
	// without the interval, a caller that came late would fetch again
	client, _ := newTestClient(source, time.Minute, WithMinFetchInterval(0))

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

	waitForWaiters(t, client, n)
	close(source.block)

	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	expectCalls(t, source, 1)
}

// Unknown key ids must not make the client fetch the key set on every request.
func TestJWKSClient_UnknownKeysDoNotRefetch(t *testing.T) {
	source := newCountingSource(sigKey("known"))
	client, clock := newTestClient(source, time.Hour)

	for i := 0; i < 100; i++ {
		expectNotFound(t, client, fmt.Sprintf("random-%d", i))
	}
	expectCalls(t, source, 1)

	// a key that is in the key set is served from it as well
	expectKey(t, client, "known")
	expectCalls(t, source, 1)

	// nothing is remembered per unknown key id
	if n := len(client.cache.(*mockCache).m); n != 1 {
		t.Fatalf("expected only the known key in the cache, got %d entries", n)
	}

	// once the interval has passed, the key set is fetched again
	clock.Advance(DefaultMinFetchInterval)
	for i := 0; i < 100; i++ {
		expectNotFound(t, client, fmt.Sprintf("random-%d", i))
	}
	expectCalls(t, source, 2)
}

// A key added to the key set is found once the minimum interval has passed.
func TestJWKSClient_NewKeyIsFoundAfterMinFetchInterval(t *testing.T) {
	source := newCountingSource(sigKey("old"))
	client, clock := newTestClient(source, time.Hour, WithMinFetchInterval(10*time.Second))

	expectNotFound(t, client, "new")

	source.set(nil, sigKey("old"), sigKey("new"))
	clock.Advance(9 * time.Second)
	expectNotFound(t, client, "new")

	clock.Advance(time.Second)
	expectKey(t, client, "new")
}

func TestJWKSClient_MinFetchIntervalDisabled(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		source := newCountingSource(sigKey("known"))
		client, _ := newTestClient(source, time.Hour, WithMinFetchInterval(interval))

		for i := 0; i < 3; i++ {
			expectNotFound(t, client, "missing")
		}
		expectCalls(t, source, 3)

		// no pause after a failure either
		source.set(errors.New("boom"))
		for i := 0; i < 3; i++ {
			expectSourceError(t, client, "missing")
		}
		expectCalls(t, source, 6)
	}
}

// A failing source must not be asked again on every request, and its failure
// must not be mistaken for a missing key.
func TestJWKSClient_FailingSourceIsNotHammered(t *testing.T) {
	source := newCountingSource()
	source.set(errors.New("boom"))
	client, clock := newTestClient(source, time.Hour)

	for i := 0; i < 100; i++ {
		expectSourceError(t, client, fmt.Sprintf("random-%d", i))
	}
	expectCalls(t, source, 1)

	clock.Advance(maxFailureBackoff)
	for i := 0; i < 100; i++ {
		expectSourceError(t, client, fmt.Sprintf("random-%d", i))
	}
	expectCalls(t, source, 2)

	// the client recovers as soon as the pause is over
	source.set(nil, sigKey("known"))
	expectSourceError(t, client, "known")
	clock.Advance(maxFailureBackoff)
	expectKey(t, client, "known")
	expectCalls(t, source, 3)
}

// An answer without keys is a malfunction of the source, not a revocation of
// every key.
func TestJWKSClient_EmptyKeySetIsAnError(t *testing.T) {
	source := newCountingSource(sigKey("known"))
	client, clock := newTestClient(source, time.Minute)
	expectKey(t, client, "known")

	source.set(nil)
	clock.Advance(time.Hour)
	expectKey(t, client, "known")
	expectSourceError(t, client, "other")

	source.set(nil, sigKey("known"))
	clock.Advance(maxFailureBackoff)
	expectKey(t, client, "known")
	expectNotFound(t, client, "other")
}

func TestJWKSClient_SourceReturningNil(t *testing.T) {
	client := NewClient(NewDummySource(nil), NewMockCache(), time.Minute)
	expectSourceError(t, client, "any")
}

// A key that disappears from the key set stops being served after the next
// refresh, not after the cache ttl.
func TestJWKSClient_RevokedKeyIsDropped(t *testing.T) {
	source := newCountingSource(sigKey("revoked"), sigKey("other"))
	client, clock := newTestClient(source, time.Minute)
	expectKey(t, client, "revoked")

	source.set(nil, sigKey("other"))
	clock.Advance(time.Minute + time.Second)

	// the key has just become due: it is served while the key set is
	// refreshed in the background
	expectKey(t, client, "revoked")
	waitForIdle(t, client, source, 2)
	expectNotFound(t, client, "revoked")

	// a dropped key does not cause a fetch on every request either
	for i := 0; i < 10; i++ {
		expectNotFound(t, client, "revoked")
	}
	expectCalls(t, source, 2)

	// if the key comes back, it is served again
	source.set(nil, sigKey("revoked"), sigKey("other"))
	clock.Advance(DefaultMinFetchInterval)
	expectKey(t, client, "revoked")
}

// A revoked key that nobody asked for in a long time must not be served to
// the requests that arrive before the refresh is done.
func TestJWKSClient_IdleRevokedKeyIsNotServed(t *testing.T) {
	source := newCountingSource(sigKey("revoked"), sigKey("other"))
	client, clock := newTestClient(source, time.Hour)
	expectKey(t, client, "revoked")

	source.set(nil, sigKey("other"))
	clock.Advance(11 * time.Hour)
	block := make(chan struct{})
	source.setBlock(block)

	const n = 50
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := client.GetSignatureKey(context.Background(), "revoked")
			errs <- err
		}()
	}
	waitForWaiters(t, client, n)
	close(block)

	for i := 0; i < n; i++ {
		if err := <-errs; !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("expected ErrKeyNotFound, got: %v", err)
		}
	}
	expectCalls(t, source, 2)
}

// The time a key may be served is counted from when its key set was fetched,
// not from when the key was last read from it.
func TestJWKSClient_RefreshIsCountedFromTheFetch(t *testing.T) {
	source := newCountingSource(sigKey("revoked"), sigKey("other"))
	client, clock := newTestClient(source, time.Minute)
	expectKey(t, client, "revoked")

	// the key set is fetched again shortly before the key is due...
	clock.Advance(55 * time.Second)
	expectNotFound(t, client, "random")
	expectCalls(t, source, 2)

	// ...and the key is revoked right after that
	source.set(nil, sigKey("other"))
	clock.Advance(6 * time.Second)
	expectKey(t, client, "revoked")
	expectCalls(t, source, 2)

	// one refresh interval and the background window after that fetch
	clock.Advance(time.Minute + backgroundRefreshWindow)
	expectNotFound(t, client, "revoked")
	expectCalls(t, source, 3)
}

// A key set fetched for any reason applies to cached keys right away.
func TestJWKSClient_NewerKeySetAppliesToCachedKeys(t *testing.T) {
	source := newCountingSource(sigKey("revoked"), sigKey("kept"))
	client, clock := newTestClient(source, time.Hour)
	expectKey(t, client, "revoked")
	expectKey(t, client, "kept")

	source.set(nil, sigKey("kept"))
	clock.Advance(DefaultMinFetchInterval)
	expectNotFound(t, client, "random")
	expectCalls(t, source, 2)

	// not due for a refresh for another hour
	expectNotFound(t, client, "revoked")
	expectKey(t, client, "kept")
	expectCalls(t, source, 2)
}

// A key whose "use" changes is not served for the old use.
func TestJWKSClient_KeyChangingUseIsDropped(t *testing.T) {
	source := newCountingSource(sigKey("key"))
	client, clock := newTestClient(source, time.Minute)
	expectKey(t, client, "key")

	source.set(nil, jose.JSONWebKey{KeyID: "key", Use: "enc"})
	clock.Advance(time.Hour)
	expectNotFound(t, client, "key")
	if _, err := client.GetEncryptionKey(context.Background(), "key"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// If the source is unavailable, cached keys keep being served, and it is not
// asked again on every request.
func TestJWKSClient_CachedKeySurvivesSourceError(t *testing.T) {
	source := newCountingSource(sigKey("known"))
	client, clock := newTestClient(source, time.Minute)
	expectKey(t, client, "known")

	source.set(errors.New("boom"))
	clock.Advance(2 * time.Hour)

	// the first request finds out that the source is down...
	expectKey(t, client, "known")
	expectCalls(t, source, 2)
	// ...and the following ones do not ask it again
	for i := 0; i < 10; i++ {
		expectKey(t, client, "known")
	}
	expectCalls(t, source, 2)

	// it is retried after a pause, in the background: nobody waits for a
	// source that is known to be down
	clock.Advance(maxFailureBackoff)
	block := make(chan struct{})
	source.setBlock(block)
	expectKey(t, client, "known")
	expectKey(t, client, "known")
	close(block)
	source.setBlock(nil)
	waitForIdle(t, client, source, 3)

	source.set(nil, sigKey("known"))
	clock.Advance(maxFailureBackoff)
	expectKey(t, client, "known")
	waitForIdle(t, client, source, 4)
	if client.sourceFailing() {
		t.Fatal("the source should not be considered failing any more")
	}
	expectKey(t, client, "known")
	expectCalls(t, source, 4)
}

// Revocation works with the default cache as well.
func TestJWKSClient_RevokedKeyIsDroppedFromDefaultCache(t *testing.T) {
	source := newCountingSource(sigKey("revoked"), sigKey("other"))
	client := NewDefaultClient(source, time.Minute, time.Hour).(*jWKSClient)
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	client.now = clock.Now
	expectKey(t, client, "revoked")

	source.set(nil, sigKey("other"))
	clock.Advance(10 * time.Minute)
	expectNotFound(t, client, "revoked")
	expectNotFound(t, client, "revoked")

	source.set(nil, sigKey("revoked"), sigKey("other"))
	clock.Advance(DefaultMinFetchInterval)
	expectKey(t, client, "revoked")
}

// A caller that gives up must not break the request for the others waiting
// for it.
func TestJWKSClient_CancelledCallerDoesNotCancelSharedFetch(t *testing.T) {
	source := newCountingSource(sigKey("known"))
	source.block = make(chan struct{})
	client, _ := newTestClient(source, time.Minute, WithMinFetchInterval(0))

	ctx1, cancel1 := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := client.GetSignatureKey(ctx1, "known")
		first <- err
	}()
	waitForWaiters(t, client, 1)

	second := make(chan error, 1)
	go func() {
		_, err := client.GetSignatureKey(context.Background(), "known")
		second <- err
	}()
	waitForWaiters(t, client, 2)

	cancel1()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}

	close(source.block)
	if err := <-second; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectCalls(t, source, 1)
}

func TestJWKSClient_CancelledContextDoesNotFetch(t *testing.T) {
	source := newCountingSource(sigKey("known"))
	client, _ := newTestClient(source, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.GetSignatureKey(ctx, "known"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.inflight != nil {
		t.Fatal("a request to the source should not be started")
	}
}

// hangingSource ignores its context and does not answer its first request
// until released.
type hangingSource struct {
	calls   atomic.Int32
	release chan struct{}
	jwks    *jose.JSONWebKeySet
}

func (s *hangingSource) JSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	if s.calls.Add(1) == 1 {
		<-s.release
	}
	return s.jwks, nil
}

// A source that hangs, ignoring its context, must not block the client for
// good.
func TestJWKSClient_HangingSourceIsGivenUpOn(t *testing.T) {
	source := &hangingSource{
		release: make(chan struct{}),
		jwks:    &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{sigKey("known")}},
	}
	defer close(source.release)
	client, clock := newTestClient(source, time.Minute)
	client.fetchTimeout = 20 * time.Millisecond

	// the caller itself is ready to wait much longer than that
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.GetSignatureKey(ctx, "known")
	if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		t.Fatalf("expected the request to the source to time out, got: %v", err)
	}

	clock.Advance(maxFailureBackoff)
	expectKey(t, client, "known")
	if calls := source.calls.Load(); calls != 2 {
		t.Fatalf("expected 2 requests to the source, got %d", calls)
	}
}

type misbehavingSource struct {
	behave func()
}

func (s misbehavingSource) JSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	s.behave()
	return nil, nil
}

func TestJWKSClient_SourcePanicIsReturnedAsError(t *testing.T) {
	for name, behave := range map[string]func(){
		"panic":  func() { panic("boom") },
		"goexit": runtime.Goexit,
	} {
		client := NewClient(misbehavingSource{behave}, NewMockCache(), time.Minute, WithMinFetchInterval(0))
		for i := 0; i < 2; i++ {
			if _, err := client.GetSignatureKey(context.Background(), "any"); err == nil || errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("%s: expected an error, got: %v", name, err)
			}
		}
	}
}

// The source may go on using the key set it returned.
func TestJWKSClient_KeySetIsCopied(t *testing.T) {
	keySet := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{sigKey("known")}}
	client, _ := newTestClient(NewDummySource(keySet), time.Minute)
	expectNotFound(t, client, "changed")

	keySet.Keys[0].KeyID = "changed"
	expectNotFound(t, client, "changed")
	expectKey(t, client, "known")
}

// A key id comes from an unverified token and must not be able to forge log
// lines or to flood the log through the error message.
func TestJWKSClient_KeyIdInErrorIsQuoted(t *testing.T) {
	client, _ := newTestClient(newCountingSource(sigKey("known")), time.Minute)
	ctx := context.Background()

	_, err := client.GetSignatureKey(ctx, "missing")
	if !errors.Is(err, ErrKeyNotFound) || err.Error() != `JWK is not found: "missing"` {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = client.GetSignatureKey(ctx, "x\n2026/11/15 00:00:00 admin logged in\r\x1b[2J")
	if !errors.Is(err, ErrKeyNotFound) || strings.ContainsAny(err.Error(), "\n\r\x1b") {
		t.Fatalf("unexpected error: %q", err)
	}

	_, err = client.GetSignatureKey(ctx, strings.Repeat("\n", 1<<20))
	if !errors.Is(err, ErrKeyNotFound) || len(err.Error()) > 300 || strings.Contains(err.Error(), "\n") {
		t.Fatalf("unexpected error of %d bytes", len(err.Error()))
	}

	// the same when only the use does not match
	_, err = client.GetEncryptionKey(ctx, "known")
	if !errors.Is(err, ErrKeyNotFound) || err.Error() != `JWK is not found: "known", use: "enc"` {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestQuoteUntrusted(t *testing.T) {
	long := strings.Repeat("a", maxUntrustedLen)
	for value, expected := range map[string]string{
		"":         `""`,
		"kid":      `"kid"`,
		`a"b`:      `"a\"b"`,
		"a\nb\rc":  `"a\nb\rc"`,
		"\x1b[2J":  `"\x1b[2J"`,
		"\xff":     `"\xff"`,
		"a\u2028b": `"a\u2028b"`, // line separator
		"a\u202eb": `"a\u202eb"`, // right-to-left override
		long:       `"` + long + `"`,
		long + "b": `"` + long + `"...`,
		// a character is not cut in half
		long[1:] + "\u00e9":       `"` + long[1:] + `"...`,
		long[2:] + "\u00e9" + "b": `"` + long[2:] + "\u00e9" + `"...`,
		// and invalid UTF-8 does not make the cut run away
		strings.Repeat("\x80", maxUntrustedLen+1): `"` + strings.Repeat(`\x80`, maxUntrustedLen-3) + `"...`,
	} {
		if quoted := quoteUntrusted(value); quoted != expected {
			t.Errorf("quoteUntrusted(%q) = %s, expected %s", value, quoted, expected)
		}
	}
}

// certifiedKey is a key with everything a key can carry.
func certifiedKey() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:                         ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)),
		KeyID:                       "key",
		Algorithm:                   "EdDSA",
		Use:                         "sig",
		Certificates:                []*x509.Certificate{{Raw: []byte("certificate")}},
		CertificateThumbprintSHA1:   []byte("sha1"),
		CertificateThumbprintSHA256: []byte("sha256"),
	}
}

func expectCertifiedKey(t *testing.T, jwk *jose.JSONWebKey) {
	t.Helper()
	expected := certifiedKey()
	if jwk.KeyID != expected.KeyID || jwk.Algorithm != expected.Algorithm || jwk.Use != expected.Use {
		t.Fatalf("unexpected key: %+v", jwk)
	}
	if key, ok := jwk.Key.(ed25519.PublicKey); !ok || !key.Equal(expected.Key.(ed25519.PublicKey)) {
		t.Fatalf("unexpected key material: %v", jwk.Key)
	}
	if len(jwk.Certificates) != 1 || jwk.Certificates[0] == nil || string(jwk.Certificates[0].Raw) != "certificate" {
		t.Fatalf("unexpected certificates: %+v", jwk.Certificates)
	}
	if string(jwk.CertificateThumbprintSHA1) != "sha1" || string(jwk.CertificateThumbprintSHA256) != "sha256" {
		t.Fatalf("unexpected thumbprints: %q, %q", jwk.CertificateThumbprintSHA1, jwk.CertificateThumbprintSHA256)
	}
}

// Whatever a caller does to the key it got must not reach the other callers,
// however the key was obtained.
func TestJWKSClient_ReturnedKeyIsACopy(t *testing.T) {
	source := newCountingSource(certifiedKey())
	client, clock := newTestClient(source, time.Minute)
	ctx := context.Background()

	var previous *jose.JSONWebKey
	// get returns the key, expects it to be intact, and spoils it
	get := func(step string) {
		t.Helper()
		jwk, err := client.GetSignatureKey(ctx, "key")
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", step, err)
		}
		if jwk == previous {
			t.Fatalf("%s: expected another copy of the key", step)
		}
		previous = jwk
		expectCertifiedKey(t, jwk)

		jwk.Key.(ed25519.PublicKey)[0] ^= 0xff
		jwk.Key = nil
		jwk.KeyID = "other"
		jwk.Algorithm = "none"
		jwk.Use = "enc"
		jwk.Certificates[0] = nil
		jwk.CertificateThumbprintSHA1[0] = 'x'
		jwk.CertificateThumbprintSHA256[0] = 'x'
	}

	get("fetched from the source")
	get("served from the cache")

	clock.Advance(time.Minute + time.Second)
	get("served while the key set is refreshed in the background")
	waitForIdle(t, client, source, 2)
	get("read again from the newer key set")

	clock.Advance(time.Hour)
	get("fetched again after a long time")
	expectCalls(t, source, 3)

	source.set(errors.New("boom"))
	clock.Advance(time.Hour)
	get("served from the cache when the source fails")
	expectCalls(t, source, 4)
	get("served from the cache while the source is known to fail")
}

// A key that is a slice is copied as well.
func TestJWKSClient_ReturnedKeyMaterialIsACopy(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// the source keeps the slice it is given, so compare with a copy
	original := slices.Clone(privateKey)
	for name, material := range map[string]interface{}{
		"ed25519 private": privateKey,
		"symmetric":       []byte("secret"),
	} {
		client, _ := newTestClient(newCountingSource(jose.JSONWebKey{KeyID: "key", Key: material}), time.Minute)
		for i := 0; i < 2; i++ {
			jwk, err := client.GetSignatureKey(context.Background(), "key")
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", name, err)
			}
			switch key := jwk.Key.(type) {
			case ed25519.PrivateKey:
				if !key.Equal(original) {
					t.Fatalf("%s: the key was changed", name)
				}
				key[0] ^= 0xff
			case []byte:
				if string(key) != "secret" {
					t.Fatalf("%s: the key was changed", name)
				}
				key[0] ^= 0xff
			default:
				t.Fatalf("%s: unexpected key %T", name, jwk.Key)
			}
		}
	}
}

// Callers may change their keys at the same time.
func TestJWKSClient_ReturnedKeysAreIndependent(t *testing.T) {
	client, _ := newTestClient(newCountingSource(certifiedKey()), time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				jwk, err := client.GetSignatureKey(context.Background(), "key")
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if jwk.Algorithm != "EdDSA" || string(jwk.CertificateThumbprintSHA1) != "sha1" {
					t.Errorf("unexpected key: %+v", jwk)
					return
				}
				jwk.Algorithm = "none"
				jwk.CertificateThumbprintSHA1[0] = 'x'
				jwk.Certificates[0] = nil
			}
		}()
	}
	wg.Wait()
}
