package jwks

import (
	"context"
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
