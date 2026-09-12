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
		KeyID: keyId,
		Use:   "sig",
	}
	sourceMock := NewDummySource(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		KeyID: keyId,
		Use:   "enc",
	}}})
	cacheMock := NewMockCache()
	cacheMock.SetWithExpiration(
		keyId,
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
	if key1.Use != "sig" {
		t.Fatalf("unexpected Use: %v", key1.Use)
	}

	// the key is refreshed in the background; wait for it
	deadline := time.Now().Add(time.Second)
	for {
		key2, _ := cacheMock.Get(keyId)
		if key2.(*cacheEntry).jwk.Use == "enc" {
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
		KeyID: keyId,
		Use:   "enc",
	}}}}
	cacheMock := NewMockCache()
	cacheMock.Set(keyId, &cacheEntry{refresh: 0, jwk: &jose.JSONWebKey{KeyID: keyId, Use: "sig"}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := NewClient(source, cacheMock, time.Minute)
	if _, err := client.GetKey(ctx, keyId, "sig"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		entry, _ := cacheMock.Get(keyId)
		if entry.(*cacheEntry).jwk.Use == "enc" {
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

	// no key with the requested use: fall back to the first one with the id
	client = NewClient(sourceMock, NewMockCache(), time.Minute)
	jwk, err = client.GetKey(ctx, keyId, "other")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jwk.Use != "enc" {
		t.Fatalf("expected the first key, got use=%q", jwk.Use)
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
