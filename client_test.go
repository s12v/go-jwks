package jwks

import (
	"testing"
	"github.com/square/go-jose"
	"time"
)

func TestJWKSClient_GetKey(t *testing.T) {
	keyId := "test-4317493287"
	sourceMock := NewDummySource(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		KeyID: keyId,
	}}})
	cacheMock := NewMockCache()

	client := NewClient(sourceMock, cacheMock, time.Minute)

	jwk, err := client.GetKey(keyId, "sig")
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
			jwk: &mockJwk,
		},
		time.Unix(0, 0),
	)

	client := NewClient(sourceMock, cacheMock, time.Minute)

	key1, err := client.GetKey(keyId, "sig")
	time.Sleep(time.Millisecond * 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key1.Use != "sig" {
		t.Fatalf("unexpected Use: %v", key1.Use)
	}

	key2, _ := cacheMock.Get(keyId)
	if key2.(*cacheEntry).jwk.Use != "enc" {
		t.Fatal("key should be updated in cache")
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
