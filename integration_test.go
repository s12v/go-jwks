package jwks_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/s12v/go-jwks"
)

// identityProviderStub signs tokens and serves the key set to verify them
// with, like an identity provider does. Its keys can be rotated and it can be
// taken down.
type identityProviderStub struct {
	t      *testing.T
	server *httptest.Server

	mu       sync.Mutex
	keys     map[string]*ecdsa.PrivateKey
	extra    []string // other keys in the key set, as JSON
	down     bool
	requests int
}

func newIdentityProviderStub(t *testing.T) *identityProviderStub {
	p := &identityProviderStub{t: t, keys: map[string]*ecdsa.PrivateKey{}}
	p.server = httptest.NewServer(http.HandlerFunc(p.serveKeySet))
	t.Cleanup(p.server.Close)
	return p
}

func (p *identityProviderStub) serveKeySet(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests++
	if p.down {
		http.Error(w, "down for maintenance", http.StatusServiceUnavailable)
		return
	}
	keys := []json.RawMessage{}
	for keyId, key := range p.keys {
		data, err := json.Marshal(jose.JSONWebKey{Key: &key.PublicKey, KeyID: keyId, Algorithm: "ES256", Use: "sig"})
		if err != nil {
			p.t.Error(err)
		}
		keys = append(keys, data)
	}
	for _, key := range p.extra {
		keys = append(keys, json.RawMessage(key))
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": keys})
}

// update changes the provider under its lock.
func (p *identityProviderStub) update(change func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	change()
}

func (p *identityProviderStub) requestCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests
}

// rotate publishes a new key and returns a token signed with it.
func (p *identityProviderStub) rotate(keyId string) string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	p.update(func() { p.keys[keyId] = key })

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: keyId}}, nil)
	if err != nil {
		p.t.Fatal(err)
	}
	signature, err := signer.Sign([]byte(`{"sub":"alice","kid":"` + keyId + `"}`))
	if err != nil {
		p.t.Fatal(err)
	}
	token, err := signature.CompactSerialize()
	if err != nil {
		p.t.Fatal(err)
	}
	return token
}

// verifyToken does what an application does with a token it received.
func verifyToken(client jwks.JWKSClient, token string) error {
	signed, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return err
	}
	jwk, err := client.GetSignatureKey(context.Background(), signed.Signatures[0].Header.KeyID)
	if err != nil {
		return err
	}
	_, err = signed.Verify(jwk)
	return err
}

// eventually waits for the condition to hold: the client learns about a
// change at the identity provider with its next request to it.
func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The life of a client next to an identity provider, over real HTTP and with
// real keys: first use, load, hostile tokens, key rotation, key revocation,
// an outage and the recovery from it.
func TestIntegration(t *testing.T) {
	const (
		refresh          = 100 * time.Millisecond
		minFetchInterval = 20 * time.Millisecond
	)
	provider := newIdentityProviderStub(t)
	provider.update(func() {
		provider.extra = []string{
			// a secret that is published is not a secret
			`{"kty":"oct","kid":"shared-secret","use":"sig","k":"c2VjcmV0"}`,
			// a key this library cannot parse
			`{"kty":"OKP","kid":"ed448","crv":"Ed448","x":"AAAA"}`,
		}
	})
	client := jwks.NewDefaultClient(jwks.NewWebSource(provider.server.URL, nil), refresh, time.Minute,
		jwks.WithMinFetchInterval(minFetchInterval))
	started := time.Now()
	// the key set is not fetched more often than once per interval
	expectFewRequests := func(step string) {
		t.Helper()
		allowed := 2 + int(time.Since(started)/minFetchInterval)
		if requests := provider.requestCount(); requests > allowed {
			t.Fatalf("%s: %d requests to the identity provider, expected at most %d", step, requests, allowed)
		}
	}

	// First use, by many callers at once: one request serves them all.
	firstToken := provider.rotate("key-1")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := verifyToken(client, firstToken); err != nil {
				t.Errorf("a valid token was rejected: %v", err)
			}
		}()
	}
	wg.Wait()
	expectFewRequests("first use")

	// Tokens that name keys nobody has heard of do not reach the provider.
	for i := 0; i < 1000; i++ {
		_, err := client.GetSignatureKey(context.Background(), fmt.Sprintf("unknown-%d", i))
		if !errors.Is(err, jwks.ErrKeyNotFound) {
			t.Fatalf("expected ErrKeyNotFound for an unknown key, got: %v", err)
		}
	}
	expectFewRequests("unknown keys")

	// Keys that must not be used are not served, and do not get in the way
	// of the others.
	for _, keyId := range []string{"shared-secret", "ed448"} {
		if _, err := client.GetSignatureKey(context.Background(), keyId); !errors.Is(err, jwks.ErrKeyNotFound) {
			t.Fatalf("expected ErrKeyNotFound for %s, got: %v", keyId, err)
		}
	}

	// Rotation: a new key is picked up, the old one keeps working.
	secondToken := provider.rotate("key-2")
	eventually(t, "a token signed with the new key is accepted", func() bool {
		return verifyToken(client, secondToken) == nil
	})
	if err := verifyToken(client, firstToken); err != nil {
		t.Fatalf("a token signed with the old key was rejected: %v", err)
	}

	// Revocation: a key that is gone from the key set stops being served.
	provider.update(func() { delete(provider.keys, "key-1") })
	eventually(t, "a token signed with the revoked key is rejected", func() bool {
		return errors.Is(verifyToken(client, firstToken), jwks.ErrKeyNotFound)
	})
	if err := verifyToken(client, secondToken); err != nil {
		t.Fatalf("a token signed with the remaining key was rejected: %v", err)
	}

	// Outage: cached keys keep working well past their refresh time, and
	// a failure to load the key set is not reported as a missing key.
	provider.update(func() { provider.down = true })
	eventually(t, "the outage is noticed", func() bool {
		_, err := client.GetSignatureKey(context.Background(), "unknown")
		return err != nil && !errors.Is(err, jwks.ErrKeyNotFound)
	})
	for outage := time.Now(); time.Since(outage) < 3*refresh; time.Sleep(10 * time.Millisecond) {
		if err := verifyToken(client, secondToken); err != nil {
			t.Fatalf("a valid token was rejected during the outage: %v", err)
		}
	}

	// Recovery: the provider is back, with a new key.
	provider.update(func() { provider.down = false })
	thirdToken := provider.rotate("key-3")
	eventually(t, "a token signed after the outage is accepted", func() bool {
		return verifyToken(client, thirdToken) == nil
	})
	expectFewRequests("the whole test")
}
