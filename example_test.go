package jwks_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/s12v/go-jwks"
)

// Verifying the signature of a token with the key that the token names.
func Example() {
	// A stand-in for an identity provider: it signs a token and publishes
	// the key set to check it with.
	token, jwksUri, stop := identityProvider()
	defer stop()

	// Create the client once and share it: it caches the keys.
	jwksClient := jwks.NewDefaultClient(
		jwks.NewWebSource(jwksUri, nil),
		time.Hour,    // Refresh keys every 1 hour
		12*time.Hour, // Expire keys after 12 hours
	)

	// Allow the algorithms you expect, not whatever the token asks for.
	signed, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		fmt.Println(err)
		return
	}

	// The header of the token names the key it is signed with.
	jwk, err := jwksClient.GetSignatureKey(context.Background(), signed.Signatures[0].Header.KeyID)
	if err != nil {
		fmt.Println(err)
		return
	}

	payload, err := signed.Verify(jwk)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("key: %v, alg: %v, use: %v\n", jwk.KeyID, jwk.Algorithm, jwk.Use)
	fmt.Printf("payload: %s\n", payload)
	// Output:
	// key: key-1, alg: ES256, use: sig
	// payload: {"sub":"alice"}
}

// identityProvider returns a signed token, the address of the key set to
// verify it with, and a function that stops serving the key set.
func identityProvider() (token string, jwksUri string, stop func()) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jose.JSONWebKey{Key: privateKey, KeyID: "key-1"},
	}, nil)
	if err != nil {
		panic(err)
	}
	signature, err := signer.Sign([]byte(`{"sub":"alice"}`))
	if err != nil {
		panic(err)
	}
	if token, err = signature.CompactSerialize(); err != nil {
		panic(err)
	}

	keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &privateKey.PublicKey,
		KeyID:     "key-1",
		Algorithm: "ES256",
		Use:       "sig",
	}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(keySet)
	}))
	return token, server.URL, server.Close
}
