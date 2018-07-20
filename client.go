package jwks

import (
	"fmt"
	"github.com/square/go-jose"
	"time"
)

type JWKSClient struct {
	source JWKSSource
	cache  Cache
}

// Creates a new client with default cache implementation
func NewDefaultClient(source JWKSSource, ttl time.Duration) *JWKSClient {
	return NewClient(source, DefaultCache(ttl))
}

func NewClient(source JWKSSource, cache Cache) *JWKSClient {
	return &JWKSClient{
		source: source,
		cache:  cache,
	}
}

func (c *JWKSClient) GetSignatureKey(kid string) (*jose.JSONWebKey, error) {
	return c.GetKey(kid, "sig")
}

func (c *JWKSClient) GetEncryptionKey(kid string) (*jose.JSONWebKey, error) {
	return c.GetKey(kid, "enc")
}

func (c *JWKSClient) GetKey(kid string, use string) (*jose.JSONWebKey, error) {
	value, found := c.cache.Get(kid)
	if found {
		return value.(*jose.JSONWebKey), nil
	}

	jwk, err := c.fetchJSONWebKey(kid, use)
	if err != nil {
		return nil, err
	}

	c.cache.Set(kid, jwk)
	return jwk, nil
}

func (c *JWKSClient) fetchJSONWebKey(kid string, use string) (*jose.JSONWebKey, error) {
	jsonWebKeySet, err := c.source.JSONWebKeySet()
	if err != nil {
		return nil, err
	}

	keys := jsonWebKeySet.Key(kid)
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWK is not found: %s", kid)
	}

	for _, jwk := range keys {
		return &jwk, nil
	}
	return nil, fmt.Errorf("JWK is not found %s, use: %s", kid, use)
}
