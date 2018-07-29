package jwks

import (
	"fmt"
	"github.com/square/go-jose"
	"golang.org/x/sync/semaphore"
	"time"
)

type JWKSClient interface {
	GetKey(keyId string, use string) (*jose.JSONWebKey, error)
	GetEncryptionKey(keyId string) (*jose.JSONWebKey, error)
	GetSignatureKey(keyId string) (*jose.JSONWebKey, error)
}

type jWKSClient struct {
	source   JWKSSource
	cache    Cache
	prefetch time.Duration
	sem      *semaphore.Weighted
}

// Creates a new client with default cache implementation
func NewDefaultClient(source JWKSSource, ttl time.Duration, prefetch time.Duration) JWKSClient {
	if prefetch >= ttl {
		panic(fmt.Sprintf("invalid prefetch: %v greater or eaquals to ttl: %v", prefetch, ttl))
	}
	return NewClient(source, DefaultCache(ttl), prefetch)
}

func NewClient(source JWKSSource, cache Cache, prefetch time.Duration) JWKSClient {
	return &jWKSClient{
		source:   source,
		cache:    cache,
		prefetch: prefetch,
		sem:      semaphore.NewWeighted(1),
	}
}

func (c *jWKSClient) GetSignatureKey(keyId string) (*jose.JSONWebKey, error) {
	return c.GetKey(keyId, "sig")
}

func (c *jWKSClient) GetEncryptionKey(keyId string) (*jose.JSONWebKey, error) {
	return c.GetKey(keyId, "enc")
}

func (c *jWKSClient) GetKey(keyId string, use string) (*jose.JSONWebKey, error) {
	jwk, expiration, found := c.cache.GetWithExpiration(keyId)
	if ! found {
		var err error
		if jwk, err = c.refreshKey(keyId, use); err != nil {
			return nil, err
		}
	}

	if time.Until(expiration) <= c.prefetch {
		if c.sem.TryAcquire(1) {
			go func () {
				defer c.sem.Release(1)
				c.refreshKey(keyId, use)
			}()
		}
	}

	return jwk.(*jose.JSONWebKey), nil
}

func (c *jWKSClient) refreshKey(keyId string, use string) (*jose.JSONWebKey, error) {
	jwk, err := c.fetchJSONWebKey(keyId, use)
	if err != nil {
		return nil, err
	}

	c.cache.Set(keyId, jwk)
	return jwk, nil
}

func (c *jWKSClient) fetchJSONWebKey(keyId string, use string) (*jose.JSONWebKey, error) {
	jsonWebKeySet, err := c.source.JSONWebKeySet()
	if err != nil {
		return nil, err
	}

	keys := jsonWebKeySet.Key(keyId)
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWK is not found: %s", keyId)
	}

	for _, jwk := range keys {
		return &jwk, nil
	}
	return nil, fmt.Errorf("JWK is not found %s, use: %s", keyId, use)
}
