package jwks

import (
	"fmt"
	"github.com/square/go-jose"
	"golang.org/x/sync/semaphore"
	"log"
	"time"
)

type JWKSClient interface {
	GetKey(keyId string, use string) (*jose.JSONWebKey, error)
	GetEncryptionKey(keyId string) (*jose.JSONWebKey, error)
	GetSignatureKey(keyId string) (*jose.JSONWebKey, error)
}

type jWKSClient struct {
	source  JWKSSource
	cache   Cache
	refresh time.Duration
	sem     *semaphore.Weighted
}

type cacheEntry struct {
	jwk     *jose.JSONWebKey
	refresh int64
}

// Creates a new client with default cache implementation
func NewDefaultClient(source JWKSSource, refresh time.Duration, ttl time.Duration) JWKSClient {
	if refresh >= ttl {
		panic(fmt.Sprintf("invalid refresh: %v greater or eaquals to ttl: %v", refresh, ttl))
	}
	if refresh < 0 {
		panic(fmt.Sprintf("invalid refresh: %v", refresh))
	}
	return NewClient(source, DefaultCache(ttl), refresh)
}

func NewClient(source JWKSSource, cache Cache, refresh time.Duration) JWKSClient {
	return &jWKSClient{
		source:  source,
		cache:   cache,
		refresh: refresh,
		sem:     semaphore.NewWeighted(1),
	}
}

func (c *jWKSClient) GetSignatureKey(keyId string) (*jose.JSONWebKey, error) {
	return c.GetKey(keyId, "sig")
}

func (c *jWKSClient) GetEncryptionKey(keyId string) (*jose.JSONWebKey, error) {
	return c.GetKey(keyId, "enc")
}

func (c *jWKSClient) GetKey(keyId string, use string) (jwk *jose.JSONWebKey, err error) {
	val, found := c.cache.Get(keyId)
	if found {
		entry := val.(*cacheEntry)
		if time.Now().After(time.Unix(entry.refresh, 0)) && c.sem.TryAcquire(1) {
			go func() {
				defer c.sem.Release(1)
				if _, err := c.refreshKey(keyId, use); err != nil {
					log.Printf("unable to refresh key: %v", err)
				}
			}()
		}
		return entry.jwk, nil
	} else {
		return c.refreshKey(keyId, use)
	}
}

func (c *jWKSClient) refreshKey(keyId string, use string) (*jose.JSONWebKey, error) {
	jwk, err := c.fetchJSONWebKey(keyId, use)
	if err != nil {
		return nil, err
	}

	c.save(keyId, jwk)
	return jwk, nil
}

func (c *jWKSClient) save(keyId string, jwk *jose.JSONWebKey) {
	c.cache.Set(keyId, &cacheEntry{
		jwk:     jwk,
		refresh: time.Now().Add(c.refresh).Unix(),
	})
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
