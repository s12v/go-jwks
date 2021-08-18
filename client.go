package jwks

import (
	"fmt"
	"time"

	"github.com/square/go-jose"
	"golang.org/x/sync/semaphore"
)

// Client interface contains operations for retrieving web keys.
type Client interface {
	// GetKey retrieves a key for use specified by keyID.
	GetKey(keyID string, use string) (*jose.JSONWebKey, error)
	// GetEncryptionKey retrieves an encryption key specified by keyID.
	GetEncryptionKey(keyID string) (*jose.JSONWebKey, error)
	// GetSignatureKey retrieves a signature verification key specified by keyID.
	GetSignatureKey(keyID string) (*jose.JSONWebKey, error)
}

type client struct {
	source  Source
	cache   Cache
	refresh time.Duration
	sem     *semaphore.Weighted
}

type cacheEntry struct {
	jwk     *jose.JSONWebKey
	refresh int64
}

// NewDefaultClient creates a new client with default cache implementation.
func NewDefaultClient(source Source, refresh time.Duration, ttl time.Duration) Client {
	if refresh >= ttl {
		panic(fmt.Sprintf("invalid refresh: %v greater or eaquals to ttl: %v", refresh, ttl))
	}
	if refresh < 0 {
		panic(fmt.Sprintf("invalid refresh: %v", refresh))
	}
	return NewClient(source, DefaultCache(ttl), refresh)
}

// NewClient creates a new Client.
func NewClient(source Source, cache Cache, refresh time.Duration) Client {
	return &client{
		source:  source,
		cache:   cache,
		refresh: refresh,
		sem:     semaphore.NewWeighted(1),
	}
}

func (c *client) GetSignatureKey(keyID string) (*jose.JSONWebKey, error) {
	return c.GetKey(keyID, "sig")
}

func (c *client) GetEncryptionKey(keyID string) (*jose.JSONWebKey, error) {
	return c.GetKey(keyID, "enc")
}

func (c *client) GetKey(keyID string, use string) (jwk *jose.JSONWebKey, err error) {
	val, found := c.cache.Get(keyID)
	if found {
		entry := val.(*cacheEntry)
		if time.Now().After(time.Unix(entry.refresh, 0)) && c.sem.TryAcquire(1) {
			go func() {
				defer c.sem.Release(1)
				if _, err := c.refreshKey(keyID, use); err != nil {
					logger.Printf("unable to refresh key: %v", err)
				}
			}()
		}
		return entry.jwk, nil
	} else {
		return c.refreshKey(keyID, use)
	}
}

func (c *client) refreshKey(keyID string, use string) (*jose.JSONWebKey, error) {
	jwk, err := c.fetchJSONWebKey(keyID, use)
	if err != nil {
		return nil, err
	}

	c.save(keyID, jwk)
	return jwk, nil
}

func (c *client) save(keyID string, jwk *jose.JSONWebKey) {
	c.cache.Set(keyID, &cacheEntry{
		jwk:     jwk,
		refresh: time.Now().Add(c.refresh).Unix(),
	})
}

func (c *client) fetchJSONWebKey(keyID string, use string) (*jose.JSONWebKey, error) {
	jsonWebKeySet, err := c.source.JSONWebKeySet()
	if err != nil {
		return nil, err
	}

	keys := jsonWebKeySet.Key(keyID)
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWK is not found: %s", keyID)
	}

	for _, jwk := range keys {
		return &jwk, nil
	}
	return nil, fmt.Errorf("JWK is not found %s, use: %s", keyID, use)
}
