package jwks

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/semaphore"
	"gopkg.in/square/go-jose.v2"
)

const (
	refreshTimeout = 15 * time.Second
)

type JWKSClient interface {
	GetKey(ctx context.Context, keyId string, use string) (*jose.JSONWebKey, error)
	GetEncryptionKey(ctx context.Context, keyId string) (*jose.JSONWebKey, error)
	GetSignatureKey(ctx context.Context, keyId string) (*jose.JSONWebKey, error)
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

func (c *jWKSClient) GetSignatureKey(ctx context.Context, keyId string) (*jose.JSONWebKey, error) {
	return c.GetKey(ctx, keyId, "sig")
}

func (c *jWKSClient) GetEncryptionKey(ctx context.Context, keyId string) (*jose.JSONWebKey, error) {
	return c.GetKey(ctx, keyId, "enc")
}

func (c *jWKSClient) GetKey(ctx context.Context, keyId string, use string) (jwk *jose.JSONWebKey, err error) {
	val, found := c.cache.Get(keyId)
	if found {
		entry := val.(*cacheEntry)
		if time.Now().After(time.Unix(entry.refresh, 0)) && c.sem.TryAcquire(1) {
			go func() {
				defer c.sem.Release(1)
				refreshCtx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
				defer cancel()
				if _, err := c.refreshKey(refreshCtx, keyId, use); err != nil {
					logger.Printf("unable to refresh key: %v", err)
				}
			}()
		}
		return entry.jwk, nil
	} else {
		return c.refreshKey(ctx, keyId, use)
	}
}

func (c *jWKSClient) refreshKey(ctx context.Context, keyId string, use string) (*jose.JSONWebKey, error) {
	jwk, err := c.fetchJSONWebKey(ctx, keyId, use)
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

func (c *jWKSClient) fetchJSONWebKey(ctx context.Context, keyId string, use string) (*jose.JSONWebKey, error) {
	jsonWebKeySet, err := c.source.JSONWebKeySet(ctx)
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
