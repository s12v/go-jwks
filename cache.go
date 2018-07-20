package jwks

import (
	"github.com/patrickmn/go-cache"
	"time"
)

type Cache interface {
	// Get an item from the cache. Returns the item or nil, and a bool indicating whether the key was found
	Get(k string) (interface{}, bool)
	// Add an item to the cache, replacing any existing item.
	Set(k string, x interface{})
}

type defaultCache struct {
	cache *cache.Cache
}

func (c *defaultCache) Set(k string, x interface{}) {
	c.cache.Set(k, x, cache.DefaultExpiration)
}

func (c *defaultCache) Get(k string) (interface{}, bool) {
	return c.cache.Get(k) // TODO GetWithExpiration and prefetch
}

func DefaultCache(ttl time.Duration) Cache {
	return &defaultCache{
		cache.New(ttl, cache.NoExpiration),
	}
}
