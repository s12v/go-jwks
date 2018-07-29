package jwks

import (
	"github.com/patrickmn/go-cache"
	"time"
	"fmt"
)

type Cache interface {
	// Get an item from the cache and itsexpiration time.
	// Returns the item or nil, and a bool indicating whether the key was found
	GetWithExpiration(k string) (interface{}, time.Time, bool)
	// Add an item to the cache, replacing any existing item.
	Set(k string, x interface{})
}

type defaultCache struct {
	cache *cache.Cache
}

func (c *defaultCache) Set(k string, x interface{}) {
	c.cache.Set(k, x, cache.DefaultExpiration)
}

func (c *defaultCache) GetWithExpiration(k string) (interface{}, time.Time, bool) {
	return c.cache.GetWithExpiration(k)
}

func DefaultCache(ttl time.Duration) Cache {
	if ttl < -1 {
		panic(fmt.Sprintf("invalid ttl: %d", ttl))
	}
	return &defaultCache{
		cache.New(ttl, -1),
	}
}
