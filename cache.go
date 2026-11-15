package jwks

import (
	"fmt"
	"sync"
	"time"
)

type Cache interface {
	// Get an item from the cache
	// Returns the item or nil, and a bool indicating whether the key was found
	Get(k string) (interface{}, bool)
	// Add an item to the cache, replacing any existing item.
	Set(k string, x interface{})
}

// defaultCache keeps items in memory for ttl after they were set.
type defaultCache struct {
	ttl time.Duration // zero or less: items never expire
	now func() time.Time

	mu    sync.RWMutex
	items map[string]cacheItem
	// when to remove the expired items next
	sweepAt time.Time
}

type cacheItem struct {
	value   interface{}
	expires time.Time
}

func (c *defaultCache) Set(k string, x interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ttl <= 0 {
		c.items[k] = cacheItem{value: x}
		return
	}

	// Nothing runs in the background to remove the items that have
	// expired, so it is done here once in a while. Until then they take
	// up memory but are not returned.
	now := c.now()
	if !now.Before(c.sweepAt) {
		for key, item := range c.items {
			if now.After(item.expires) {
				delete(c.items, key)
			}
		}
		c.sweepAt = now.Add(c.ttl)
	}
	c.items[k] = cacheItem{value: x, expires: now.Add(c.ttl)}
}

func (c *defaultCache) Get(k string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[k]
	if !found || (c.ttl > 0 && c.now().After(item.expires)) {
		return nil, false
	}
	return item.value, true
}

// DefaultCache returns an in-memory cache. An item is kept for ttl after it
// was set; with a ttl of 0 or -1 items are kept forever.
func DefaultCache(ttl time.Duration) Cache {
	if ttl < -1 {
		panic(fmt.Sprintf("invalid ttl: %d", ttl))
	}
	return &defaultCache{
		ttl:   ttl,
		now:   time.Now,
		items: make(map[string]cacheItem),
	}
}
