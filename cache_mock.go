package jwks

import (
	"sync"
	"time"
)

type mockCache struct {
	mu sync.RWMutex
	m  map[string]interface{}
}

func (c *mockCache) Set(k string, x interface{}) {
	c.SetWithExpiration(k, x, time.Now())
}

func (c *mockCache) SetWithExpiration(k string, x interface{}, exp time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[k] = x
}

func (c *mockCache) Get(k string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, exists := c.m[k]
	return v, exists
}

func NewMockCache() *mockCache {
	return &mockCache{m: make(map[string]interface{})}
}
