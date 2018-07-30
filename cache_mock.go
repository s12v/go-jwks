package jwks

import "time"

type mockCache struct {
	m map[string]interface{}
}

func (c *mockCache) Set(k string, x interface{}) {
	c.SetWithExpiration(k, x, time.Now())
}

func (c *mockCache) SetWithExpiration(k string, x interface{}, exp time.Time) {
	c.m[k] = x
}

func (c *mockCache) Get(k string) (interface{}, bool) {
	v, exists := c.m[k]
	return v, exists
}

func NewMockCache() *mockCache {
	return &mockCache{make(map[string]interface{})}
}
