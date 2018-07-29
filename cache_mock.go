package jwks

import "time"

type mockCache struct {
	m map[string]pair
}

type pair struct {
	val interface{}
	exp time.Time
}

func (c *mockCache) Set(k string, x interface{}) {
	c.SetWithExpiration(k, x, time.Now())
}

func (c *mockCache) SetWithExpiration(k string, x interface{}, exp time.Time) {
	c.m[k] = pair {
		val: x,
		exp: exp,
	}
}

func (c *mockCache) GetWithExpiration(k string) (interface{}, time.Time, bool) {
	v, exists := c.m[k]
	return v.val, v.exp, exists
}

func NewMockCache() *mockCache {
	return &mockCache{make(map[string]pair)}
}
