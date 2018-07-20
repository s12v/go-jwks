package jwks

type dummyCache struct{}

func (c *dummyCache) Set(k string, x interface{}) {}

func (c *dummyCache) Get(k string) (interface{}, bool) {
	return nil, false
}

func DummyCache() Cache {
	return &dummyCache{}
}
