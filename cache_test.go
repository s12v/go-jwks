package jwks

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// newTestCache returns a default cache that reads the time from the
// returned clock.
func newTestCache(ttl time.Duration) (*defaultCache, *fakeClock) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	c := DefaultCache(ttl).(*defaultCache)
	c.now = clock.Now
	return c, clock
}

func (c *defaultCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func expectCached(t *testing.T, c Cache, key string, expected interface{}) {
	t.Helper()
	val, found := c.Get(key)
	if !found {
		t.Fatalf("%s should be found", key)
	}
	if val != expected {
		t.Fatalf("%s should be %v, got %v instead", key, expected, val)
	}
}

func expectNotCached(t *testing.T, c Cache, key string) {
	t.Helper()
	if val, found := c.Get(key); found || val != nil {
		t.Fatalf("%s should not be found, got %v", key, val)
	}
}

func TestDefaultCache_Get(t *testing.T) {
	c := DefaultCache(time.Minute)
	expectNotCached(t, c, "key")

	c.Set("key", "val")
	expectCached(t, c, "key", "val")

	c.Set("key", "other")
	expectCached(t, c, "key", "other")
	expectNotCached(t, c, "another key")
}

func TestDefaultCache_Expiration(t *testing.T) {
	c, clock := newTestCache(time.Minute)
	c.Set("key", "val")

	// an item lives for ttl after it was set
	clock.Advance(time.Minute)
	expectCached(t, c, "key", "val")
	clock.Advance(time.Nanosecond)
	expectNotCached(t, c, "key")

	// setting it again gives it another ttl
	c.Set("key", "val")
	clock.Advance(30 * time.Second)
	c.Set("key", "new")
	clock.Advance(time.Minute)
	expectCached(t, c, "key", "new")
	clock.Advance(time.Nanosecond)
	expectNotCached(t, c, "key")
}

// Expired items are removed, so the cache does not grow with every key that
// was ever in it.
func TestDefaultCache_ExpiredItemsAreRemoved(t *testing.T) {
	c, clock := newTestCache(time.Minute)

	// a new key every ten seconds, for an hour
	for i := 0; i < 360; i++ {
		c.Set(fmt.Sprintf("key-%d", i), i)
		clock.Advance(10 * time.Second)
	}
	// at most the keys of the last two ttl are held
	if size := c.size(); size > 13 {
		t.Fatalf("expected the expired items to be removed, got %d items", size)
	}
	// and the ones that have not expired are among them
	for i := 354; i < 360; i++ {
		expectCached(t, c, fmt.Sprintf("key-%d", i), i)
	}
	expectNotCached(t, c, "key-353")

	// only the expired items are removed
	c, clock = newTestCache(time.Minute)
	c.Set("old", "val")
	clock.Advance(50 * time.Second)
	c.Set("recent", "val")
	clock.Advance(11 * time.Second)
	c.Set("new", "val")
	expectNotCached(t, c, "old")
	expectCached(t, c, "recent", "val")
	expectCached(t, c, "new", "val")
	if size := c.size(); size != 2 {
		t.Fatalf("expected 2 items, got %d", size)
	}

	// an item that expired is removed even if nothing else did
	clock.Advance(time.Hour)
	c.Set("last", "val")
	if size := c.size(); size != 1 {
		t.Fatalf("expected only the last item, got %d items", size)
	}
}

func TestDefaultCache_NoExpiration(t *testing.T) {
	for _, ttl := range []time.Duration{0, -1} {
		c, clock := newTestCache(ttl)
		c.Set("key", "val")
		clock.Advance(1000 * time.Hour)
		c.Set("other", "val")
		expectCached(t, c, "key", "val")
		if size := c.size(); size != 2 {
			t.Fatalf("expected 2 items, got %d", size)
		}
	}
}

func TestDefaultCache_Concurrent(t *testing.T) {
	c := DefaultCache(time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				key := fmt.Sprintf("key-%d", j%10)
				c.Set(key, j)
				if val, found := c.Get(key); found && val == nil {
					t.Errorf("found %s without a value", key)
				}
			}
		}()
	}
	wg.Wait()
}

func TestDefaultCache(t *testing.T) {
	DefaultCache(time.Hour)
	DefaultCache(0)
	DefaultCache(-1)
}

func TestDefaultCache_InvalidTtl(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected a panic")
		}
	}()
	DefaultCache(-2)
}
