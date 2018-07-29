package jwks

import (
	"testing"
	"github.com/patrickmn/go-cache"
	"time"
)

func TestDefaultCache_Get(t *testing.T) {
	c := &defaultCache{
		cache.New(1, 0),
	}

	c.cache.Set("key", "val", time.Minute)
	val, expTime, found := c.cache.GetWithExpiration("key")

	if expTime.Before(time.Now()) {
		t.Fatalf("expTime should be after now: %v", expTime)
	}

	if !found {
		t.Fatal("should be found")
	}

	if val != "val" {
		t.Fatalf("val should be 'val', got %v instead", val)
	}
}

func TestDefaultCache_GetExpired(t *testing.T) {
	c := &defaultCache{
		cache.New(1, 0),
	}

	c.cache.Set("key", "val", time.Nanosecond)
	time.Sleep(10 * time.Millisecond)
	val, expTime, found := c.cache.GetWithExpiration("key")

	if expTime.After(time.Now()) {
		t.Fatalf("expTime should be before now: %v", expTime)
	}

	if found {
		t.Fatal("should be not found")
	}

	if val != nil {
		t.Fatalf("val should be nil, got %v instead", val)
	}
}
