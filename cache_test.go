package jwks

import (
	"github.com/patrickmn/go-cache"
	"testing"
	"time"
)

func TestDefaultCache_Get(t *testing.T) {
	c := &defaultCache{
		cache.New(time.Minute, 0),
	}

	c.Set("key", "val")
	val, found := c.Get("key")

	if !found {
		t.Fatal("should be found")
	}

	if val != "val" {
		t.Fatalf("val should be 'val', got %v instead", val)
	}
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
