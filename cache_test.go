package jwks

import (
	"testing"
	"github.com/patrickmn/go-cache"
	"time"
)

func TestDefaultCache_GetWithExpiration(t *testing.T) {
	c := &defaultCache{
		cache.New(time.Minute, 0),
	}

	c.Set("key", "val")
	val, expTime, found := c.GetWithExpiration("key")

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

func TestDefaultCache_GetWithExpiration_Expired(t *testing.T) {
	c := &defaultCache{
		cache.New(time.Nanosecond, 0),
	}

	c.Set("key", "val")
	time.Sleep(10 * time.Millisecond)
	val, expTime, found := c.GetWithExpiration("key")

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


