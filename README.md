[![CI](https://github.com/s12v/go-jwks/actions/workflows/ci.yml/badge.svg)](https://github.com/s12v/go-jwks/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/s12v/go-jwks/branch/master/graph/badge.svg)](https://codecov.io/gh/s12v/go-jwks)
[![Go Reference](https://pkg.go.dev/badge/github.com/s12v/go-jwks.svg)](https://pkg.go.dev/github.com/s12v/go-jwks)

# go-jwks

A Go library to retrieve public keys from a JWKS (JSON Web Key Set) endpoint, with caching and background refresh.

## Installation

```bash
go get github.com/s12v/go-jwks
```

Requires Go 1.24 or newer.

## Dependencies

 * [`github.com/go-jose/go-jose/v4`](https://github.com/go-jose/go-jose) - JWK types
 * [`github.com/patrickmn/go-cache`](https://github.com/patrickmn/go-cache) - default in-memory cache

## Example

`GetSignatureKey` returns `*jose.JSONWebKey` for a given key id:

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/s12v/go-jwks"
)

func main() {
	jwksSource := jwks.NewWebSource("https://www.googleapis.com/oauth2/v3/certs", nil)
	jwksClient := jwks.NewDefaultClient(
		jwksSource,
		time.Hour,    // Refresh keys every 1 hour
		12*time.Hour, // Expire keys after 12 hours
	)

	var jwk *jose.JSONWebKey
	jwk, err := jwksClient.GetSignatureKey(context.Background(), "c6af7caa0895fd01e778dceaa7a7988347d8f25c")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("key: %v, alg: %v, use: %v", jwk.KeyID, jwk.Algorithm, jwk.Use)
}
```

`NewWebSource` accepts an optional `*http.Client`; when `nil` is passed, a client with a 10 second timeout is used.

## Caching

### Key refresh and TTL

There are two caching parameters:
 - `refresh` - the key will be fetched from the source after this interval
 - `ttl` - if not used, the key will be deleted from cache

On the first request, the key is synchronously fetched from the key server and stored in the cache.
On the next request after `refresh` interval, the key is refreshed in the background (does not affect response time).
Only one key refresh is executed at a time. The background refresh does not depend on the caller's context
and is bounded by a 15 second timeout.

If the key is not requested during `ttl` interval, it will be removed from cache.

### Cache implementations

Default cache is `github.com/patrickmn/go-cache` in-memory cache.
You can provide your own cache implementation, see `cache.go`:

```go
type Cache interface {
	// Get an item from the cache
	// Returns the item or nil, and a bool indicating whether the key was found
	Get(k string) (interface{}, bool)
	// Add an item to the cache, replacing any existing item.
	Set(k string, x interface{})
}
```

and pass it to `func NewClient(...)`. The implementation must be safe for concurrent use.

## Source

Default source is `WebSource`. You can provide your own implementation, see `source.go`:

```go
type JWKSSource interface {
	JSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, error)
}
```

## Logging

Background refresh errors are logged with the standard `log` package by default.
Provide your own logger (anything with a `Printf(format string, v ...interface{})` method) or silence it:

```go
jwks.SetLogger(myLogger)
```
