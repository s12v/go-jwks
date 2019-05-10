[![Build Status](https://travis-ci.com/s12v/go-jwks.svg?branch=master)](https://travis-ci.com/s12v/go-jwks)
[![codecov](https://codecov.io/gh/s12v/go-jwks/branch/master/graph/badge.svg)](https://codecov.io/gh/s12v/go-jwks)
# go-jwks

A Go library to retrieve RSA public keys from a JWKS (JSON Web Key Set) endpoint.

## Installation

Using [Go modules](https://github.com/golang/go/wiki/Modules)

```bash
go get github.com/s12v/go-jwks@v0.2.0
```

## Dependencies

 * `github.com/square/go-jose` - JWT library
 * `github.com/patrickmn/go-cache` - default in-memory cache

## Example

`GetEncryptionKey` returns `*jose.JSONWebKey` for a given key id:

```go
package main

import (
	"github.com/s12v/go-jwks"
	"github.com/square/go-jose"
	"time"
	"log"
)

func main() {
	jwksSource := jwks.NewWebSource("https://www.googleapis.com/oauth2/v3/certs")
	jwksClient := jwks.NewDefaultClient(
		jwksSource,
		time.Hour,    // Refresh keys every 1 hour
		12*time.Hour, // Expire keys after 12 hours
	)

	var jwk *jose.JSONWebKey
	jwk, err := jwksClient.GetEncryptionKey("c6af7caa0895fd01e778dceaa7a7988347d8f25c")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("key: %v, alg: %v, use: %v", jwk.KeyID, jwk.Algorithm, jwk.Use)
}
```

Log:

```
2018/07/30 01:22:35 Fetchng JWKS from https://www.googleapis.com/oauth2/v3/certs
2018/07/30 01:22:36 key: c6af7caa0895fd01e778dceaa7a7988347d8f25c, alg: RS256, use: sig
```

## Caching

### Key refresh and TTL

There are two caching parameters:
 - `refresh` - the key will be fetched from the source after this interval 
 - `ttl` - if not used, the key will be deleted from cache 

On the first request, the key is synchronously fetched from the key server and stored in the cache.
On the next request after `refresh` interval, the key will be refreshed in the background (not affect response time).
Only 1 key refresh is executed at the same time.

If the key is not requested during `ttl` interval, it will be removed from cache.

## Cache implementations

Default cache is `github.com/patrickmn/go-cache` in-memory cache.
You can provide your own cache implementation, see `cache.go`:

```go
type Cache interface {
	// Get an item from the cache and itsexpiration time.
	// Returns the item or nil, and a bool indicating whether the key was found
	GetWithExpiration(k string) (interface{}, time.Time, bool)
	// Add an item to the cache, replacing any existing item.
	Set(k string, x interface{})
}
```

and pass it to `func NewClient(...)`

## Source

Default source is `WebSource`. You can provide your own implementation, see `source.go`:

```go
type JWKSSource interface {
	JSONWebKeySet() (*jose.JSONWebKeySet, error)
}
```
