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

## Key use

`GetSignatureKey` and `GetEncryptionKey` return a key with the matching `use` (`sig` or `enc`),
or, if there is none, a key with no `use` at all. A key that declares a different `use` is never returned:
for example, `GetSignatureKey` fails for a key marked `"use": "enc"`.
`GetKey` with an empty `use` returns any key with the given id.

The library does not check the key type or algorithm: verify them against what you expect,
e.g. by passing the allowed algorithms to `jose.ParseSigned`.

## Caching

### Key refresh and TTL

There are two caching parameters:
 - `refresh` - a cached key is re-read from the key set after this interval
 - `ttl` - a key that has not been refreshed for this long is removed from the default cache

On the first request, the key set is synchronously fetched from the key server and the key is stored in the cache.
On the next request after `refresh` interval, the key is refreshed in the background (does not affect response time).
Only one key refresh is executed at a time. The background refresh does not depend on the caller's context.

If the key server is unavailable, cached keys keep being served until `ttl` expires.

### Revoked keys

A key that is no longer in the key set is dropped from the cache by its next refresh, without waiting for `ttl`.
A revoked key can therefore be served for up to `refresh` after it is removed from the key set,
plus the one request that triggers the refresh: choose `refresh` accordingly.

### Unknown keys and load on the key server

Key ids come from tokens that are not verified yet, so anyone can send a token with a random `kid`.
To keep such requests from turning into requests to the key server:

 - concurrent cache misses share a single request to the source;
 - the fetched key set is reused for 10 seconds: a key that is not in it is reported as not found
   without contacting the source. Nothing is stored per unknown key id.

The other side of it is that a key added to the key set may stay unknown for up to that interval.
Change it with `WithMinFetchInterval` (`0` turns the limit off):

```go
jwksClient := jwks.NewDefaultClient(jwksSource, time.Hour, 12*time.Hour,
	jwks.WithMinFetchInterval(time.Minute))
```

A request to the source is shared, so it is not cancelled with the context of the caller that started it:
that caller returns as soon as its context is done, the request goes on for the others and is bounded
by a 15 second timeout.

### Errors

When there is no key with the requested id and use, the error wraps `jwks.ErrKeyNotFound` (check with `errors.Is`).
Any other error means the key set could not be loaded.

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
