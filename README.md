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

`GetSignatureKey` returns `*jose.JSONWebKey` for a given key id. The id comes from the header of the token
you are about to verify:

```go
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/s12v/go-jwks"
)

// Create the client once and share it: it caches the keys.
var jwksClient = jwks.NewDefaultClient(
	jwks.NewWebSource("https://www.googleapis.com/oauth2/v3/certs", nil),
	time.Hour,    // Refresh keys every 1 hour
	12*time.Hour, // Expire keys after 12 hours
)

// verify checks the signature of a token and returns its payload.
func verify(ctx context.Context, token string) ([]byte, error) {
	// Allow the algorithms you expect, not whatever the token asks for.
	signed, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}

	// The header of the token names the key it is signed with.
	jwk, err := jwksClient.GetSignatureKey(ctx, signed.Signatures[0].Header.KeyID)
	if err != nil {
		return nil, err
	}
	log.Printf("key: %v, alg: %v, use: %v", jwk.KeyID, jwk.Algorithm, jwk.Use)

	return signed.Verify(jwk)
}

func main() {
	// e.g. a Google ID token
	payload, err := verify(context.Background(), os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// The signature is valid. The claims in the payload (issuer, audience,
	// expiry) are still yours to check.
	log.Printf("payload: %s", payload)
}
```

A complete example that runs without a network is in [`example_test.go`](example_test.go).

`NewWebSource` accepts an optional `*http.Client`; when `nil` is passed, a client with a 10 second timeout is used.

## Key use

`GetSignatureKey` and `GetEncryptionKey` return a key with the matching `use` (`sig` or `enc`),
or, if there is none, a key with no `use` at all. A key that declares a different `use` is never returned:
for example, `GetSignatureKey` fails for a key marked `"use": "enc"`.
`GetKey` with an empty `use` returns any key with the given id.

The library does not check the algorithm, or that the key is of the type the algorithm needs:
verify them against what you expect, e.g. by passing the allowed algorithms to `jose.ParseSigned`.

The returned key is your own copy: changing its fields, or the contents of its slices, does not affect
what other callers get. What it points to is shared and must not be modified: an RSA or EC key in `Key`,
the certificates in `Certificates`, and `CertificatesURL`.

## Caching

### Key refresh and TTL

There are two caching parameters:
 - `refresh` - how long a cached key is served before the key set is fetched again
 - `ttl` - how long a key that could not be refreshed stays in the default cache

On the first request, the key set is synchronously fetched from the key server and the key is stored in the cache.
On the next request after `refresh` interval, the key is still returned at once and the key set is fetched
in the background (does not affect response time). The background fetch does not depend on the caller's context.

A key that was not requested for more than 10 seconds after it became due for a refresh is not served unchecked:
the request waits for the key set to be fetched.

If the key server is unavailable, cached keys keep being served until `ttl` expires.

### Revoked keys

A key that is no longer in the key set is dropped from the cache, without waiting for `ttl`.
Unless the key server is unavailable, a key is not served for longer than `refresh` plus 10 seconds
(plus the time a request to the key server takes) after the key set it was last seen in was fetched.
Choose `refresh` accordingly.

A key set fetched for any reason applies to all cached keys right away, so a key can be dropped sooner than that.

A response without keys is treated as a failure of the key server, not as a revocation of every key.
A response that lacks some of the keys cannot be told from a revocation: those keys are dropped
and picked up again by a later fetch.

### Unknown keys and load on the key server

Key ids come from tokens that are not verified yet, so anyone can send a token with a random `kid`.
To keep such requests from turning into requests to the key server:

 - concurrent cache misses share a single request to the source;
 - the fetched key set is reused for 10 seconds: a key that is not in it is reported as not found
   without contacting the source. Nothing is stored per unknown key id;
 - after a failed request, the source is not asked again for 1 second; the error is returned in the meantime.

The other side of it is that a key added to the key set may stay unknown for up to 10 seconds,
and that cached keys are not refreshed more often than that, even if `refresh` is shorter.
Change the interval with `WithMinFetchInterval` (`0` turns both limits off):

```go
jwksClient := jwks.NewDefaultClient(jwksSource, time.Hour, 12*time.Hour,
	jwks.WithMinFetchInterval(time.Minute))
```

A request to the source is shared, so it is not cancelled with the context of the caller that started it:
that caller returns as soon as its context is done, the request goes on for the others.
It is given up on after 15 seconds, even if the source ignores its context.

### Errors

When there is no key with the requested id and use, the error wraps `jwks.ErrKeyNotFound` (check with `errors.Is`).
The key id is cut to 100 bytes and quoted in the message, so that an id from a hostile token
cannot forge log lines or flood the log. Quoting escapes control and non-printable characters,
so the quoted id can be longer than 100 bytes.
Any other error means that the key set could not be loaded, or that the caller's context is done.

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

The client serves the keys a source returns as they are. A source that takes the key set from somewhere
it does not control should leave out the keys that are not public, like `WebSource` does.

`WebSource` skips the keys it cannot parse (an unknown key type or curve, missing parameters and so on),
so that one such key does not make the rest of the key set unavailable.

It also skips keys that come with private or symmetric key material: private keys, symmetric (`oct`) keys,
and RSA keys published together with their prime factors. A key set is public, so such a key is known
to everyone and anyone could sign with it; only public keys are served. If you do keep private or
symmetric keys in a key set of your own, provide your own source.

Skipped keys are logged (the first five of them by name). If no key is left, the request fails.

A response larger than 1 MiB (`MaxResponseSize`) is rejected without being read in full.
The limit applies to the response after decompression. It cannot be changed; if your key set is larger,
provide your own source.

## Logging

Failed requests to the source and keys dropped from the cache are logged with the standard `log` package by default.
Provide your own logger (anything with a `Printf(format string, v ...interface{})` method) or silence it:

```go
jwks.SetLogger(myLogger)
jwks.SetLogger(nil)           // no logging
jwks.SetLogger(log.Default()) // back to the default
```

The logger is shared by all clients and sources. `SetLogger` can be called at any time.
A logger that panics does not take the client down; its messages are lost.
