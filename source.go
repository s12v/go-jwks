package jwks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// DefaultHTTPTimeout is the timeout of the http.Client created by NewWebSource
// when no client is given.
const DefaultHTTPTimeout = 10 * time.Second

// MaxResponseSize is the largest key set, in bytes, that WebSource accepts.
// A key takes a few kilobytes at most, even with a certificate chain.
const MaxResponseSize = 1 << 20

type JWKSSource interface {
	JSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, error)
}

type WebSource struct {
	client  *http.Client
	jwksUri string

	mu sync.Mutex
	// what was last logged about skipped keys, to log it once and not on
	// every request
	lastSkipped string
}

// NewWebSource returns a source that fetches the key set from jwksUri.
// If client is nil, an http.Client with DefaultHTTPTimeout is used.
func NewWebSource(jwksUri string, client *http.Client) *WebSource {
	if client == nil {
		client = &http.Client{Timeout: DefaultHTTPTimeout}
	}

	return &WebSource{
		client:  client,
		jwksUri: jwksUri,
	}
}

func (s *WebSource) JSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.jwksUri, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed request to %s, status: %d", s.jwksUri, resp.StatusCode)
	}

	// Read no more than the limit, whatever the server sends: the response
	// is held in memory in full.
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS from %s: %w", s.jwksUri, err)
	}
	if len(body) > MaxResponseSize {
		return nil, fmt.Errorf("invalid JWKS from %s: larger than %d bytes", s.jwksUri, MaxResponseSize)
	}

	// The keys are parsed one by one: a key that cannot be parsed must not
	// make the rest of the key set unusable.
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err = json.NewDecoder(bytes.NewReader(body)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("invalid JWKS from %s: %w", s.jwksUri, err)
	}

	jsonWebKeySet, skipped := parseKeys(raw.Keys)
	if len(jsonWebKeySet.Keys) == 0 && len(skipped) > 0 {
		return nil, fmt.Errorf("invalid JWKS from %s: none of the %d keys can be used: %w", s.jwksUri, len(skipped), skipped[0])
	}
	if report := s.skippedReport(skipped, len(raw.Keys)); report != "" {
		logf("%s", report)
	}

	return jsonWebKeySet, nil
}

// parseKeys returns the keys that can be parsed, and an error for each one
// that cannot. Such keys are to be ignored (RFC 7517, section 5): a key set
// may well contain keys of a type, curve or size that is not supported here,
// next to the ones that are needed.
func parseKeys(rawKeys []json.RawMessage) (*jose.JSONWebKeySet, []error) {
	keySet := &jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(rawKeys))}
	var skipped []error
	for _, rawKey := range rawKeys {
		var key jose.JSONWebKey
		if err := json.Unmarshal(rawKey, &key); err != nil {
			// best effort, to tell which key it was
			var id struct {
				Kid string `json:"kid"`
				Kty string `json:"kty"`
			}
			_ = json.Unmarshal(rawKey, &id)
			skipped = append(skipped, fmt.Errorf("key %q of type %q: %w", id.Kid, id.Kty, err))
			continue
		}
		keySet.Keys = append(keySet.Keys, key)
	}
	return keySet, skipped
}

// skippedReport returns what to log about the keys that were skipped. It is
// empty if there are none, or if they are the same as the last time: the key
// set is fetched over and over, and it rarely changes.
func (s *WebSource) skippedReport(skipped []error, total int) string {
	var report string
	if len(skipped) > 0 {
		reasons := make([]string, len(skipped))
		for i, err := range skipped {
			reasons[i] = err.Error()
		}
		report = fmt.Sprintf("skipped %d of %d keys in JWKS from %s: %s",
			len(skipped), total, s.jwksUri, strings.Join(reasons, "; "))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if report == s.lastSkipped {
		return ""
	}
	s.lastSkipped = report
	return report
}
