package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// DefaultHTTPTimeout is the timeout of the http.Client created by NewWebSource
// when no client is given.
const DefaultHTTPTimeout = 10 * time.Second

type JWKSSource interface {
	JSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, error)
}

type WebSource struct {
	client  *http.Client
	jwksUri string
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

	jsonWebKeySet := new(jose.JSONWebKeySet)
	if err = json.NewDecoder(resp.Body).Decode(jsonWebKeySet); err != nil {
		return nil, fmt.Errorf("invalid JWKS from %s: %w", s.jwksUri, err)
	}

	return jsonWebKeySet, nil
}
