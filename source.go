package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"net/http"
)

type JWKSSource interface {
	JSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, error)
}

type WebSource struct {
	client  *http.Client
	jwksUri string
}

func NewWebSource(jwksUri string, client *http.Client) *WebSource {
	if client == nil {
		client = new(http.Client)
	}

	return &WebSource{
		client:  client,
		jwksUri: jwksUri,
	}
}

func (s *WebSource) JSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	logger.Printf("Fetching JWKS from %s", s.jwksUri)

	req, err := http.NewRequest("GET", s.jwksUri, nil)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed request, status: %d", resp.StatusCode)
	}

	jsonWebKeySet := new(jose.JSONWebKeySet)
	if err = json.NewDecoder(resp.Body).Decode(jsonWebKeySet); err != nil {
		return nil, err
	}

	return jsonWebKeySet, err
}
