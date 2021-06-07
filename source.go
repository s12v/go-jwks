package jwks

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/square/go-jose"
)

type JWKSSource interface {
	JSONWebKeySet() (*jose.JSONWebKeySet, error)
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

func (s *WebSource) JSONWebKeySet() (*jose.JSONWebKeySet, error) {
	logger.Printf("Fetching JWKS from %s", s.jwksUri)
	resp, err := s.client.Get(s.jwksUri)
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
