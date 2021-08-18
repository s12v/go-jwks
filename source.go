package jwks

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/square/go-jose"
)

type Source interface {
	JSONWebKeySet() (*jose.JSONWebKeySet, error)
}

type WebSource struct {
	client  *http.Client
	jwksURI string
}

func NewWebSource(jwksURI string, client *http.Client) *WebSource {
	if client == nil {
		client = new(http.Client)
	}

	return &WebSource{
		client:  client,
		jwksURI: jwksURI,
	}
}

func (s *WebSource) JSONWebKeySet() (*jose.JSONWebKeySet, error) {
	logger.Printf("Fetching JWKS from %s", s.jwksURI)
	resp, err := s.client.Get(s.jwksURI)
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
