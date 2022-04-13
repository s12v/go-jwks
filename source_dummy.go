package jwks

import (
	"context"
	"github.com/square/go-jose"
)

type DummySource struct {
	Jwks *jose.JSONWebKeySet
}

func NewDummySource(jwks *jose.JSONWebKeySet) *DummySource {
	return &DummySource{Jwks: jwks}
}

func (s *DummySource) JSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, error) {
	return s.Jwks, nil
}
