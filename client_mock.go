package jwks

import (
	"github.com/square/go-jose"
)

type mockClient struct {
	secret string
}

func NewMockClient(secret string) Client {
	return &mockClient{
		secret: secret,
	}
}

func (c *mockClient) GetSignatureKey(keyID string) (*jose.JSONWebKey, error) {
	return mockKey(c.secret), nil
}

func (c *mockClient) GetEncryptionKey(keyID string) (*jose.JSONWebKey, error) {
	return mockKey(c.secret), nil
}

func (c *mockClient) GetKey(keyID string, use string) (*jose.JSONWebKey, error) {
	return mockKey(c.secret), nil
}

func mockKey(secret string) *jose.JSONWebKey {
	return &jose.JSONWebKey{
		KeyID:     "key1",
		Algorithm: "HS256",
		Key:       []byte(secret),
	}
}
