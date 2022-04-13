package jwks

import (
	"context"
	"gopkg.in/square/go-jose.v2"
)

type jWKSClientMock struct {
	secret string
}

func NewMockClient(secret string) JWKSClient {
	return &jWKSClientMock{
		secret: secret,
	}
}

func (c *jWKSClientMock) GetSignatureKey(ctx context.Context, keyId string) (*jose.JSONWebKey, error) {
	return mockKey(c.secret), nil
}

func (c *jWKSClientMock) GetEncryptionKey(ctx context.Context, keyId string) (*jose.JSONWebKey, error) {
	return mockKey(c.secret), nil
}

func (c *jWKSClientMock) GetKey(ctx context.Context, keyId string, use string) (*jose.JSONWebKey, error) {
	return mockKey(c.secret), nil
}

func mockKey(secret string) *jose.JSONWebKey {
	return &jose.JSONWebKey{
		KeyID:     "key1",
		Algorithm: "HS256",
		Key:       []byte(secret),
	}
}
