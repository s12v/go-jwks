package jwks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testJWKS = `{"keys":[{"kty":"oct","kid":"key1","use":"sig","k":"c2VjcmV0"}]}`

func TestWebSource_JSONWebKeySet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %v", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testJWKS))
	}))
	defer srv.Close()

	jwks, err := NewWebSource(srv.URL, nil).JSONWebKeySet(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0].KeyID != "key1" {
		t.Fatalf("unexpected key set: %+v", jwks)
	}
}

func TestWebSource_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if _, err := NewWebSource(srv.URL, nil).JSONWebKeySet(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestWebSource_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	if _, err := NewWebSource(srv.URL, nil).JSONWebKeySet(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestWebSource_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, err := NewWebSource(srv.URL, nil).JSONWebKeySet(ctx); err == nil {
		t.Fatal("expected an error")
	}
}

func TestNewWebSource_DefaultClientHasTimeout(t *testing.T) {
	s := NewWebSource("http://example.com", nil)
	if s.client.Timeout != DefaultHTTPTimeout {
		t.Fatalf("unexpected timeout: %v", s.client.Timeout)
	}

	custom := &http.Client{Timeout: time.Minute}
	if NewWebSource("http://example.com", custom).client != custom {
		t.Fatal("custom client should be used as is")
	}
}
