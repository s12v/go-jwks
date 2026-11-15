package jwks

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
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

// the example key from RFC 7517, appendix A.1
const testRSAKey = `{"kty":"RSA","kid":"rsa1","use":"sig","alg":"RS256","e":"AQAB","n":"` +
	"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw" +
	`"}`

// keys that go-jose does not accept
var unsupportedKeys = map[string]string{
	"unknown key type": `{"kty":"AKP","kid":"pq1","alg":"ML-DSA-65","pub":"AAAA"}`,
	"unknown curve":    `{"kty":"EC","kid":"ec1","crv":"secp256k1","x":"AAAA","y":"AAAA"}`,
	"Ed448":            `{"kty":"OKP","kid":"ed1","crv":"Ed448","x":"AAAA"}`,
	"X25519":           `{"kty":"OKP","kid":"x1","crv":"X25519","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}`,
	"missing members":  `{"kty":"RSA","kid":"rsa2"}`,
	"not an object":    `"key"`,
}

func serveJWKS(t *testing.T, body *string) *WebSource {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(*body))
	}))
	t.Cleanup(srv.Close)
	return NewWebSource(srv.URL, nil)
}

// A key that cannot be parsed must not make the other keys unavailable.
func TestWebSource_UnsupportedKeyIsSkipped(t *testing.T) {
	for name, unsupported := range unsupportedKeys {
		t.Run(name, func(t *testing.T) {
			for _, body := range []string{
				`{"keys":[` + testRSAKey + `,` + unsupported + `]}`,
				`{"keys":[` + unsupported + `,` + testRSAKey + `]}`,
			} {
				source := serveJWKS(t, &body)

				jwks, err := source.JSONWebKeySet(context.Background())
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(jwks.Keys) != 1 || jwks.Keys[0].KeyID != "rsa1" {
					t.Fatalf("expected only the supported key, got: %+v", jwks.Keys)
				}

				// and the key is served by the client
				client := NewDefaultClient(source, time.Minute, time.Hour)
				jwk, err := client.GetSignatureKey(context.Background(), "rsa1")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !jwk.Valid() {
					t.Fatal("expected a valid key")
				}
			}
		})
	}
}

// A key set without a single usable key is an error, and the error tells why.
func TestWebSource_NoSupportedKeys(t *testing.T) {
	body := `{"keys":[` + unsupportedKeys["unknown curve"] + `,` + unsupportedKeys["Ed448"] + `]}`
	source := serveJWKS(t, &body)

	_, err := source.JSONWebKeySet(context.Background())
	if !errors.Is(err, jose.ErrUnsupportedKeyType) {
		t.Fatalf("expected jose.ErrUnsupportedKeyType, got: %v", err)
	}
	if !strings.Contains(err.Error(), `"ec1"`) {
		t.Fatalf("expected the error to name the key, got: %v", err)
	}
}

func TestWebSource_EmptyKeySet(t *testing.T) {
	for _, body := range []string{`{"keys":[]}`, `{}`} {
		source := serveJWKS(t, &body)

		jwks, err := source.JSONWebKeySet(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(jwks.Keys) != 0 {
			t.Fatalf("unexpected keys: %+v", jwks.Keys)
		}
	}
}

// Skipped keys are reported once, not on every request.
func TestWebSource_SkippedKeysAreReportedOnce(t *testing.T) {
	source := NewWebSource("http://example.com", nil)
	ed448 := []error{errors.New(`key "ed1": unsupported`)}
	x25519 := []error{errors.New(`key "x1": unsupported`)}

	report := source.skippedReport(ed448, 2)
	if !strings.Contains(report, "skipped 1 of 2 keys") || !strings.Contains(report, `"ed1"`) {
		t.Fatalf("unexpected report: %q", report)
	}
	if report = source.skippedReport(ed448, 2); report != "" {
		t.Fatalf("expected no report for the same keys, got: %q", report)
	}
	if report = source.skippedReport(x25519, 2); !strings.Contains(report, `"x1"`) {
		t.Fatalf("expected a report for other keys, got: %q", report)
	}
	if report = source.skippedReport(nil, 1); report != "" {
		t.Fatalf("expected no report without skipped keys, got: %q", report)
	}
	if report = source.skippedReport(ed448, 2); report == "" {
		t.Fatal("expected a report when keys are skipped again")
	}
}

func TestWebSource_SkippedKeysAreNoted(t *testing.T) {
	body := `{"keys":[` + testRSAKey + `,` + unsupportedKeys["Ed448"] + `]}`
	source := serveJWKS(t, &body)
	if _, err := source.JSONWebKeySet(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	source.mu.Lock()
	defer source.mu.Unlock()
	if !strings.Contains(source.lastSkipped, `key "ed1" of type "OKP"`) {
		t.Fatalf("unexpected report: %q", source.lastSkipped)
	}
}
