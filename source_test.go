package jwks

import (
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const testJWKS = `{"keys":[` + testRSAKey + `]}`

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
	if len(jwks.Keys) != 1 || jwks.Keys[0].KeyID != "rsa1" {
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

// A response is read up to the limit and no further.
func TestWebSource_ResponseSizeLimit(t *testing.T) {
	// a key set padded to exactly n bytes
	padded := func(n int) string {
		head, tail := `{"keys":[`+testRSAKey+`],"padding":"`, `"}`
		return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
	}

	body := padded(MaxResponseSize)
	source := serveJWKS(t, &body)
	jwks, err := source.JSONWebKeySet(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("unexpected keys: %+v", jwks.Keys)
	}

	body = padded(MaxResponseSize + 1)
	if _, err = source.JSONWebKeySet(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("expected a size error, got: %v", err)
	}
}

// A server that never stops sending is cut off at the limit.
func TestWebSource_EndlessResponse(t *testing.T) {
	sent := make(chan int, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("a", 64<<10))
		n := 0
		defer func() { sent <- n }()
		_, _ = w.Write([]byte(`{"keys":[],"padding":"`))
		for n < 64<<20 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			n += len(chunk)
		}
	}))
	defer srv.Close()

	if _, err := NewWebSource(srv.URL, nil).JSONWebKeySet(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("expected a size error, got: %v", err)
	}
	// the connection is dropped long before the server is done
	if n := <-sent; n >= 64<<20 {
		t.Fatalf("the whole response was read: %d bytes", n)
	}
}

// A response that declares its size is rejected without being read.
func TestWebSource_DeclaredSizeOverLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(MaxResponseSize+1))
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()

	if _, err := NewWebSource(srv.URL, nil).JSONWebKeySet(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("expected a size error, got: %v", err)
	}
}

// The limit applies to the response as it is held in memory, not as it is
// sent: a small compressed response can expand into a huge one.
func TestWebSource_CompressedResponse(t *testing.T) {
	padding := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			t.Errorf("expected the client to accept gzip")
		}
		w.Header().Set("Content-Encoding", "gzip")
		compressed := gzip.NewWriter(w)
		defer compressed.Close()
		_, _ = compressed.Write([]byte(`{"keys":[` + testRSAKey + `],"padding":"` + strings.Repeat("a", padding) + `"}`))
	}))
	defer srv.Close()
	source := NewWebSource(srv.URL, nil)

	jwks, err := source.JSONWebKeySet(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("unexpected keys: %+v", jwks.Keys)
	}

	padding = 4 * MaxResponseSize
	if _, err = source.JSONWebKeySet(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("expected a size error, got: %v", err)
	}
}

// The report about skipped keys stays short, whatever the key set holds.
func TestWebSource_SkippedReportIsBounded(t *testing.T) {
	longKid := strings.Repeat("k", 10000)
	keys := []string{testRSAKey}
	for i := 0; i < 99; i++ {
		keys = append(keys, fmt.Sprintf(`{"kty":"OKP","crv":"Ed448","kid":"%s-%d","x":"AAAA"}`, longKid, i))
	}
	body := `{"keys":[` + strings.Join(keys, ",") + `]}`
	source := serveJWKS(t, &body)
	if _, err := source.JSONWebKeySet(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	source.mu.Lock()
	defer source.mu.Unlock()
	if len(source.lastSkipped) > 2000 || !strings.Contains(source.lastSkipped, "and 94 more") {
		t.Fatalf("unexpected report of %d bytes: %.300s", len(source.lastSkipped), source.lastSkipped)
	}
}

// marshalKey returns the key as it would be published in a key set.
func marshalKey(t *testing.T, keyId string, key interface{}) string {
	t.Helper()
	data, err := json.Marshal(jose.JSONWebKey{Key: key, KeyID: keyId, Use: "sig"})
	if err != nil {
		t.Fatalf("unable to marshal the %s key: %v", keyId, err)
	}
	return string(data)
}

var (
	generateRSAKey  sync.Once
	generatedRSAKey *rsa.PrivateKey
)

// testRSAPrivateKey returns an RSA key that is generated once: it takes a
// while, the more so under the race detector.
func testRSAPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	generateRSAKey.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		generatedRSAKey = key
	})
	if generatedRSAKey == nil {
		t.Fatal("no RSA key")
	}
	return generatedRSAKey
}

// testKeyPairs returns a private and a public key of each supported type,
// and a symmetric key, by key id.
func testKeyPairs(t *testing.T) (private map[string]string, public map[string]string) {
	t.Helper()
	rsaKey := testRSAPrivateKey(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// an RSA key without "d" is parsed as a public key, whatever else of
	// the private key comes with it
	withMembers := func(keyId string, members ...string) string {
		var all, kept map[string]json.RawMessage
		if err := json.Unmarshal([]byte(marshalKey(t, keyId, rsaKey)), &all); err != nil {
			t.Fatal(err)
		}
		kept = map[string]json.RawMessage{}
		for _, name := range append([]string{"kty", "kid", "use", "n", "e"}, members...) {
			if _, found := all[name]; !found {
				t.Fatalf("no %q in the RSA key", name)
			}
			kept[name] = all[name]
		}
		data, err := json.Marshal(kept)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	private = map[string]string{
		"rsa-private": marshalKey(t, "rsa-private", rsaKey),
		"rsa-factors": withMembers("rsa-factors", "p", "q"),
		"rsa-p":       withMembers("rsa-p", "p"),
		"rsa-q":       withMembers("rsa-q", "q"),
		"rsa-dp":      withMembers("rsa-dp", "dp"),
		"rsa-dq":      withMembers("rsa-dq", "dq"),
		"rsa-qi":      withMembers("rsa-qi", "qi"),
		"rsa-oth":     strings.Replace(marshalKey(t, "rsa-oth", &rsaKey.PublicKey), `{`, `{"oth":[],`, 1),
		"rsa-k":       strings.Replace(marshalKey(t, "rsa-k", &rsaKey.PublicKey), `{`, `{"k":"c2VjcmV0",`, 1),
		"ec-private":  marshalKey(t, "ec-private", ecKey),
		"ed-private":  marshalKey(t, "ed-private", edPrivate),
		"symmetric":   marshalKey(t, "symmetric", []byte("a secret that is not one any more")),
	}
	public = map[string]string{
		"rsa-public": marshalKey(t, "rsa-public", &rsaKey.PublicKey),
		"ec-public":  marshalKey(t, "ec-public", &ecKey.PublicKey),
		"ed-public":  marshalKey(t, "ed-public", edPublic),
	}
	return private, public
}

// A private or a symmetric key that is published in a key set is known to
// everyone, so it must not be handed out to verify anything.
func TestWebSource_NonPublicKeyIsSkipped(t *testing.T) {
	private, public := testKeyPairs(t)

	for keyId, key := range private {
		t.Run(keyId, func(t *testing.T) {
			body := `{"keys":[` + key + `,` + testRSAKey + `]}`
			source := serveJWKS(t, &body)

			jwks, err := source.JSONWebKeySet(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(jwks.Keys) != 1 || jwks.Keys[0].KeyID != "rsa1" {
				t.Fatalf("expected only the public key, got: %+v", jwks.Keys)
			}

			source.mu.Lock()
			report := source.lastSkipped
			source.mu.Unlock()
			if !strings.Contains(report, `key "`+keyId+`"`) || !strings.Contains(report, "not a public key") {
				t.Fatalf("unexpected report: %q", report)
			}

			// the client does not serve it either
			client := NewDefaultClient(source, time.Minute, time.Hour)
			if _, err = client.GetSignatureKey(context.Background(), keyId); !errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("expected ErrKeyNotFound, got: %v", err)
			}
			if _, err = client.GetSignatureKey(context.Background(), "rsa1"); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// a key set with nothing else is of no use
			body = `{"keys":[` + key + `]}`
			if _, err = source.JSONWebKeySet(context.Background()); !errors.Is(err, errNotPublicKey) {
				t.Fatalf("expected errNotPublicKey, got: %v", err)
			}
		})
	}

	// public keys of the same types are served
	for keyId, key := range public {
		t.Run(keyId, func(t *testing.T) {
			body := `{"keys":[` + key + `]}`
			client := NewDefaultClient(serveJWKS(t, &body), time.Minute, time.Hour)
			jwk, err := client.GetSignatureKey(context.Background(), keyId)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !jwk.IsPublic() || !jwk.Valid() {
				t.Fatalf("expected a valid public key, got %T", jwk.Key)
			}
		})
	}
}
