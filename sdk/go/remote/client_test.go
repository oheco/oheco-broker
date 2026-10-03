package remote

import (
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInputValidation(t *testing.T) {
	for _, options := range []Options{{URL: "http://127.0.0.1\x00.invalid"}, {URL: "http://127.0.0.1", Token: "secret\x00suffix"}, {URL: "http://127.0.0.1", Timeout: -time.Second}, {URL: "http://127.0.0.1", Timeout: 301 * time.Second}, {URL: "http://example.invalid"}} {
		client, err := New(options)
		if err == nil {
			client.Close()
			t.Fatal("accepted invalid options")
		}
	}
	client, err := New(Options{URL: "http://127.0.0.1:1", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.Request("GET", "/v1/me\x00/admin", nil, nil); err == nil {
		t.Fatal("accepted NUL API path")
	}
	if _, err = client.Serve("name", "secret\x00suffix", ServeOptions{}); err == nil {
		t.Fatal("accepted truncated password")
	}
	if _, err = client.Connect("id", "pw", ConnectOptions{Timeout: -time.Second}); err == nil {
		t.Fatal("accepted negative timeout")
	}
	if _, err = client.Connect("id", "pw", ConnectOptions{Relay: RelayMode(99)}); err == nil {
		t.Fatal("accepted invalid native relay mode")
	}
}
func TestCloseLifetime(t *testing.T) {
	client, err := New(Options{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.retain(); err != nil {
		t.Fatal(err)
	}
	if err = client.Close(); err == nil {
		t.Fatal("destroyed client with live native reference")
	}
	client.refs.Add(-1)
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Request("GET", "/v1/me", nil, nil); err == nil {
		t.Fatal("used closed client")
	}
	if _, err = client.retain(); err == nil {
		t.Fatal("retained destroyed native client")
	}
}

func TestVerifiedHTTPSWithOptionalCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	trusted, err := New(Options{URL: server.URL, CAFile: path, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer trusted.Close()
	if _, err = trusted.Request("GET", "/v1/me", nil, nil); err != nil {
		t.Fatalf("explicit CA verification failed: %v", err)
	}
	untrusted, err := New(Options{URL: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.Close()
	_, err = untrusted.Request("GET", "/v1/me", nil, nil)
	var diagnostic *Error
	if !errors.As(err, &diagnostic) || diagnostic.HTTPStatus != 0 || diagnostic.TransportCode == 0 {
		t.Fatalf("omitted CA bypassed HTTPS verification: %v", err)
	}
}
