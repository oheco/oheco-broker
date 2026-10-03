package remote

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// Empty optional STUN must be NULL at the C boundary, not a non-NULL invalid
// hostname. Reach a real HTTP endpoint rather than merely rejecting a bad ID.
func TestOptionalSTUNDefaultsReachControl(t *testing.T) {
	var observed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"fixture denied"}`))
	}))
	defer server.Close()
	client, err := New(Options{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.Serve("optional-stun", "private-peer-password", ServeOptions{})
	var diagnostic *Error
	if !errors.As(err, &diagnostic) || diagnostic.HTTPStatus != 401 {
		t.Fatalf("serve did not reach control with omitted STUN: %v", err)
	}
	_, err = client.Connect("12345678-1234-4234-8234-123456789abc", "private-peer-password", ConnectOptions{})
	if !errors.As(err, &diagnostic) || diagnostic.HTTPStatus != 401 {
		t.Fatalf("connect did not reach control with omitted STUN: %v", err)
	}
	if observed.Load() != 2 {
		t.Fatalf("unexpected request count %d", observed.Load())
	}
}
