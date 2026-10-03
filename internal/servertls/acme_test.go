package servertls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme"
)

const testDomain = "broker.example.org"

// localCA implements only the RFC 8555 endpoints autocert needs. It performs an
// actual TLS connection to the provider for every tls-alpn-01 authorization,
// verifies the critical acmeIdentifier extension against the registered JWK,
// and signs the CSR with a locally generated root. It never calls a public CA.
type localCA struct {
	t              *testing.T
	server         *httptest.Server
	root           *x509.Certificate
	rootKey        *ecdsa.PrivateKey
	roots          *x509.CertPool
	mu             sync.Mutex
	address        string
	thumbprint     string
	account        bool
	orders         map[int]*localOrder
	finalizeGate   <-chan struct{}
	finalizeHit    chan struct{}
	failFinalize   bool
	finalizeFailed atomic.Bool
	requests       atomic.Int64
	issued         atomic.Int64
	challenges     atomic.Int64
	httpAttempts   atomic.Int64
	nonce          atomic.Int64
}

type localOrder struct {
	id     int
	domain string
	valid  bool
	der    []byte
}

type testJWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func newLocalCA(t *testing.T) *localCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Local ACME test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &localCA{t: t, root: root, rootKey: key, roots: x509.NewCertPool(), orders: make(map[int]*localOrder), finalizeHit: make(chan struct{}, 4)}
	ca.roots.AddCert(root)
	ca.server = httptest.NewServer(http.HandlerFunc(ca.serveHTTP))
	t.Cleanup(ca.server.Close)
	return ca
}

func (ca *localCA) endpoint(path string) string { return ca.server.URL + path }

func (ca *localCA) setAddress(address string) {
	ca.mu.Lock()
	ca.address = address
	ca.mu.Unlock()
}

func decodeJWS(r *http.Request) (testJWK, []byte, error) {
	var envelope struct{ Protected, Payload string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&envelope); err != nil {
		return testJWK{}, nil, err
	}
	protected, err := base64.RawURLEncoding.DecodeString(envelope.Protected)
	if err != nil {
		return testJWK{}, nil, err
	}
	var header struct {
		JWK testJWK `json:"jwk"`
	}
	if err := json.Unmarshal(protected, &header); err != nil {
		return testJWK{}, nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	return header.JWK, payload, err
}

func (ca *localCA) json(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		ca.t.Errorf("local CA response: %v", err)
	}
}

func (ca *localCA) orderJSON(order *localOrder) map[string]any {
	status := "pending"
	if order.valid {
		status = "ready"
	}
	if order.der != nil {
		status = "valid"
	}
	value := map[string]any{"status": status, "authorizations": []string{ca.endpoint(fmt.Sprintf("/authz/%d", order.id))}, "finalize": ca.endpoint(fmt.Sprintf("/finalize/%d", order.id))}
	if order.der != nil {
		value["certificate"] = ca.endpoint(fmt.Sprintf("/cert/%d", order.id))
	}
	return value
}

func (ca *localCA) authzJSON(order *localOrder) map[string]any {
	status := "pending"
	if order.valid {
		status = "valid"
	}
	return map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": order.domain},
		"challenges": []any{
			map[string]string{"type": "http-01", "url": ca.endpoint(fmt.Sprintf("/http-challenge/%d", order.id)), "token": "http-token"},
			map[string]string{"type": "tls-alpn-01", "url": ca.endpoint(fmt.Sprintf("/challenge/%d", order.id)), "token": fmt.Sprintf("token-%d", order.id)},
		}}
}

func (ca *localCA) serveHTTP(w http.ResponseWriter, r *http.Request) {
	ca.requests.Add(1)
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", ca.nonce.Add(1)))
	if r.URL.Path == "/directory" {
		ca.json(w, 200, map[string]any{"newNonce": ca.endpoint("/nonce"), "newAccount": ca.endpoint("/account"), "newOrder": ca.endpoint("/new-order"), "meta": map[string]string{"termsOfService": ca.endpoint("/tos")}})
		return
	}
	if r.URL.Path == "/nonce" {
		w.WriteHeader(200)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 400)
		return
	}
	jwk, payload, err := decodeJWS(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if r.URL.Path == "/account" {
		ca.mu.Lock()
		var registration struct {
			TermsOfServiceAgreed bool `json:"termsOfServiceAgreed"`
			OnlyReturnExisting   bool `json:"onlyReturnExisting"`
		}
		_ = json.Unmarshal(payload, &registration)
		if !ca.account && !registration.TermsOfServiceAgreed {
			ca.mu.Unlock()
			w.Header().Set("Content-Type", "application/problem+json")
			ca.json(w, 400, map[string]string{"type": "urn:ietf:params:acme:error:accountDoesNotExist", "detail": "account not registered"})
			return
		}
		canonical, _ := json.Marshal(jwk)
		digest := sha256.Sum256(canonical)
		if ca.account && ca.thumbprint != base64.RawURLEncoding.EncodeToString(digest[:]) {
			ca.mu.Unlock()
			http.Error(w, "unexpected account key", 400)
			return
		}
		ca.thumbprint = base64.RawURLEncoding.EncodeToString(digest[:])
		ca.account = true
		ca.mu.Unlock()
		w.Header().Set("Location", ca.endpoint("/account/1"))
		ca.json(w, 201, map[string]string{"status": "valid"})
		return
	}
	if r.URL.Path == "/new-order" {
		var request struct {
			Identifiers []struct{ Type, Value string }
		}
		if err := json.Unmarshal(payload, &request); err != nil || len(request.Identifiers) != 1 || request.Identifiers[0].Value != testDomain {
			http.Error(w, "invalid identifiers", 400)
			return
		}
		ca.mu.Lock()
		order := &localOrder{id: len(ca.orders) + 1, domain: request.Identifiers[0].Value}
		ca.orders[order.id] = order
		value := ca.orderJSON(order)
		ca.mu.Unlock()
		w.Header().Set("Location", ca.endpoint(fmt.Sprintf("/order/%d", order.id)))
		ca.json(w, 201, value)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 2 {
		http.Error(w, "unknown endpoint", 404)
		return
	}
	id, err := strconv.Atoi(parts[1])
	ca.mu.Lock()
	order := ca.orders[id]
	if err != nil || order == nil {
		ca.mu.Unlock()
		http.Error(w, "unknown order", 404)
		return
	}
	switch parts[0] {
	case "authz":
		value := ca.authzJSON(order)
		ca.mu.Unlock()
		ca.json(w, 200, value)
	case "order":
		value := ca.orderJSON(order)
		ca.mu.Unlock()
		ca.json(w, 200, value)
	case "http-challenge":
		ca.mu.Unlock()
		ca.httpAttempts.Add(1)
		http.Error(w, "HTTP-01 must not be used", 400)
	case "challenge":
		address, thumbprint, domain := ca.address, ca.thumbprint, order.domain
		ca.mu.Unlock()
		if err := checkALPNChallenge(address, domain, fmt.Sprintf("token-%d", id), thumbprint); err != nil {
			ca.t.Errorf("actual TLS-ALPN challenge: %v", err)
			http.Error(w, "challenge verification failed", 400)
			return
		}
		ca.challenges.Add(1)
		ca.mu.Lock()
		order.valid = true
		ca.mu.Unlock()
		ca.json(w, 200, map[string]string{"status": "valid", "type": "tls-alpn-01", "url": ca.endpoint(fmt.Sprintf("/challenge/%d", id)), "token": fmt.Sprintf("token-%d", id)})
	case "finalize":
		gate, valid := ca.finalizeGate, order.valid
		ca.mu.Unlock()
		if !valid {
			http.Error(w, "authorization required", 400)
			return
		}
		select {
		case ca.finalizeHit <- struct{}{}:
		default:
		}
		if gate != nil {
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
		if ca.failFinalize {
			ca.finalizeFailed.Store(true)
			ca.json(w, http.StatusBadRequest, map[string]string{"type": "urn:ietf:params:acme:error:rejectedIdentifier", "detail": "local test renewal rejection"})
			return
		}
		var request struct {
			CSR string `json:"csr"`
		}
		if err := json.Unmarshal(payload, &request); err != nil {
			http.Error(w, "invalid CSR", 400)
			return
		}
		der, err := base64.RawURLEncoding.DecodeString(request.CSR)
		if err != nil {
			http.Error(w, "invalid CSR encoding", 400)
			return
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 1 || csr.DNSNames[0] != testDomain {
			http.Error(w, "invalid CSR", 400)
			return
		}
		leaf, err := ca.sign(csr.PublicKey, time.Now().Add(90*24*time.Hour), ca.issued.Add(1)+10)
		if err != nil {
			http.Error(w, "signing failed", 500)
			return
		}
		ca.mu.Lock()
		order.der = leaf
		value := ca.orderJSON(order)
		ca.mu.Unlock()
		w.Header().Set("Location", ca.endpoint(fmt.Sprintf("/order/%d", id)))
		ca.json(w, 200, value)
	case "cert":
		der := append([]byte(nil), order.der...)
		ca.mu.Unlock()
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw})
	default:
		ca.mu.Unlock()
		http.Error(w, "unknown endpoint", 404)
	}
}

func (ca *localCA) sign(publicKey any, expiry time.Time, serial int64) ([]byte, error) {
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{testDomain},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	return x509.CreateCertificate(rand.Reader, template, ca.root, publicKey, ca.rootKey)
}

func checkALPNChallenge(address, domain, token, thumbprint string) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{
		ServerName: domain, NextProtos: []string{acme.ALPNProto}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != acme.ALPNProto || len(state.PeerCertificates) != 1 {
		return fmt.Errorf("invalid challenge negotiation")
	}
	cert := state.PeerCertificates[0]
	if err := cert.VerifyHostname(domain); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(token + "." + thumbprint))
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}) {
			var value []byte
			rest, err := asn1.Unmarshal(extension.Value, &value)
			if err != nil || len(rest) != 0 || !extension.Critical || !bytes.Equal(value, digest[:]) {
				return fmt.Errorf("invalid acmeIdentifier extension")
			}
			return nil
		}
	}
	return fmt.Errorf("acmeIdentifier extension missing")
}

// A child created with 0700 is required: on HarmonyOS Go's testing temporary
// parent may be 0777, and hmdfs ignores chmod altogether.
func privateTestDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("test requires a real private filesystem: %v %v", info, err)
	}
	return path
}

func providerServer(t *testing.T, provider *Provider) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upgrader := websocket.Upgrader{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		connection, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		for {
			kind, payload, err := connection.ReadMessage()
			if err != nil {
				return
			}
			if err := connection.WriteMessage(kind, payload); err != nil {
				return
			}
		}
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(tls.NewListener(listener, provider.TLSConfig())) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-done:
			if err != http.ErrServerClosed {
				t.Errorf("TLS server: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("TLS server did not close")
		}
	})
	return listener.Addr().String()
}

func dialCertificate(address, domain string, roots *x509.CertPool, protocols ...string) (*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", address, &tls.Config{ServerName: domain, RootCAs: roots, NextProtos: protocols, MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != "http/1.1" {
		return nil, fmt.Errorf("unexpected ALPN %q", conn.ConnectionState().NegotiatedProtocol)
	}
	return conn.ConnectionState().PeerCertificates[0], nil
}

func testOptions(ca *localCA, cache string) Options {
	return Options{ACMEDomain: testDomain, ACMECacheDir: cache, ACMEDirectoryURL: ca.endpoint("/directory"), ACMEAcceptTOS: true}
}

func TestACMEInitialIssueChallengeAndRestartCache(t *testing.T) {
	ca := newLocalCA(t)
	cache := privateTestDir(t)
	var eventsMu sync.Mutex
	var events []Event
	opts := testOptions(ca, cache)
	opts.Log = func(event Event) { eventsMu.Lock(); events = append(events, event); eventsMu.Unlock() }
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	address := providerServer(t, p)
	ca.setAddress(address)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := p.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	leaf, err := dialCertificate(address, testDomain, ca.roots, "h2", "http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	if ca.issued.Load() != 1 || ca.challenges.Load() != 1 || ca.httpAttempts.Load() != 0 {
		t.Fatalf("issued=%d TLS challenges=%d HTTP attempts=%d", ca.issued.Load(), ca.challenges.Load(), ca.httpAttempts.Load())
	}
	requests := ca.requests.Load()
	for _, protocols := range [][]string{{"http/1.1"}, {acme.ALPNProto}} {
		if conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{ServerName: "unknown.example.org", InsecureSkipVerify: true, NextProtos: protocols}); err == nil {
			conn.Close()
			t.Fatal("unknown SNI accepted")
		}
	}
	if ca.requests.Load() != requests {
		t.Fatal("unknown SNI contacted ACME")
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(cache, entry.Name()))
		if err != nil || checkFile(info) != nil {
			t.Fatalf("unsafe cache entry %q: %v", entry.Name(), err)
		}
	}
	if _, err := os.Stat(filepath.Join(cache, "acme_account+key")); err != nil {
		t.Fatalf("persistent account key missing: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Ensure(context.Background()); err != ErrClosed {
		t.Fatalf("Ensure after Close = %v", err)
	}
	// The same directory endpoint stays configured but is now unavailable.
	ca.server.Close()
	p2, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p2.Close() })
	address2 := providerServer(t, p2)
	cached, err := dialCertificate(address2, testDomain, ca.roots, "http/1.1")
	if err != nil {
		t.Fatalf("restart must work with CA offline: %v", err)
	}
	if !bytes.Equal(cached.Raw, leaf.Raw) {
		t.Fatal("restart replaced cached certificate")
	}
	if ca.requests.Load() != requests {
		t.Fatal("restart contacted ACME instead of reusing certificate")
	}
	eventsMu.Lock()
	defer eventsMu.Unlock()
	stored, served := false, false
	for _, event := range events {
		if event.Domain != testDomain {
			t.Fatalf("invalid event domain: %+v", event)
		}
		stored = stored || event.Kind == "certificate_stored"
		served = served || event.Kind == "certificate_served"
	}
	if !stored || !served {
		t.Fatalf("missing certificate status events: %+v", events)
	}
	t.Logf("local ACME: initial issue=%d, verified TLS-ALPN challenges=%d, restart used identical certificate with CA offline", ca.issued.Load(), ca.challenges.Load())
}

func TestACMEAutomaticRenewalOnSameProvider(t *testing.T) {
	ca := newLocalCA(t)
	gate := make(chan struct{})
	ca.finalizeGate = gate
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(gate) }) })
	cache := privateTestDir(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seedDER, err := ca.sign(&key.PublicKey, time.Now().Add(5*time.Minute), 7)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	seedPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	seedPEM = append(seedPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: seedDER})...)
	seedPEM = append(seedPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw})...)
	if err := os.WriteFile(filepath.Join(cache, testDomain), seedPEM, 0600); err != nil {
		t.Fatal(err)
	}
	stored := make(chan Event, 4)
	opts := testOptions(ca, cache)
	opts.Log = func(event Event) {
		if event.Kind == "certificate_stored" && event.NotAfter.After(time.Now().Add(24*time.Hour)) {
			select {
			case stored <- event:
			default:
			}
		}
	}
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	address := providerServer(t, p)
	ca.setAddress(address)
	first, err := dialCertificate(address, testDomain, ca.roots, "http/1.1")
	if err != nil || !bytes.Equal(first.Raw, seedDER) {
		t.Fatalf("initial cached seed certificate: %v", err)
	}
	// This verified WSS connection spans the automatic certificate replacement.
	// Only new TLS handshakes should see the renewed certificate.
	wsDialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig:  &tls.Config{RootCAs: ca.roots, ServerName: testDomain, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	ws, response, err := wsDialer.Dial("wss://"+testDomain+"/ws", nil)
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		t.Fatalf("WSS before renewal: %v", err)
	}
	defer ws.Close()
	wsTLS := ws.UnderlyingConn().(*tls.Conn)
	if !bytes.Equal(wsTLS.ConnectionState().PeerCertificates[0].Raw, seedDER) {
		t.Fatal("WSS did not start with original cached certificate")
	}
	echo := func(message string) {
		t.Helper()
		if err := ws.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := ws.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			t.Fatalf("existing WSS write: %v", err)
		}
		if err := ws.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		kind, payload, err := ws.ReadMessage()
		if err != nil || kind != websocket.TextMessage || string(payload) != message {
			t.Fatalf("existing WSS echo: %q %v", payload, err)
		}
	}
	echo("before renewal")
	select {
	case <-ca.finalizeHit:
	case <-time.After(15 * time.Second):
		t.Fatal("autocert did not start automatic renewal")
	}
	// Renewal is deliberately blocked at finalization. Concurrent handshakes
	// continue using the existing valid certificate without a provider restart.
	for range 3 {
		current, err := dialCertificate(address, testDomain, ca.roots, "http/1.1")
		if err != nil || !bytes.Equal(current.Raw, seedDER) {
			t.Fatalf("valid certificate lost while renewal pending: %v", err)
		}
	}
	release.Do(func() { close(gate) })
	select {
	case <-stored:
	case <-time.After(15 * time.Second):
		t.Fatal("renewed certificate not persisted")
	}
	// Cache persistence occurs just before upstream updates its in-memory state.
	deadline := time.Now().Add(5 * time.Second)
	var renewed *x509.Certificate
	for time.Now().Before(deadline) {
		renewed, err = dialCertificate(address, testDomain, ca.roots, "http/1.1")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(renewed.Raw, seedDER) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if renewed == nil || bytes.Equal(renewed.Raw, seedDER) || renewed.NotAfter.Before(time.Now().Add(80*24*time.Hour)) {
		t.Fatal("same provider did not serve renewed certificate")
	}
	if ca.issued.Load() != 1 || ca.challenges.Load() != 1 || ca.httpAttempts.Load() != 0 {
		t.Fatalf("unexpected renewal traffic: issued=%d TLS=%d HTTP=%d", ca.issued.Load(), ca.challenges.Load(), ca.httpAttempts.Load())
	}
	cached, err := os.ReadFile(filepath.Join(cache, testDomain))
	if err != nil {
		t.Fatal(err)
	}
	persisted, ok := cachedCertificate(cached)
	if !ok || !bytes.Equal(persisted.Raw, renewed.Raw) {
		t.Fatal("renewed certificate missing from cache")
	}
	echo("after renewal on the same WSS connection")
	if !bytes.Equal(wsTLS.ConnectionState().PeerCertificates[0].Raw, seedDER) {
		t.Fatal("existing WSS TLS session unexpectedly replaced")
	}
	t.Logf("same provider renewed serial 7 to %s, verified real TLS-ALPN, persisted replacement, and existing verified WSS connection kept echoing", renewed.SerialNumber)
}

func TestACMERenewalFailureKeepsValidCertificate(t *testing.T) {
	ca := newLocalCA(t)
	ca.failFinalize = true
	cache := privateTestDir(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seedDER, err := ca.sign(&key.PublicKey, time.Now().Add(5*time.Minute), 9)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	seedPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	seedPEM = append(seedPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: seedDER})...)
	seedPEM = append(seedPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw})...)
	if err := os.WriteFile(filepath.Join(cache, testDomain), seedPEM, 0600); err != nil {
		t.Fatal(err)
	}
	failure := make(chan struct{}, 1)
	opts := testOptions(ca, cache)
	opts.Log = func(event Event) {
		if event.Kind == "acme_error" && ca.finalizeFailed.Load() {
			select {
			case failure <- struct{}{}:
			default:
			}
		}
	}
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	address := providerServer(t, p)
	ca.setAddress(address)
	first, err := dialCertificate(address, testDomain, ca.roots, "http/1.1")
	if err != nil || !bytes.Equal(first.Raw, seedDER) {
		t.Fatalf("initial seed: %v", err)
	}
	select {
	case <-failure:
	case <-time.After(15 * time.Second):
		t.Fatal("mock CA did not reject automatic renewal")
	}
	for range 3 {
		leaf, err := dialCertificate(address, testDomain, ca.roots, "http/1.1")
		if err != nil || !bytes.Equal(leaf.Raw, seedDER) {
			t.Fatalf("renewal failure discarded valid certificate: %v", err)
		}
	}
	persisted, err := os.ReadFile(filepath.Join(cache, testDomain))
	if err != nil || !bytes.Equal(persisted, seedPEM) {
		t.Fatalf("renewal failure modified valid cache: %v", err)
	}
	if ca.issued.Load() != 0 || ca.challenges.Load() != 1 {
		t.Fatalf("unexpected failure scenario: issued=%d challenges=%d", ca.issued.Load(), ca.challenges.Load())
	}
	t.Log("local CA rejected automatic renewal; original valid serial 9 remained available and unchanged in cache")
}
