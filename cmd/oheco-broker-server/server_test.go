package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oheco/oheco-broker/internal/control"
	"github.com/pion/stun/v3"
)

func fixtureCertificate(t *testing.T, dir string, serials ...int64) (certPath, keyPath string, roots *x509.CertPool) {
	t.Helper()
	serial := int64(1)
	if len(serials) != 0 {
		serial = serials[0]
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "isolated standalone HTTPS fixture"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("fixture certificate could not be trusted")
	}
	return certPath, keyPath, roots
}

type readyWriter struct{ ch chan ReadyEvent }

func (w readyWriter) Write(p []byte) (int, error) {
	var event ReadyEvent
	if err := json.Unmarshal(p, &event); err != nil {
		return 0, err
	}
	w.ch <- event
	return len(p), nil
}

func startFixture(t *testing.T, cfg Config) (ReadyEvent, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	readyCh := make(chan ReadyEvent, 1)
	done := make(chan struct{})
	var runErr error
	go func() {
		runErr = Run(ctx, cfg, readyWriter{ch: readyCh})
		close(done)
	}()
	stop := func() {
		cancel()
		select {
		case <-done:
			if runErr != nil {
				t.Errorf("fixture Run shutdown: %v", runErr)
			}
		case <-time.After(15 * time.Second):
			t.Error("fixture did not stop gracefully")
		}
	}
	t.Cleanup(stop)
	select {
	case event := <-readyCh:
		return event, stop
	case <-done:
		t.Fatalf("fixture failed before readiness: %v", runErr)
	case <-time.After(10 * time.Second):
		t.Fatal("fixture readiness timed out")
	}
	return ReadyEvent{}, stop
}

func requestJSON(t *testing.T, client *http.Client, api, method, path, token string, payload any, want int) map[string]any {
	t.Helper()
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, api+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatal("fixture request was not protected by TLS 1.2+")
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if resp.StatusCode != want {
		t.Fatalf("%s %s status=%d want=%d body=%v", method, path, resp.StatusCode, want, out)
	}
	return out
}

func TestLocalHTTPSManagementSTUNAndGracefulClose(t *testing.T) {
	dir := privateTestDir(t)
	cert, key, roots := fixtureCertificate(t, dir)
	cfg := DefaultConfig()
	cfg.ListenAddr, cfg.DBPath, cfg.AdminToken = "127.0.0.1:0", filepath.Join(dir, "control.sqlite"), testAdminToken
	cfg.TLSCertFile, cfg.TLSKeyFile = cert, key
	cfg.TURNListenAddr, cfg.TURNPublicIP = "127.0.0.1:0", "127.0.0.1"
	event, stop := startFixture(t, cfg)
	if event.Event != "server_ready" || event.Version != Version || !strings.HasPrefix(event.API, "https://127.0.0.1:") {
		t.Fatalf("invalid readiness: %+v", event)
	}
	if strings.HasSuffix(event.API, ":0") || strings.HasSuffix(event.TURN, ":0") || event.TURN == "" || event.TURN != event.TURNAdvertised {
		t.Fatalf("readiness lacks actual bound endpoints: %+v", event)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	requestJSON(t, client, event.API, "GET", "/v1/admin/settings", "", nil, http.StatusUnauthorized)
	settings := requestJSON(t, client, event.API, "GET", "/v1/admin/settings", testAdminToken, nil, http.StatusOK)
	if settings["registration_policy"] != "approval" {
		t.Fatalf("standalone registration default not applied: %v", settings)
	}
	registration := requestJSON(t, client, event.API, "POST", "/v1/tenants/register", "", map[string]any{
		"name": "standalone-fixture", "email": "standalone@example.invalid", "password": "standalone-fixture-password",
	}, http.StatusCreated)
	tenant := registration["tenant"].(map[string]any)
	if tenant["status"] != "pending" || tenant["relay_enabled"] != false {
		t.Fatalf("registration unexpectedly authorized relay: %v", tenant)
	}
	accountToken := registration["token"].(string)
	capabilities := requestJSON(t, client, event.API, "GET", "/v1/capabilities", accountToken, nil, http.StatusOK)
	if capabilities["turn_available"] != true || capabilities["turn_address"] != event.TURNAdvertised || capabilities["relay_enabled"] != false {
		t.Fatalf("backend capabilities differ from actual readiness: %v", capabilities)
	}
	requestJSON(t, client, event.API, "POST", "/v1/admin/tenants/"+tenant["id"].(string)+"/approve", testAdminToken, nil, http.StatusOK)
	broker := requestJSON(t, client, event.API, "POST", "/v1/brokers", accountToken, map[string]string{"name": "isolated-broker"}, http.StatusCreated)
	if broker["device_token"] == "" || broker["broker"] == nil {
		t.Fatal("real backend broker registration failed")
	}
	requestJSON(t, client, event.API, "PATCH", "/v1/admin/settings", testAdminToken, map[string]string{"registration_policy": "closed"}, http.StatusOK)
	checkSTUNBinding(t, event.TURN)

	transport.CloseIdleConnections()
	stop()
	apiSocket := strings.TrimPrefix(event.API, "https://")
	if conn, err := net.DialTimeout("tcp", apiSocket, time.Second); err == nil {
		conn.Close()
		t.Error("API listener survived graceful shutdown")
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", event.TURN)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		t.Fatalf("TURN listener survived graceful shutdown: %v", err)
	}
	udp.Close()

	// Reopening the same database confirms HTTP finished before service.Close,
	// SQLite was closed, and persisted administration was not overwritten by the
	// command's default approval policy. This uses the actual control functions.
	backend, err := control.New(control.Config{DBPath: cfg.DBPath, AdminToken: testAdminToken, RegistrationPolicy: "approval"})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	req := httptest.NewRequest("GET", "/v1/admin/settings", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	recorder := httptest.NewRecorder()
	backend.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"registration_policy":"closed"`) {
		t.Fatalf("SQLite settings not persisted: %d %s", recorder.Code, recorder.Body.String())
	}
}

func checkSTUNBinding(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.Dial("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := conn.Write(message.Raw); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("real STUN binding response: %v", err)
	}
	response := &stun.Message{Raw: buf[:n]}
	if err := response.Decode(); err != nil {
		t.Fatal(err)
	}
	if response.Type != stun.BindingSuccess || response.TransactionID != message.TransactionID {
		t.Fatalf("unexpected STUN response: %s", response)
	}
	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(response); err != nil || !mapped.IP.IsLoopback() || mapped.Port == 0 {
		t.Fatalf("incorrect STUN mapped address: %v err=%v", mapped, err)
	}
}

func TestReadinessWriteFailureClosesService(t *testing.T) {
	dir := privateTestDir(t)
	cfg := DefaultConfig()
	cfg.ListenAddr, cfg.DBPath, cfg.AdminToken = "127.0.0.1:0", filepath.Join(dir, "control.sqlite"), testAdminToken
	cfg.TURNListenAddr = "127.0.0.1:0"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := Run(ctx, cfg, failingWriter{}); err == nil || !strings.Contains(err.Error(), "write readiness") {
		t.Fatalf("readiness write failure ignored: %v", err)
	}
	backend, err := control.New(control.Config{DBPath: cfg.DBPath, AdminToken: testAdminToken})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestCanceledContextDoesNotCreateState(t *testing.T) {
	cfg := testConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	if err := Run(ctx, cfg, &output); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(cfg.DBPath)); !os.IsNotExist(err) {
		t.Fatalf("canceled Run created state: %v", err)
	}
}
