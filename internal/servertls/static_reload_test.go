package servertls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type staticFixture struct {
	cert, key []byte
	private   *ecdsa.PrivateKey
}

func makeStaticFixture(t *testing.T, ca *localCA, serial int64, before, after time.Time) staticFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{testDomain},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: before, NotAfter: after,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.root, &key.PublicKey, ca.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw})...)
	return staticFixture{cert: chain, key: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), private: key}
}

func replaceStaticFile(t *testing.T, name string, data []byte) {
	t.Helper()
	f, err := os.CreateTemp(filepath.Dir(name), ".replacement-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.Name(), name); err != nil {
		t.Fatal(err)
	}
}

type staticEvents struct {
	mu      sync.Mutex
	events  []Event
	changed chan struct{}
}

func (s *staticEvents) log(event Event) {
	s.mu.Lock()
	s.events = append(s.events, event)
	s.mu.Unlock()
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

func (s *staticEvents) count(kind string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, event := range s.events {
		if kind == "" || event.Kind == kind {
			count++
		}
	}
	return count
}

func (s *staticEvents) wait(t *testing.T, kind string, count int) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for s.count(kind) < count {
		select {
		case <-s.changed:
		case <-timer.C:
			t.Fatalf("waiting for %s event %d; got %d", kind, count, s.count(kind))
		}
	}
}

func TestStaticReloadIPTLSAndWSSLastGood(t *testing.T) {
	ca := newLocalCA(t)
	now := time.Now()
	first := makeStaticFixture(t, ca, 101, now.Add(-time.Hour), now.Add(24*time.Hour))
	second := makeStaticFixture(t, ca, 102, now.Add(-time.Hour), now.Add(48*time.Hour))
	third := makeStaticFixture(t, ca, 103, now.Add(-time.Hour), now.Add(72*time.Hour))
	base := privateTestDir(t)
	certPath, keyPath := filepath.Join(base, "certificate.pem"), filepath.Join(base, "private.key")
	replaceStaticFile(t, certPath, first.cert)
	replaceStaticFile(t, keyPath, first.key)
	events := &staticEvents{changed: make(chan struct{}, 64)}
	const interval = 15 * time.Millisecond
	p, err := New(Options{CertFile: certPath, KeyFile: keyPath, ReloadInterval: interval, Log: events.log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if len(p.TLSConfig().Certificates) != 0 || p.TLSConfig().GetCertificate == nil {
		t.Fatal("IP clients must always use GetCertificate, without a fixed certificate fallback")
	}
	callback := p.config.GetCertificate
	var withoutSNI atomic.Bool
	p.config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" {
			withoutSNI.Store(true)
		}
		return callback(hello)
	}
	address := providerServer(t, p)
	check := func(t *testing.T, serial int64) {
		t.Helper()
		leaf, err := dialCertificate(address, "127.0.0.1", ca.roots, "http/1.1")
		if err != nil || leaf.SerialNumber.Int64() != serial {
			t.Fatalf("verified IP TLS serial %d: leaf=%v error=%v", serial, leaf, err)
		}
	}
	check(t, 101)
	if !withoutSNI.Load() {
		t.Fatal("IP TLS test did not exercise a ClientHello without SNI")
	}
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{ServerName: "127.0.0.1", RootCAs: ca.roots, MinVersion: tls.VersionTLS12}, HandshakeTimeout: 5 * time.Second}
	ws, _, err := dialer.Dial("wss://"+address+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	connection := ws.UnderlyingConn().(*tls.Conn)
	if state := connection.ConnectionState(); len(state.VerifiedChains) == 0 || state.PeerCertificates[0].SerialNumber.Int64() != 101 {
		t.Fatal("WSS was not verified against the original IP certificate")
	}
	echo := func(t *testing.T, message string) {
		t.Helper()
		if err := ws.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := ws.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			t.Fatal(err)
		}
		if err := ws.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		kind, payload, err := ws.ReadMessage()
		if err != nil || kind != websocket.TextMessage || string(payload) != message {
			t.Fatalf("existing WSS echo %q: type=%d payload=%q error=%v", message, kind, payload, err)
		}
	}
	echo(t, "before replacement")

	// A CA installer can replace the two files separately. The new leaf with
	// the old key must not displace the valid certificate already in memory.
	replaceStaticFile(t, certPath, second.cert)
	events.wait(t, "certificate_reload_error", 1)
	check(t, 101)
	echo(t, "while pair mismatches")
	errorCount := events.count("certificate_reload_error")
	time.Sleep(5 * interval)
	if events.count("certificate_reload_error") != errorCount {
		t.Fatal("a repeated broken pair flooded reload error events")
	}
	replaceStaticFile(t, keyPath, second.key)
	events.wait(t, "certificate_reloaded", 1)
	check(t, 102)
	echo(t, "after replacement")
	if connection.ConnectionState().PeerCertificates[0].SerialNumber.Int64() != 101 {
		t.Fatal("existing WSS connection was replaced or renegotiated")
	}

	badAndRestore := func(t *testing.T, breakFiles, restoreFiles func()) {
		t.Helper()
		errors := events.count("certificate_reload_error")
		recoveries := events.count("certificate_reload_recovered")
		breakFiles()
		events.wait(t, "certificate_reload_error", errors+1)
		check(t, 102)
		echo(t, "last-good during bad replacement")
		restoreFiles()
		events.wait(t, "certificate_reload_recovered", recoveries+1)
		check(t, 102)
	}
	t.Run("unsafe-private-permissions", func(t *testing.T) {
		badAndRestore(t, func() {
			if err := os.Chmod(keyPath, 0644); err != nil {
				t.Fatal(err)
			}
			if info, err := os.Stat(keyPath); err != nil || info.Mode().Perm() != 0644 {
				t.Fatalf("unsafe permission fixture was masked: %v %v", info, err)
			}
		}, func() {
			if err := os.Chmod(keyPath, 0600); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("missing-certificate", func(t *testing.T) {
		saved := certPath + ".saved"
		badAndRestore(t, func() {
			if err := os.Rename(certPath, saved); err != nil {
				t.Fatal(err)
			}
		}, func() {
			if err := os.Rename(saved, certPath); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("malformed-certificate", func(t *testing.T) {
		badAndRestore(t, func() { replaceStaticFile(t, certPath, []byte("not a certificate")) },
			func() { replaceStaticFile(t, certPath, second.cert) })
	})
	t.Run("symbolic-link-key", func(t *testing.T) {
		saved := keyPath + ".saved"
		badAndRestore(t, func() {
			if err := os.Rename(keyPath, saved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(saved, keyPath); err != nil {
				t.Fatal(err)
			}
		}, func() {
			if err := os.Remove(keyPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(saved, keyPath); err != nil {
				t.Fatal(err)
			}
		})
	})

	// Re-encoding the matching key and re-exporting the same DER chain must
	// not announce another certificate generation.
	pkcs8, err := x509.MarshalPKCS8PrivateKey(second.private)
	if err != nil {
		t.Fatal(err)
	}
	replaceStaticFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	replaceStaticFile(t, certPath, append([]byte("\n"), second.cert...))
	time.Sleep(5 * interval)
	check(t, 102)
	if events.count("certificate_loaded") != 1 || events.count("certificate_reloaded") != 1 {
		t.Fatal("an unchanged certificate/key pair produced additional load events")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	closedCount := events.count("")
	replaceStaticFile(t, certPath, third.cert)
	replaceStaticFile(t, keyPath, third.key)
	time.Sleep(5 * interval)
	if events.count("") != closedCount || p.staticCert.Load().Leaf.SerialNumber.Int64() != 102 {
		t.Fatal("closed provider continued loading replacement certificates")
	}
	if _, err := p.TLSConfig().GetCertificate(&tls.ClientHelloInfo{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed no-SNI callback: %v", err)
	}
	if _, err := dialCertificate(address, "127.0.0.1", ca.roots, "http/1.1"); err == nil {
		t.Fatal("closed provider accepted a new IP TLS handshake")
	}
	echo(t, "existing WSS after provider close")
	if ca.requests.Load() != 0 {
		t.Fatal("file reload unexpectedly contacted the CA")
	}
}

func TestStaticRejectsInvalidValidityAndChain(t *testing.T) {
	ca := newLocalCA(t)
	other := newLocalCA(t)
	now := time.Now()
	good := makeStaticFixture(t, ca, 201, now.Add(-time.Hour), now.Add(24*time.Hour))
	expired := makeStaticFixture(t, ca, 202, now.Add(-24*time.Hour), now.Add(-time.Hour))
	future := makeStaticFixture(t, ca, 203, now.Add(time.Hour), now.Add(24*time.Hour))
	leaf, _ := pem.Decode(good.cert)
	cases := []struct {
		name string
		pair staticFixture
	}{
		{"expired", expired},
		{"not-yet-valid", future},
		{"malformed-chain", staticFixture{cert: append(pem.EncodeToMemory(leaf), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")})...), key: good.key}},
		{"unrelated-chain", staticFixture{cert: append(pem.EncodeToMemory(leaf), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.root.Raw})...), key: good.key}},
		{"mismatched-key", staticFixture{cert: good.cert, key: expired.key}},
		{"malformed-key", staticFixture{cert: good.cert, key: []byte("invalid private key")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := privateTestDir(t)
			certPath, keyPath := filepath.Join(base, "cert.pem"), filepath.Join(base, "key.pem")
			replaceStaticFile(t, certPath, tc.pair.cert)
			replaceStaticFile(t, keyPath, tc.pair.key)
			if p, err := New(Options{CertFile: certPath, KeyFile: keyPath}); err == nil {
				p.Close()
				t.Fatal("unsafe initial certificate pair was accepted")
			}
		})
	}
}

func TestStaticFileVersionDetectsInPlaceWrite(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "same-inode")
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Linux can reuse its timestamp within a kernel clock tick. Make this
	// deliberate write occur in a later tick before restoring the old mtime.
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(path, []byte("after!"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("fixture did not preserve inode, length and mtime")
	}
	if sameStaticFileVersion(before, after) {
		t.Fatal("in-place write with restored mtime was missed")
	}
	data, err := readStaticFile(path, true)
	if err != nil || !bytes.Equal(data, []byte("after!")) {
		t.Fatalf("a stable private file failed to read: %q %v", data, err)
	}
}

func TestStaticCloseWaitsForReloadWorker(t *testing.T) {
	ca := newLocalCA(t)
	now := time.Now()
	pair := makeStaticFixture(t, ca, 301, now.Add(-time.Hour), now.Add(time.Hour))
	base := privateTestDir(t)
	certPath, keyPath := filepath.Join(base, "cert.pem"), filepath.Join(base, "key.pem")
	replaceStaticFile(t, certPath, pair.cert)
	replaceStaticFile(t, keyPath, pair.key)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	p, err := New(Options{CertFile: certPath, KeyFile: keyPath, ReloadInterval: 10 * time.Millisecond, Log: func(event Event) {
		if event.Kind == "certificate_reload_error" {
			close(entered)
			<-release
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); _ = p.Close() })
	replaceStaticFile(t, certPath, []byte("broken replacement"))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("reload worker never observed replacement")
	}
	closed := make(chan error, 1)
	go func() { closed <- p.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before reload worker ended: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not join the released reload worker")
	}
	select {
	case <-p.reloadDone:
	default:
		t.Fatal("reload worker remains active after Close")
	}
}
