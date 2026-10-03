package servertls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func TestValidateCombinationsAndValues(t *testing.T) {
	valid := Options{ACMEDomain: testDomain, ACMECacheDir: "not-created", ACMEAcceptTOS: true}
	cases := []struct {
		name  string
		opts  Options
		valid bool
	}{
		{"plaintext", Options{}, true},
		{"static-no-filesystem-inspection", Options{CertFile: "missing-cert", KeyFile: "missing-key"}, true},
		{"static-reload-positive", Options{CertFile: "missing-cert", KeyFile: "missing-key", ReloadInterval: time.Second}, true},
		{"negative-reload", Options{CertFile: "missing-cert", KeyFile: "missing-key", ReloadInterval: -time.Second}, false},
		{"plaintext-reload", Options{ReloadInterval: time.Second}, false},
		{"acme-reload", func() Options { o := valid; o.ReloadInterval = time.Second; return o }(), false},
		{"acme-no-email", valid, true},
		{"uppercase-and-trailing-dot", func() Options { o := valid; o.ACMEDomain = "BROKER.EXAMPLE.ORG."; return o }(), true},
		{"idn", func() Options { o := valid; o.ACMEDomain = "例子.example.org"; return o }(), true},
		{"email", func() Options { o := valid; o.ACMEEmail = "admin@example.org"; return o }(), true},
		{"https-directory", func() Options { o := valid; o.ACMEDirectoryURL = "https://ca.example.org/directory"; return o }(), true},
		{"loopback-http", func() Options { o := valid; o.ACMEDirectoryURL = "http://127.0.0.1:12345/directory"; return o }(), true},
		{"loopback-ipv6", func() Options { o := valid; o.ACMEDirectoryURL = "http://[::1]:12345/directory"; return o }(), true},
		{"cert-only", Options{CertFile: "cert"}, false},
		{"key-only", Options{KeyFile: "key"}, false},
		{"email-without-domain", Options{ACMEEmail: "admin@example.org"}, false},
		{"cache-without-domain", Options{ACMECacheDir: "cache"}, false},
		{"directory-without-domain", Options{ACMEDirectoryURL: "https://ca.example.org/directory"}, false},
		{"tos-without-domain", Options{ACMEAcceptTOS: true}, false},
		{"acme-with-static", func() Options { o := valid; o.CertFile = "cert"; o.KeyFile = "key"; return o }(), false},
		{"tos-required", func() Options { o := valid; o.ACMEAcceptTOS = false; return o }(), false},
		{"cache-required", func() Options { o := valid; o.ACMECacheDir = ""; return o }(), false},
		{"display-email", func() Options { o := valid; o.ACMEEmail = "Admin <admin@example.org>"; return o }(), false},
		{"bad-email", func() Options { o := valid; o.ACMEEmail = "not-email"; return o }(), false},
		{"remote-http", func() Options { o := valid; o.ACMEDirectoryURL = "http://ca.example.org/directory"; return o }(), false},
		{"userinfo", func() Options {
			o := valid
			o.ACMEDirectoryURL = "https://user:secret@ca.example.org/directory"
			return o
		}(), false},
		{"fragment", func() Options { o := valid; o.ACMEDirectoryURL = "https://ca.example.org/directory#fragment"; return o }(), false},
		{"bad-url", func() Options { o := valid; o.ACMEDirectoryURL = "https://[broken"; return o }(), false},
		{"bad-port", func() Options { o := valid; o.ACMEDirectoryURL = "https://ca.example.org:65536/directory"; return o }(), false},
	}
	for _, domain := range []string{"localhost", "127.0.0.1", "::1", "*.example.org", "https://example.org", "example.org:443", "example.org/path", " example.org", "a..example.org", "-a.example.org", "a-.example.org", strings.Repeat("a", 64) + ".example.org"} {
		o := valid
		o.ACMEDomain = domain
		cases = append(cases, struct {
			name  string
			opts  Options
			valid bool
		}{"domain-" + domain, o, false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(tc.opts); (err == nil) != tc.valid {
				t.Fatalf("Validate = %v; valid=%v", err, tc.valid)
			}
		})
	}
	base := privateTestDir(t)
	valid.ACMECacheDir = filepath.Join(base, "must-not-exist")
	if err := Validate(valid); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(valid.ACMECacheDir); !os.IsNotExist(err) {
		t.Fatalf("Validate created state: %v", err)
	}
}

func TestProviderDisabledAndDefaultACME(t *testing.T) {
	p, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p.TLSConfig() != nil || p.Ensure(context.Background()) != nil {
		t.Fatal("plaintext unexpectedly enabled TLS")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(privateTestDir(t), "new-cache")
	p, err = New(Options{ACMEDomain: "BROKER.EXAMPLE.ORG.", ACMEAcceptTOS: true, ACMECacheDir: cache})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.manager.Client.DirectoryURL != autocert.DefaultACMEDirectory || p.manager.Email != "" {
		t.Fatal("unexpected CA defaults")
	}
	if p.domain != testDomain || p.TLSConfig().MinVersion != tls.VersionTLS12 {
		t.Fatal("domain or TLS version not normalized")
	}
	if protocols := p.TLSConfig().NextProtos; len(protocols) != 2 || protocols[0] != "http/1.1" || protocols[1] != acme.ALPNProto {
		t.Fatalf("wrong ALPN protocols: %v", protocols)
	}
	entries, err := os.ReadDir(cache)
	if err != nil || len(entries) != 0 {
		t.Fatalf("New must not contact CA or generate keys: %v %v", entries, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p.Ensure(ctx) != context.Canceled {
		t.Fatal("Ensure ignored prior cancellation")
	}
}

func TestStaticTLSAndPrivateKeyValidation(t *testing.T) {
	ca := newLocalCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := ca.sign(&key.PublicKey, time.Now().Add(24*time.Hour), 4)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	base := privateTestDir(t)
	certPath, keyPath := filepath.Join(base, "cert.pem"), filepath.Join(base, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	opts := Options{CertFile: certPath, KeyFile: keyPath}
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	address := providerServer(t, p)
	leaf, err := dialCertificate(address, testDomain, ca.roots, "h2", "http/1.1")
	if err != nil || !bytes.Equal(leaf.Raw, der) {
		t.Fatalf("static handshake: %v", err)
	}
	if err := p.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if bad, err := New(opts); err == nil {
		bad.Close()
		t.Fatal("public private-key permissions accepted")
	}
	if err := os.Chmod(keyPath, 0400); err != nil {
		t.Fatal(err)
	}
	readOnly, err := New(opts)
	if err != nil {
		t.Fatalf("0400 key rejected: %v", err)
	}
	readOnly.Close()
	link := filepath.Join(base, "key-link.pem")
	if err := os.Symlink(keyPath, link); err != nil {
		t.Fatal(err)
	}
	opts.KeyFile = link
	if bad, err := New(opts); err == nil {
		bad.Close()
		t.Fatal("symbolic-link private key accepted")
	}
}

func TestEnsureCancellationAndCloseCancelsIssuance(t *testing.T) {
	ca := newLocalCA(t)
	gate := make(chan struct{})
	ca.finalizeGate = gate
	var released bool
	t.Cleanup(func() {
		if !released {
			close(gate)
		}
	})
	p, err := New(testOptions(ca, privateTestDir(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	address := providerServer(t, p)
	ca.setAddress(address)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- p.Ensure(ctx) }()
	select {
	case <-ca.finalizeHit:
	case <-time.After(15 * time.Second):
		t.Fatal("issuance never reached local CA")
	}
	cancel()
	select {
	case err := <-result:
		if err != context.Canceled {
			t.Fatalf("Ensure = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Ensure ignored cancellation")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	close(gate)
	released = true
	if _, err := p.getCertificate(&tls.ClientHelloInfo{ServerName: testDomain}); err != ErrClosed {
		t.Fatalf("certificate after Close = %v", err)
	}
}
