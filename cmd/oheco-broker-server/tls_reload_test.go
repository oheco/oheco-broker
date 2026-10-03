package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise Run's shared provider integration with an IP client that sends no SNI.
// Updating servertls alone used to leave this entry point on a startup snapshot.
func TestStandaloneStaticCertificateReloadWithoutSNI(t *testing.T) {
	cfg := testConfig(t)
	dir := privateTestDir(t)
	cfg.TLSCertFile, cfg.TLSKeyFile, _ = fixtureCertificate(t, dir, 1)
	cfg.TLSReloadInterval = 20 * time.Millisecond
	replacement := filepath.Join(dir, "replacement")
	if err := os.Mkdir(replacement, 0700); err != nil {
		t.Fatal(err)
	}
	newCert, newKey, roots := fixtureCertificate(t, replacement, 2)
	oldPEM, err := os.ReadFile(cfg.TLSCertFile)
	if err != nil || !roots.AppendCertsFromPEM(oldPEM) {
		t.Fatalf("trust both fixture certificates: %v", err)
	}
	ready, _ := startFixture(t, cfg)
	address := strings.TrimPrefix(ready.API, "https://")
	serial := func() int64 {
		t.Helper()
		conn, err := tls.Dial("tcp", address, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
	}
	if got := serial(); got != 1 {
		t.Fatalf("initial serial = %d", got)
	}
	// A renewer replaces the certificate before its matching private key.
	if err := os.Rename(newCert, cfg.TLSCertFile); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * cfg.TLSReloadInterval)
	if got := serial(); got != 1 {
		t.Fatalf("mismatched pair replaced last-good serial: %d", got)
	}
	if err := os.Rename(newKey, cfg.TLSKeyFile); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if serial() == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("standalone server did not adopt replacement certificate")
}
