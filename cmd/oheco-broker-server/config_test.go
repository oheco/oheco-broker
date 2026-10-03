package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const testAdminToken = "standalone-local-test-admin-never-production"

// t.TempDir's numbered child can be 0777 on OHOS. Always create a separate
// 0700 child for secret files and SQLite; never put them on HOME/hmdfs.
func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("fixture requires a permissions-capable private TMPDIR: info=%v err=%v", info, err)
	}
	return dir
}

func testConfig(t *testing.T) Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.DBPath = filepath.Join(privateTestDir(t), "not-created", "control.sqlite")
	cfg.AdminToken = testAdminToken
	return cfg
}

func TestDefaultsAndVersion(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.RegistrationPolicy != "approval" || cfg.RegistrationRelayEnabled || cfg.TURNAllowLoopback || cfg.TURNListenAddr != "" {
		t.Fatalf("unsafe defaults: %+v", cfg)
	}
	t.Setenv("OHECO_BROKER_ADMIN_TOKEN", "")
	for _, args := range [][]string{{"--version"}, {"--version", "--admin-token-file=/does/not/exist", "--tls-cert=/missing"}} {
		var out, stderr bytes.Buffer
		if err := Execute(context.Background(), args, &out, &stderr); err != nil {
			t.Fatal(err)
		}
		if out.String() != "oheco-broker-server "+Version+"\n" {
			t.Fatalf("unexpected version output %q", out.String())
		}
	}
	var out, stderr bytes.Buffer
	if err := Execute(context.Background(), []string{"--help"}, &out, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "turn-relay-max-port") {
		t.Fatal("missing help flags")
	}
}

func TestInvalidConfigHasNoStartupSideEffects(t *testing.T) {
	cases := []struct {
		name string
		set  func(*Config)
		want string
	}{
		{"api-missing-port", func(c *Config) { c.ListenAddr = "127.0.0.1" }, "--listen"},
		{"api-negative-port", func(c *Config) { c.ListenAddr = "127.0.0.1:-1" }, "numeric port"},
		{"api-overflow-port", func(c *Config) { c.ListenAddr = "127.0.0.1:65536" }, "numeric port"},
		{"api-named-port", func(c *Config) { c.ListenAddr = "127.0.0.1:http" }, "numeric port"},
		{"http-wildcard", func(c *Config) { c.ListenAddr = "0.0.0.0:0" }, "requires --tls-cert"},
		{"http-empty-host", func(c *Config) { c.ListenAddr = ":0" }, "requires --tls-cert"},
		{"http-public", func(c *Config) { c.ListenAddr = "192.0.2.1:0" }, "requires --tls-cert"},
		{"http-ipv6-wildcard", func(c *Config) { c.ListenAddr = "[::]:0" }, "requires --tls-cert"},
		{"api-multicast", func(c *Config) { c.ListenAddr = "224.0.0.1:0" }, "unicast"},
		{"db-empty", func(c *Config) { c.DBPath = "" }, "--db"},
		{"db-dsn", func(c *Config) { c.DBPath = "file:control.sqlite?mode=memory" }, "--db"},
		{"registration", func(c *Config) { c.RegistrationPolicy = "allow" }, "--registration"},
		{"min-overflow", func(c *Config) { c.TURNRelayMinPort = 65536 }, "0..65535"},
		{"max-overflow", func(c *Config) { c.TURNRelayMaxPort = 65536 }, "0..65535"},
		{"min-only", func(c *Config) { c.TURNRelayMinPort = 50000 }, "both be zero"},
		{"max-only", func(c *Config) { c.TURNRelayMaxPort = 50000 }, "both be zero"},
		{"reversed", func(c *Config) { c.TURNRelayMinPort, c.TURNRelayMaxPort = 55000, 50000 }, "ascending"},
		{"turn-options-without-listen", func(c *Config) { c.TURNPublicIP = "127.0.0.1" }, "require --turn-listen"},
		{"turn-port-overflow", func(c *Config) { c.TURNListenAddr = "127.0.0.1:65536" }, "numeric port"},
		{"turn-port-negative", func(c *Config) { c.TURNListenAddr = "127.0.0.1:-1" }, "numeric port"},
		{"turn-wildcard-without-public-ip", func(c *Config) { c.TURNListenAddr = "0.0.0.0:0" }, "--turn-public-ip"},
		{"turn-public-ip-hostname", func(c *Config) { c.TURNListenAddr, c.TURNPublicIP = "127.0.0.1:0", "localhost" }, "--turn-public-ip"},
		{"turn-public-ip-multicast", func(c *Config) { c.TURNListenAddr, c.TURNPublicIP = "127.0.0.1:0", "224.0.0.1" }, "--turn-public-ip"},
		{"turn-public-ip-broadcast", func(c *Config) { c.TURNListenAddr, c.TURNPublicIP = "127.0.0.1:0", "255.255.255.255" }, "--turn-public-ip"},
		{"turn-public-ip-ipv6", func(c *Config) { c.TURNListenAddr, c.TURNPublicIP = "127.0.0.1:0", "::1" }, "--turn-public-ip"},
		{"turn-loopback-on-public-bind", func(c *Config) {
			c.TURNListenAddr, c.TURNPublicIP, c.TURNAllowLoopback = "0.0.0.0:0", "127.0.0.1", true
		}, "only permitted"},
		{"turn-loopback-on-public-advertisement", func(c *Config) {
			c.TURNListenAddr, c.TURNPublicIP, c.TURNAllowLoopback = "127.0.0.1:0", "192.0.2.1", true
		}, "only permitted"},
		{"tls-cert-only", func(c *Config) { c.TLSCertFile = "/missing/cert.pem" }, "provided together"},
		{"tls-key-only", func(c *Config) { c.TLSKeyFile = "/missing/key.pem" }, "provided together"},
		{"tls-both-missing", func(c *Config) { c.TLSCertFile, c.TLSKeyFile = "/missing/cert.pem", "/missing/key.pem" }, "TLS certificate"},
		{"acme-options-without-domain", func(c *Config) { c.ACMECacheDir = "/missing/cache" }, "require an ACME domain"},
		{"acme-no-tos", func(c *Config) { c.ACMEDomain = "broker.example.org" }, "terms of service"},
		{"acme-no-cache", func(c *Config) { c.ACMEDomain, c.ACMEAcceptTOS = "broker.example.org", true }, "cache directory"},
		{"acme-non443", func(c *Config) {
			c.ACMEDomain, c.ACMEAcceptTOS, c.ACMECacheDir = "broker.example.org", true, "/missing/cache"
		}, "port 443"},
		{"acme-static-conflict", func(c *Config) {
			c.ACMEDomain, c.ACMEAcceptTOS, c.ACMECacheDir = "broker.example.org", true, "/missing/cache"
			c.TLSCertFile, c.TLSKeyFile = "/missing/cert", "/missing/key"
		}, "mutually exclusive"},
		{"no-token", func(c *Config) { c.AdminToken = "" }, "single token"},
		{"short-token", func(c *Config) { c.AdminToken = "short" }, "single token"},
		{"token-newline", func(c *Config) { c.AdminToken = "long-token-one\nlong-token-two" }, "single token"},
		{"token-too-large", func(c *Config) { c.AdminToken = strings.Repeat("x", 4097) }, "single token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			originalDB := cfg.DBPath
			tc.set(&cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var output bytes.Buffer
			err := Run(ctx, cfg, &output)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v; want %q", err, tc.want)
			}
			if output.Len() != 0 {
				t.Fatalf("invalid config announced readiness: %s", output.String())
			}
			if _, err := os.Stat(filepath.Dir(originalDB)); !os.IsNotExist(err) {
				t.Fatalf("invalid config created database state: %v", err)
			}
		})
	}
}

func TestUnsignedFlagRejectsNegativeAndOversizePorts(t *testing.T) {
	for _, name := range []string{"--turn-relay-min-port", "--turn-relay-max-port"} {
		for _, port := range []string{"-1", "65536", "4294967296"} {
			t.Run(name+"="+port, func(t *testing.T) {
				cfg := testConfig(t)
				var out, stderr bytes.Buffer
				args := []string{"--db=" + cfg.DBPath, name + "=" + port}
				if err := Execute(context.Background(), args, &out, &stderr); err == nil {
					t.Fatal("invalid port accepted")
				}
				if out.Len() != 0 {
					t.Fatalf("invalid port announced readiness: %s", out.String())
				}
				if _, err := os.Stat(filepath.Dir(cfg.DBPath)); !os.IsNotExist(err) {
					t.Fatalf("invalid port created state: %v", err)
				}
			})
		}
	}
}

func TestValidTURNBoundsAndTLSConfig(t *testing.T) {
	dir := privateTestDir(t)
	cert, key, _ := fixtureCertificate(t, dir)
	cfg := DefaultConfig()
	cfg.ListenAddr = "0.0.0.0:0"
	cfg.DBPath = filepath.Join(dir, "db.sqlite")
	cfg.AdminToken = testAdminToken
	cfg.TLSCertFile, cfg.TLSKeyFile = cert, key
	cfg.TURNListenAddr, cfg.TURNPublicIP = "0.0.0.0:0", "192.0.2.1"
	cfg.TURNRelayMinPort, cfg.TURNRelayMaxPort = 1, 65535
	v, err := validate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v.tls.MinVersion != tls.VersionTLS12 || len(v.tls.Certificates) != 1 {
		t.Fatalf("TLS configuration not prevalidated: %+v", v.tls)
	}
	if v.backend.TURN.RelayMinPort != 1 || v.backend.TURN.RelayMaxPort != 65535 || v.backend.TURN.AllowLoopbackPeers {
		t.Fatalf("TURN port bounds lost: %+v", v.backend.TURN)
	}
	if _, err := os.Stat(cfg.DBPath); !os.IsNotExist(err) {
		t.Fatalf("validation created database: %v", err)
	}
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		cfg.ListenAddr, cfg.TLSCertFile, cfg.TLSKeyFile = addr, "", ""
		if _, err := validate(cfg); err != nil {
			t.Fatalf("loopback HTTP %s: %v", addr, err)
		}
	}
}

func TestPrivateSecretFiles(t *testing.T) {
	dir := privateTestDir(t)
	cfg := DefaultConfig()
	cfg.ListenAddr, cfg.DBPath = "127.0.0.1:0", filepath.Join(dir, "db.sqlite")
	cfg.AdminToken = "short-env-token" // A good file must override the environment.
	cfg.AdminTokenFile = filepath.Join(dir, "admin.token")
	if err := os.WriteFile(cfg.AdminTokenFile, []byte(testAdminToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := validate(cfg)
	if err != nil || v.backend.AdminToken != testAdminToken {
		t.Fatalf("private file override: %v", err)
	}
	if err := os.Chmod(cfg.AdminTokenFile, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := validate(cfg); err != nil {
		t.Fatalf("owner-read-only file: %v", err)
	}
	if err := os.Chmod(cfg.AdminTokenFile, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := validate(cfg); err == nil || !strings.Contains(err.Error(), "private file") {
		t.Fatalf("group-readable secret accepted: %v", err)
	}
	if err := os.Chmod(cfg.AdminTokenFile, 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "token-link")
	if err := os.Symlink(cfg.AdminTokenFile, symlink); err != nil {
		t.Fatal(err)
	}
	cfg.AdminTokenFile = symlink
	if _, err := validate(cfg); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink secret accepted: %v", err)
	}
	cfg.AdminTokenFile = dir
	if _, err := validate(cfg); err == nil {
		t.Fatal("directory accepted as secret file")
	}
	cfg.AdminTokenFile = filepath.Join(dir, "oversize.token")
	if err := os.WriteFile(cfg.AdminTokenFile, []byte(strings.Repeat("x", 4097)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := validate(cfg); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized secret accepted: %v", err)
	}

	// Ownership check is deterministic even without permission to chown a real
	// file on this device; use the same native stat shape as f.Stat provides.
	fake := secretInfo{uid: uint32(os.Geteuid()) + 1}
	if err := checkPrivateFile(fake); err == nil || !strings.Contains(err.Error(), "effective service user") {
		t.Fatalf("another user's secret accepted: %v", err)
	}
}

type secretInfo struct{ uid uint32 }

func (secretInfo) Name() string       { return "secret" }
func (secretInfo) Size() int64        { return 32 }
func (secretInfo) Mode() os.FileMode  { return 0600 }
func (secretInfo) ModTime() time.Time { return time.Time{} }
func (secretInfo) IsDir() bool        { return false }
func (s secretInfo) Sys() any         { return &syscall.Stat_t{Uid: s.uid} }

func TestInvalidTLSCreatesNoState(t *testing.T) {
	dir := privateTestDir(t)
	cert, key, _ := fixtureCertificate(t, dir)
	cfg := DefaultConfig()
	cfg.ListenAddr, cfg.DBPath, cfg.AdminToken = "127.0.0.1:0", filepath.Join(dir, "state", "db.sqlite"), testAdminToken
	cfg.TLSCertFile, cfg.TLSKeyFile = cert, key
	cases := []struct {
		name string
		set  func()
	}{
		{"missing-key", func() { cfg.TLSKeyFile = filepath.Join(dir, "missing.key") }},
		{"invalid-pem", func() {
			cfg.TLSKeyFile = filepath.Join(dir, "invalid.key")
			if err := os.WriteFile(cfg.TLSKeyFile, []byte("not a key"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"key-too-readable", func() {
			cfg.TLSKeyFile = key
			if err := os.Chmod(key, 0644); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.set()
			var output bytes.Buffer
			if err := Run(context.Background(), cfg, &output); err == nil {
				t.Fatal("bad TLS key accepted")
			}
			if output.Len() != 0 {
				t.Fatalf("bad TLS pair announced readiness: %s", output.String())
			}
			if _, err := os.Stat(filepath.Dir(cfg.DBPath)); !os.IsNotExist(err) {
				t.Fatalf("bad TLS pair created state: %v", err)
			}
		})
	}
}
