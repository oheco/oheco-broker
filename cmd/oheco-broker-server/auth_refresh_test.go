package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthRefreshServerDefaultsAndValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AdminToken = "isolated-refresh-server-admin"
	v, err := validate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v.backend.AccountTokenTTL != 24*time.Hour || v.backend.AuthRefreshTTL != 30*24*time.Hour || v.backend.AuthAbsoluteTTL != 0 || v.backend.AuthAccessOverlap != 2*time.Minute {
		t.Fatal("incorrect auth defaults", v.backend)
	}
	for _, field := range []string{"access", "refresh", "absolute", "overlap"} {
		t.Run(field, func(t *testing.T) {
			bad := cfg
			switch field {
			case "access":
				bad.AccountTokenTTL = -1
			case "refresh":
				bad.AuthRefreshTTL = -1
			case "absolute":
				bad.AuthAbsoluteTTL = -1
			case "overlap":
				bad.AuthAccessOverlap = -1
			}
			if _, err := validate(bad); err == nil {
				t.Fatal("negative lifetime accepted")
			}
		})
	}
	var help bytes.Buffer
	if err = Execute(context.Background(), []string{"--help"}, &bytes.Buffer{}, &help); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"account-token-ttl", "auth-refresh-ttl", "auth-absolute-ttl", "auth-access-overlap"} {
		if !strings.Contains(help.String(), flag) {
			t.Fatal("missing auth flag", flag)
		}
	}
}

func TestAuthRefreshStandaloneFlagsReachWire(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cert, key, roots := fixtureCertificate(t, dir)
	t.Setenv("OHECO_BROKER_ADMIN_TOKEN", "isolated-refresh-flags-admin")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan ReadyEvent, 1)
	done := make(chan error, 1)
	go func() {
		done <- Execute(ctx, []string{"--listen", "127.0.0.1:0", "--tls-cert", cert, "--tls-key", key, "--db", filepath.Join(dir, "control.sqlite"), "--registration", "open", "--account-token-ttl", "15s", "--auth-refresh-ttl", "1m", "--auth-absolute-ttl", "30s", "--auth-access-overlap", "1s"}, readyWriter{ch}, &bytes.Buffer{})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("auth flag fixture failed to stop")
		}
	})
	var event ReadyEvent
	select {
	case event = <-ch:
	case err := <-done:
		t.Fatal("auth flags startup failed", err)
	case <-time.After(10 * time.Second):
		t.Fatal("auth flags readiness timeout")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	t.Cleanup(client.CloseIdleConnections)
	result := requestJSON(t, client, event.API, "POST", "/v1/auth/register", "", map[string]any{"name": "refresh-flag-fixture", "password": "private-fixture-account-password"}, 201)
	access, err := time.Parse(time.RFC3339Nano, result["token_expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := time.Parse(time.RFC3339Nano, result["refresh_expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if access.Sub(time.Now()) > 15*time.Second || access.Sub(time.Now()) < 10*time.Second || refresh.Sub(time.Now()) > 30*time.Second || refresh.Sub(time.Now()) < 25*time.Second {
		t.Fatal("wire ignored configured access/absolute deadlines", access, refresh)
	}
	info := requestJSON(t, client, event.API, "GET", "/v1/status", "", nil, 200)
	if info["account_refresh_protocol"] != "refresh-v1" {
		t.Fatal("missing feature discovery")
	}
}
