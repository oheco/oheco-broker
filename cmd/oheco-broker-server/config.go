package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/oheco/oheco-broker/internal/control"
	"github.com/oheco/oheco-broker/internal/servertls"
)

// Config belongs only to this command; it does not change backend or root CLI
// defaults. AdminTokenFile takes precedence over AdminToken (the CLI environment).
// Ports remain uint until validated, so values above 65535 cannot silently wrap.
type Config struct {
	ListenAddr               string
	DBPath                   string
	AdminToken               string
	AdminTokenFile           string
	RegistrationPolicy       string
	RegistrationRelayEnabled bool
	TURNListenAddr           string
	TURNPublicIP             string
	TURNRelayMinPort         uint
	TURNRelayMaxPort         uint
	TURNAllowLoopback        bool
	TLSCertFile              string
	TLSKeyFile               string
	TLSReloadInterval        time.Duration
	ACMEDomain               string
	ACMEEmail                string
	ACMECacheDir             string
	ACMEDirectoryURL         string
	ACMEAcceptTOS            bool
}

func DefaultConfig() Config {
	return Config{
		ListenAddr:         "127.0.0.1:8080",
		DBPath:             "control.sqlite",
		RegistrationPolicy: "approval",
	}
}

type validatedConfig struct {
	backend control.Config
	tls     *tls.Config
}

// validate does all command validation and reads secrets/certificates without
// creating a database or starting a listener. The backend owns database directory
// and SQLite permission checks. Resolved IPs are pinned before either listener is
// started; a hostname cannot evade the plaintext/loopback policy through DNS.
func validate(cfg Config) (validatedConfig, error) {
	var v validatedConfig
	if cfg.DBPath == "" || strings.ContainsAny(cfg.DBPath, "?\x00") || strings.HasPrefix(cfg.DBPath, "file:") {
		return v, errors.New("--db must be a nonempty plain SQLite filesystem path (or :memory:)")
	}
	if cfg.RegistrationPolicy != "open" && cfg.RegistrationPolicy != "approval" && cfg.RegistrationPolicy != "closed" {
		return v, errors.New("--registration must be open, approval, or closed")
	}
	if cfg.TURNRelayMinPort > 65535 || cfg.TURNRelayMaxPort > 65535 {
		return v, errors.New("TURN relay ports must be in 0..65535")
	}
	if (cfg.TURNRelayMinPort == 0) != (cfg.TURNRelayMaxPort == 0) || cfg.TURNRelayMinPort > cfg.TURNRelayMaxPort {
		return v, errors.New("TURN relay ports must both be zero or define an ascending nonzero range")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return v, errors.New("--tls-cert and --tls-key must be provided together")
	}

	apiAddr, apiLoopback, err := resolveAPIAddress(cfg.ListenAddr)
	if err != nil {
		return v, err
	}
	if err := servertls.Validate(cfg.tlsOptions()); err != nil {
		return v, err
	}
	if cfg.ACMEDomain != "" {
		_, port, _ := net.SplitHostPort(apiAddr)
		if port != "443" {
			return v, errors.New("--acme-domain requires --listen on port 443 for TLS-ALPN-01 validation")
		}
	}
	if !apiLoopback && cfg.TLSCertFile == "" && cfg.ACMEDomain == "" {
		return v, errors.New("non-loopback --listen requires --tls-cert and --tls-key or --acme-domain; plaintext HTTP is loopback-only")
	}
	turnCfg := control.TURNConfig{
		Enabled:            cfg.TURNListenAddr != "",
		RelayMinPort:       uint16(cfg.TURNRelayMinPort),
		RelayMaxPort:       uint16(cfg.TURNRelayMaxPort),
		AllowLoopbackPeers: cfg.TURNAllowLoopback,
	}
	if !turnCfg.Enabled {
		if cfg.TURNPublicIP != "" || cfg.TURNRelayMinPort != 0 || cfg.TURNRelayMaxPort != 0 || cfg.TURNAllowLoopback {
			return v, errors.New("TURN options require --turn-listen")
		}
	} else {
		turnAddr, publicIP, turnLoopback, err := resolveTURNAddress(cfg.TURNListenAddr, cfg.TURNPublicIP)
		if err != nil {
			return v, err
		}
		if cfg.TURNAllowLoopback && (!apiLoopback || !turnLoopback || !publicIP.IsLoopback()) {
			return v, errors.New("--turn-allow-loopback is only permitted with loopback API, TURN listen, and TURN public IP")
		}
		turnCfg.ListenAddr = turnAddr
		turnCfg.PublicIP = publicIP.String()
	}

	// Prevalidate the initial pair before any database or listener side effects.
	// The shared TLS provider performs subsequent static-file hot reloads.
	if cfg.TLSCertFile != "" {
		certPEM, err := readBoundedFile(cfg.TLSCertFile, 1024*1024, false)
		if err != nil {
			return v, fmt.Errorf("TLS certificate: %w", err)
		}
		keyPEM, err := readBoundedFile(cfg.TLSKeyFile, 1024*1024, true)
		if err != nil {
			return v, fmt.Errorf("TLS key: %w", err)
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return v, fmt.Errorf("TLS certificate/key pair: %w", err)
		}
		v.tls = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	}

	token := cfg.AdminToken
	if cfg.AdminTokenFile != "" {
		b, err := readBoundedFile(cfg.AdminTokenFile, 4096, true)
		if err != nil {
			return v, fmt.Errorf("admin token file: %w", err)
		}
		token = string(b)
	}
	token = strings.TrimSpace(token)
	if len(token) < 16 || len(token) > 4096 || strings.ContainsRune(token, '\x00') || strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return v, errors.New("set --admin-token-file or OHECO_BROKER_ADMIN_TOKEN to a single token of 16..4096 bytes")
	}
	v.backend = control.Config{
		ListenAddr:               apiAddr,
		DBPath:                   cfg.DBPath,
		AdminToken:               token,
		RegistrationPolicy:       cfg.RegistrationPolicy,
		RegistrationRelayEnabled: cfg.RegistrationRelayEnabled,
		TURN:                     turnCfg,
	}
	return v, nil
}

func (cfg Config) tlsOptions() servertls.Options {
	return servertls.Options{
		CertFile: cfg.TLSCertFile, KeyFile: cfg.TLSKeyFile, ReloadInterval: cfg.TLSReloadInterval,
		ACMEDomain: cfg.ACMEDomain, ACMEEmail: cfg.ACMEEmail,
		ACMECacheDir: cfg.ACMECacheDir, ACMEDirectoryURL: cfg.ACMEDirectoryURL,
		ACMEAcceptTOS: cfg.ACMEAcceptTOS,
	}
}

func splitListenAddress(addr, flagName string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("%s must be host:port: %w", flagName, err)
	}
	if port == "" || strings.IndexFunc(port, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return "", "", fmt.Errorf("%s requires a numeric port in 0..65535", flagName)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", "", fmt.Errorf("%s requires a numeric port in 0..65535", flagName)
	}
	return host, port, nil
}

func resolveAPIAddress(addr string) (string, bool, error) {
	host, port, err := splitListenAddress(addr, "--listen")
	if err != nil {
		return "", false, err
	}
	// Treat only literal loopback (or the exact localhost alias, pinned below)
	// as safe for plaintext; arbitrary DNS names always require TLS.
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	loopback := ip != nil && ip.IsLoopback()
	a, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return "", false, fmt.Errorf("--listen: %w", err)
	}
	if a.IP.IsMulticast() || a.IP.Equal(net.IPv4bcast) {
		return "", false, errors.New("--listen requires a unicast or wildcard address")
	}
	return a.String(), loopback, nil
}

func resolveTURNAddress(addr, advertised string) (string, net.IP, bool, error) {
	host, port, err := splitListenAddress(addr, "--turn-listen")
	if err != nil {
		return "", nil, false, err
	}
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	a, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, port))
	if err != nil {
		return "", nil, false, fmt.Errorf("--turn-listen: %w", err)
	}
	if a.IP != nil && (a.IP.To4() == nil || a.IP.IsMulticast() || a.IP.Equal(net.IPv4bcast)) {
		return "", nil, false, errors.New("--turn-listen requires a unicast or wildcard IPv4 address")
	}
	publicIP := net.ParseIP(advertised).To4()
	if advertised == "" {
		publicIP = a.IP.To4()
	}
	if publicIP == nil || publicIP.IsUnspecified() || publicIP.IsMulticast() || publicIP.Equal(net.IPv4bcast) {
		return "", nil, false, errors.New("TURN requires a unicast IPv4 --turn-public-ip (or a concrete IPv4 listen address)")
	}
	return a.String(), publicIP, a.IP.IsLoopback(), nil
}

func checkPrivateFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() || (info.Mode().Perm() != 0600 && info.Mode().Perm() != 0400) {
		return errors.New("must be a regular private file (0600 or 0400) on a permissions-capable filesystem")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("must be owned by the effective service user")
	}
	return nil
}

// Secret files must not be symlinks: compare the pre-open inode with the open
// descriptor, and verify permissions/owner on that descriptor before reading.
// O_NONBLOCK prevents a swapped FIFO from blocking service startup.
func readBoundedFile(path string, max int64, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("must be a regular file, not a directory or symlink")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(before, info) {
		return nil, errors.New("file changed while opening")
	}
	if private {
		if err := checkPrivateFile(info); err != nil {
			return nil, err
		}
	}
	if info.Size() > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}
	return b, nil
}
