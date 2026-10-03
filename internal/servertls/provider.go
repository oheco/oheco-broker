// Package servertls provides reloading file-backed TLS or persistent TLS-ALPN-01 ACME TLS.
package servertls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/idna"
)

// Options selects exactly one of plaintext, a static key pair, or ACME.
// ACMECacheDir must be a private directory on a filesystem enforcing Unix modes.
// ACMEDirectoryURL defaults to Let's Encrypt production. HTTP is accepted only
// for loopback ACME test servers; other directory endpoints must use HTTPS.
// Static certificates are checked every ReloadInterval (zero means 30 seconds).
// Log is optional, may be called concurrently, and must return promptly without
// synchronously calling Close, which waits for the static reload worker.
type Options struct {
	CertFile         string
	KeyFile          string
	ReloadInterval   time.Duration
	ACMEDomain       string
	ACMEEmail        string
	ACMECacheDir     string
	ACMEDirectoryURL string
	ACMEAcceptTOS    bool
	Log              func(Event)
}

// Event deliberately excludes private keys, account details, cache contents,
// request URLs, and untrusted CA error bodies.
type Event struct {
	Kind     string
	Domain   string
	NotAfter time.Time
}

var ErrClosed = errors.New("servertls: provider closed")

// Validate checks option values without reading files, creating directories,
// generating account keys, or contacting an ACME server.
func Validate(opts Options) error {
	if opts.ReloadInterval < 0 {
		return errors.New("servertls: certificate reload interval must not be negative")
	}
	if opts.ReloadInterval != 0 && (opts.CertFile == "" || opts.ACMEDomain != "") {
		return errors.New("servertls: certificate reload interval requires static TLS")
	}
	if (opts.CertFile == "") != (opts.KeyFile == "") {
		return errors.New("servertls: cert and key must be supplied together")
	}
	acmeOptions := opts.ACMEEmail != "" || opts.ACMECacheDir != "" || opts.ACMEDirectoryURL != "" || opts.ACMEAcceptTOS
	if opts.ACMEDomain == "" {
		if acmeOptions {
			return errors.New("servertls: ACME options require an ACME domain")
		}
		return nil
	}
	if opts.CertFile != "" {
		return errors.New("servertls: static certificates and ACME are mutually exclusive")
	}
	if _, err := normalizeDomain(opts.ACMEDomain); err != nil {
		return err
	}
	if !opts.ACMEAcceptTOS {
		return errors.New("servertls: ACME requires explicit acceptance of the CA terms of service")
	}
	if strings.TrimSpace(opts.ACMECacheDir) == "" {
		return errors.New("servertls: ACME requires a persistent private cache directory")
	}
	if opts.ACMEEmail != "" {
		address, err := mail.ParseAddress(opts.ACMEEmail)
		if err != nil || address.Address != opts.ACMEEmail || address.Name != "" {
			return errors.New("servertls: ACME email must be a single email address")
		}
	}
	if opts.ACMEDirectoryURL != "" {
		u, err := url.Parse(opts.ACMEDirectoryURL)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
			return errors.New("servertls: invalid ACME directory URL")
		}
		if u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname())) {
			return errors.New("servertls: ACME directory URL requires HTTPS (HTTP is allowed only on loopback)")
		}
		if port := u.Port(); port != "" {
			if _, err := net.LookupPort("tcp", port); err != nil {
				return errors.New("servertls: invalid ACME directory URL port")
			}
		}
	}
	return nil
}

func loopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
}

func normalizeDomain(domain string) (string, error) {
	invalid := errors.New("servertls: ACME domain must be a DNS name, without a wildcard, scheme, port, or path")
	if domain == "" || strings.TrimSpace(domain) != domain {
		return "", invalid
	}
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", invalid
	}
	ascii = strings.TrimSuffix(strings.ToLower(ascii), ".")
	if len(ascii) > 253 || net.ParseIP(ascii) != nil || !strings.Contains(ascii, ".") {
		return "", invalid
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", invalid
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", invalid
			}
		}
	}
	return ascii, nil
}

// Provider owns a TLS configuration, the ACME cache, and outbound transport.
// Call Close after shutting down servers using TLSConfig.
type Provider struct {
	config     *tls.Config
	manager    *autocert.Manager
	cache      *privateCache
	cancel     context.CancelFunc
	ctx        context.Context
	transport  *http.Transport
	closeOnce  sync.Once
	closeErr   error
	domain     string
	log        func(Event)
	certMu     sync.Mutex
	lastCert   [32]byte
	staticCert atomic.Pointer[tls.Certificate]
	reloadDone chan struct{}
}

// New validates options and loads static certificates or opens the ACME cache.
// ACME registration and certificate issuance happen lazily on the first TLS
// handshake for ACMEDomain. Port 443 must route directly to this TLS listener;
// this package never opens a port 80 listener or enables HTTP-01 challenges.
func New(opts Options) (*Provider, error) {
	if err := Validate(opts); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Provider{ctx: ctx, cancel: cancel, log: opts.Log}
	if opts.CertFile != "" {
		if err := p.configureStatic(opts); err != nil {
			cancel()
			return nil, err
		}
		return p, nil
	}
	if opts.ACMEDomain == "" {
		return p, nil
	}
	p.domain, _ = normalizeDomain(opts.ACMEDomain)
	cache, err := newPrivateCache(opts.ACMECacheDir, p.emit)
	if err != nil {
		cancel()
		return nil, err
	}
	p.cache = cache
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		p.transport = base.Clone()
	} else {
		p.transport = (&http.Transport{Proxy: http.ProxyFromEnvironment}).Clone()
	}
	directory := opts.ACMEDirectoryURL
	if directory == "" {
		directory = autocert.DefaultACMEDirectory
	}
	p.manager = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      cache,
		HostPolicy: autocert.HostWhitelist(p.domain),
		Email:      opts.ACMEEmail,
		Client:     &acme.Client{DirectoryURL: directory, HTTPClient: &http.Client{Transport: &providerTransport{provider: p}, Timeout: 2 * time.Minute}},
	}
	p.config = p.manager.TLSConfig()
	// Standalone net/http Serve with a TLS listener does not configure HTTP/2.
	p.config.NextProtos = []string{"http/1.1", acme.ALPNProto}
	p.config.MinVersion = tls.VersionTLS12
	p.config.GetCertificate = p.getCertificate
	p.emit(Event{Kind: "acme_ready"})
	return p, nil
}

// TLSConfig returns nil when TLS is disabled. Treat the returned configuration
// as immutable after attaching it to a server.
func (p *Provider) TLSConfig() *tls.Config { return p.config }

// Ensure waits for an ECDSA certificate for the configured domain. Start the
// TLS listener before calling Ensure, so the CA can perform TLS-ALPN-01.
// Cancellation stops waiting; call Close after a fatal startup cancellation to
// cancel issuance itself, since autocert owns the acquisition context.
// Static TLS and plaintext need no acquisition and return immediately.
func (p *Provider) Ensure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.ctx.Err() != nil {
		return ErrClosed
	}
	if p.manager == nil {
		return nil
	}
	result := make(chan error, 1)
	go func() {
		_, err := p.getCertificate(&tls.ClientHelloInfo{
			ServerName:       p.domain,
			SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
			SupportedCurves:  []tls.CurveID{tls.CurveP256},
			CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_AES_128_GCM_SHA256},
			SupportedProtos:  []string{"http/1.1"},
		})
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-p.ctx.Done():
		return ErrClosed
	}
}

func (p *Provider) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if p.ctx.Err() != nil {
		return nil, ErrClosed
	}
	// Enforce the single domain even for cached TLS-ALPN challenge certificates.
	// Manager's host policy does not cover its challenge-certificate branch.
	name, err := normalizeDomain(hello.ServerName)
	if err != nil || name != p.domain {
		return nil, errors.New("servertls: unconfigured TLS server name")
	}
	copyHello := *hello
	copyHello.ServerName = name
	cert, err := p.manager.GetCertificate(&copyHello)
	if err != nil {
		p.emit(Event{Kind: "certificate_error"})
		return nil, err
	}
	if len(hello.SupportedProtos) != 1 || hello.SupportedProtos[0] != acme.ALPNProto {
		fingerprint := sha256.Sum256(cert.Certificate[0])
		p.certMu.Lock()
		changed := fingerprint != p.lastCert
		p.lastCert = fingerprint
		p.certMu.Unlock()
		if changed {
			p.emit(Event{Kind: "certificate_served", NotAfter: cert.Leaf.NotAfter})
		}
	}
	return cert, nil
}

func (p *Provider) emit(event Event) {
	event.Domain = p.domain
	if p.log != nil {
		p.log(event)
	}
}

// Close is idempotent. It rejects new certificate callbacks, stops and joins the
// static reload worker, cancels outbound ACME requests, closes idle connections
// and the cache directory handle. Upstream
// autocert v0.43.0 does not expose a renewal-timer stop API: its internal timers
// may still wake, but cannot access the closed cache or contact the CA.
func (p *Provider) Close() error {
	p.closeOnce.Do(func() {
		p.cancel()
		if p.reloadDone != nil {
			<-p.reloadDone
		}
		if p.transport != nil {
			p.transport.CloseIdleConnections()
		}
		if p.cache != nil {
			p.closeErr = p.cache.Close()
		}
	})
	return p.closeErr
}

type providerTransport struct{ provider *Provider }

func (t *providerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	p := t.provider
	if p.ctx.Err() != nil {
		return nil, ErrClosed
	}
	ctx, cancel := context.WithCancel(request.Context())
	stop := context.AfterFunc(p.ctx, cancel)
	cleanup := func() { stop(); cancel() }
	response, err := p.transport.RoundTrip(request.Clone(ctx))
	if err != nil {
		cleanup()
		p.emit(Event{Kind: "acme_error"})
		return nil, err
	}
	if response.StatusCode >= 400 {
		p.emit(Event{Kind: "acme_error"})
	}
	response.Body = &cancelBody{ReadCloser: response.Body, cleanup: cleanup}
	return response, nil
}

type cancelBody struct {
	io.ReadCloser
	cleanup func()
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cleanup()
	return err
}
