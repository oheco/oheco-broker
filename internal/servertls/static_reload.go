package servertls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"
)

const defaultReloadInterval = 30 * time.Second

func loadStaticPair(certPath, keyPath string) (*tls.Certificate, [32]byte, error) {
	var fingerprint [32]byte
	certBefore, err := os.Lstat(certPath)
	if err != nil {
		return nil, fingerprint, fmt.Errorf("servertls: inspect static certificate: %w", err)
	}
	keyBefore, err := os.Lstat(keyPath)
	if err != nil {
		return nil, fingerprint, fmt.Errorf("servertls: inspect static private key: %w", err)
	}
	certPEM, err := readStaticFile(certPath, false)
	if err != nil {
		return nil, fingerprint, fmt.Errorf("servertls: read static certificate: %w", err)
	}
	keyPEM, err := readStaticFile(keyPath, true)
	if err != nil {
		return nil, fingerprint, fmt.Errorf("servertls: read static private key: %w", err)
	}
	certAfter, certErr := os.Lstat(certPath)
	keyAfter, keyErr := os.Lstat(keyPath)
	if certErr != nil || keyErr != nil || !sameStaticFileVersion(certBefore, certAfter) || !sameStaticFileVersion(keyBefore, keyAfter) {
		return nil, fingerprint, errors.New("servertls: certificate pair changed while reading")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fingerprint, fmt.Errorf("servertls: load static certificate: %w", err)
	}
	// X509KeyPair checks the leaf/private-key match, but not every supplied
	// chain certificate. Reject malformed or incorrectly ordered chains before
	// publishing them. Trust anchors remain the client's responsibility, so a
	// private CA or a self-signed server certificate is still supported.
	var parent *x509.Certificate
	hash := sha256.New()
	for i, der := range pair.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fingerprint, fmt.Errorf("servertls: parse static certificate chain: %w", err)
		}
		if i == 0 {
			pair.Leaf = cert
		} else if !bytes.Equal(parent.RawIssuer, cert.RawSubject) || parent.CheckSignatureFrom(cert) != nil {
			return nil, fingerprint, errors.New("servertls: invalid static certificate chain")
		}
		parent = cert
		_, _ = hash.Write(der)
	}
	now := time.Now()
	if !pair.Leaf.NotAfter.After(pair.Leaf.NotBefore) || now.Before(pair.Leaf.NotBefore) || !now.Before(pair.Leaf.NotAfter) {
		return nil, fingerprint, errors.New("servertls: static certificate is not currently valid")
	}
	// Hash DER, not PEM formatting. A re-export of the same chain and matching
	// key is unchanged and must not create repeated reload events.
	copy(fingerprint[:], hash.Sum(nil))
	return &pair, fingerprint, nil
}

func (p *Provider) configureStatic(opts Options) error {
	pair, fingerprint, err := loadStaticPair(opts.CertFile, opts.KeyFile)
	if err != nil {
		return err
	}
	p.staticCert.Store(pair)
	p.config = &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1"},
		GetCertificate: p.staticCertificate,
		// Certificates stays empty: Go otherwise bypasses GetCertificate for
		// clients without SNI, including clients connecting to a literal IP.
	}
	interval := opts.ReloadInterval
	if interval == 0 {
		interval = defaultReloadInterval
	}
	p.reloadDone = make(chan struct{})
	p.emit(Event{Kind: "certificate_loaded", NotAfter: pair.Leaf.NotAfter})
	go p.reloadStatic(opts.CertFile, opts.KeyFile, interval, fingerprint)
	return nil
}

func (p *Provider) staticCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if p.ctx.Err() != nil {
		return nil, ErrClosed
	}
	return p.staticCert.Load(), nil
}

func (p *Provider) reloadStatic(certPath, keyPath string, interval time.Duration, fingerprint [32]byte) {
	defer close(p.reloadDone)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	failed := false
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
		}
		if p.ctx.Err() != nil {
			return
		}
		pair, next, err := loadStaticPair(certPath, keyPath)
		if p.ctx.Err() != nil {
			return
		}
		if err != nil {
			if !failed {
				failed = true
				p.emit(Event{Kind: "certificate_reload_error", NotAfter: p.staticCert.Load().Leaf.NotAfter})
			}
			continue
		}
		if next != fingerprint {
			p.staticCert.Store(pair)
			fingerprint = next
			p.emit(Event{Kind: "certificate_reloaded", NotAfter: pair.Leaf.NotAfter})
		} else if failed {
			p.emit(Event{Kind: "certificate_reload_recovered", NotAfter: pair.Leaf.NotAfter})
		}
		failed = false
	}
}
