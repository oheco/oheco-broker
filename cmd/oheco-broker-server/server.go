package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/oheco/oheco-broker/internal/control"
	"github.com/oheco/oheco-broker/internal/servertls"
)

// ReadyEvent is the single JSON line emitted after validated TLS configuration
// and successfully bound listeners. API and TURN contain actual bound ports, not
// :0; TURNAdvertised uses the backend's public IP and the actual UDP port.
type ReadyEvent struct {
	Event          string `json:"event"`
	Version        string `json:"version"`
	API            string `json:"api"`
	TURN           string `json:"turn"`
	TURNAdvertised string `json:"turn_advertised"`
}

// Run validates configuration before opening SQLite or starting any listener.
// Cancellation (including main's SIGINT/SIGTERM context) drains HTTP before
// closing TURN, maintenance, usage accounting, and SQLite. No global state or
// persistent background process is required to exercise this function in tests.
func Run(ctx context.Context, cfg Config, output io.Writer) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if output == nil {
		return errors.New("readiness output writer is required")
	}
	v, err := validate(cfg)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	opts := cfg.tlsOptions()
	opts.Log = func(event servertls.Event) {
		log.Printf("TLS event=%s domain=%s expires=%s", event.Kind, event.Domain, event.NotAfter.UTC().Format(time.RFC3339))
	}
	tlsProvider, err := servertls.New(opts)
	if err != nil {
		return err
	}
	defer tlsProvider.Close()
	v.tls = tlsProvider.TLSConfig()
	service, err := control.New(v.backend)
	if err != nil {
		return err
	}
	// This defer executes only after HTTP shutdown and the Serve goroutine join.
	defer func() { result = errors.Join(result, service.Close()) }()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", v.backend.ListenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	apiAddr := listener.Addr().String()
	scheme := "http"
	if v.tls != nil {
		scheme = "https"
		listener = tls.NewListener(listener, v.tls)
	}
	httpServer := &http.Server{
		Handler:           service.Handler(),
		TLSConfig:         v.tls,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 * 1024,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.Serve(listener) }()

	if cfg.ACMEDomain != "" {
		acquireCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		err := tlsProvider.Ensure(acquireCtx)
		cancel()
		if err != nil {
			_ = tlsProvider.Close()
			_ = httpServer.Close()
			<-errCh
			return fmt.Errorf("acquire ACME certificate: %w", err)
		}
	}

	ready := ReadyEvent{
		Event:          "server_ready",
		Version:        Version,
		API:            scheme + "://" + apiAddr,
		TURN:           service.TURNAddr(),
		TURNAdvertised: service.AdvertisedTURNAddr(),
	}
	if err := json.NewEncoder(output).Encode(ready); err != nil {
		result = fmt.Errorf("write readiness: %w", err)
	} else {
		select {
		case err := <-errCh:
			if !errors.Is(err, http.ErrServerClosed) {
				result = err
			}
			// No Serve goroutine remains. Shutdown still waits for active handlers.
			return errors.Join(result, shutdownHTTP(httpServer))
		case <-ctx.Done():
		}
	}
	// Shutdown needs an independent deadline: ctx is normally already canceled.
	result = errors.Join(result, shutdownHTTP(httpServer))
	if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
		result = errors.Join(result, err)
	}
	return result
}

func shutdownHTTP(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return errors.Join(err, server.Close())
	}
	return nil
}
