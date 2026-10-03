// oheco-broker-server hosts only the management/signaling API and UDP STUN/TURN.
// It intentionally imports no native broker client or peer SDK packages.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

const Version = "0.3.0"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := Execute(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "oheco-broker-server:", err)
		os.Exit(1)
	}
}

// Execute parses the standalone flags. --version and --help require no secrets,
// database, TLS files, or listeners. Only Run starts the service.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cfg := DefaultConfig()
	flags := flag.NewFlagSet("oheco-broker-server", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "HTTP(S) API listen address; non-loopback requires TLS")
	flags.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite path in a private directory on a permissions-capable filesystem")
	flags.StringVar(&cfg.AdminTokenFile, "admin-token-file", "", "Private admin token file; otherwise OHECO_BROKER_ADMIN_TOKEN")
	flags.StringVar(&cfg.RegistrationPolicy, "registration", cfg.RegistrationPolicy, "Initial registration policy: open, approval, or closed (persisted in SQLite)")
	flags.BoolVar(&cfg.RegistrationRelayEnabled, "registration-relay", cfg.RegistrationRelayEnabled, "Initial TURN eligibility for newly registered accounts (persisted in SQLite)")
	flags.StringVar(&cfg.TURNListenAddr, "turn-listen", "", "UDP4 STUN/TURN listen address; empty disables STUN/TURN")
	flags.StringVar(&cfg.TURNPublicIP, "turn-public-ip", "", "Advertised unicast IPv4 address; required for wildcard TURN listen")
	flags.UintVar(&cfg.TURNRelayMinPort, "turn-relay-min-port", 0, "Inclusive relay UDP port range minimum; 0/0 uses ephemeral ports")
	flags.UintVar(&cfg.TURNRelayMaxPort, "turn-relay-max-port", 0, "Inclusive relay UDP port range maximum (0..65535)")
	flags.BoolVar(&cfg.TURNAllowLoopback, "turn-allow-loopback", false, "Allow loopback relay peers only in an isolated loopback-only fixture")
	flags.StringVar(&cfg.TLSCertFile, "tls-cert", "", "PEM certificate chain for HTTPS")
	flags.StringVar(&cfg.TLSKeyFile, "tls-key", "", "Private PEM key for HTTPS (current owner, 0600 or 0400)")
	flags.DurationVar(&cfg.TLSReloadInterval, "tls-reload-interval", 0, "Static certificate/key reload interval; 0 uses 30s (requires --tls-cert and --tls-key)")
	flags.StringVar(&cfg.ACMEDomain, "acme-domain", "", "Single public DNS name for automatic HTTPS via TLS-ALPN-01 on TCP 443")
	flags.StringVar(&cfg.ACMEEmail, "acme-email", "", "Optional ACME account contact email")
	flags.StringVar(&cfg.ACMECacheDir, "acme-cache", "", "Private persistent ACME account and certificate cache directory (0700)")
	flags.StringVar(&cfg.ACMEDirectoryURL, "acme-directory", "", "ACME directory URL; empty uses Let's Encrypt production")
	flags.BoolVar(&cfg.ACMEAcceptTOS, "acme-accept-tos", false, "Accept the configured ACME CA's terms of service")
	showVersion := flags.Bool("version", false, "Print version and exit")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: oheco-broker-server [flags]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if *showVersion {
		_, err := fmt.Fprintf(stdout, "oheco-broker-server %s\n", Version)
		return err
	}
	cfg.AdminToken = os.Getenv("OHECO_BROKER_ADMIN_TOKEN")
	return Run(ctx, cfg, stdout)
}
