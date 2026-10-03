package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oheco/oheco-broker/internal/control"
	"github.com/oheco/oheco-broker/internal/servertls"
	"github.com/oheco/oheco-broker/sdk/go/remote"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type rootOptions struct{ api, config, ca string }

func Execute(ctx context.Context, args []string, version string, shell func(context.Context) error) error {
	options := &rootOptions{}
	root := &cobra.Command{Use: "oheco-broker", Short: "Local command broker and authenticated peer port forwarding", Version: version, SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
	root.SetVersionTemplate("oheco-broker {{.Version}}\n")
	root.PersistentFlags().StringVar(&options.api, "api", "", "Management API origin (or OHECO_BROKER_API / saved configuration)")
	root.PersistentFlags().StringVar(&options.config, "config", "", "Private account configuration file (default XDG_CONFIG_HOME/oheco-broker/account.json)")
	root.PersistentFlags().StringVar(&options.ca, "ca-file", "", "PEM CA bundle for verified HTTPS")
	local := &cobra.Command{Use: "shell", Short: "Trusted local-only command execution"}
	local.AddCommand(&cobra.Command{Use: "serve", Args: cobra.NoArgs, Short: "Run the legacy loopback command server", RunE: func(cmd *cobra.Command, _ []string) error { return shell(cmd.Context()) }})
	root.AddCommand(local, serverCommands(), tenantCommands(options), adminCommands(options))
	root.SetArgs(args)
	return root.ExecuteContext(ctx)
}
func (o *rootOptions) path() (string, error) { return configPath(o.config) }
func (o *rootOptions) endpoint(cfg config) string {
	if o.api != "" {
		return o.api
	}
	if v := os.Getenv("OHECO_BROKER_API"); v != "" {
		return v
	}
	if cfg.API != "" {
		return cfg.API
	}
	return "http://127.0.0.1:8080"
}
func (o *rootOptions) newClient(auth bool) (*remote.Client, config, string, error) {
	path, err := o.path()
	if err != nil {
		return nil, config{}, "", err
	}
	cfg, err := loadConfig(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, cfg, path, err
	}
	if auth && err != nil {
		return nil, cfg, path, errors.New("register or login before this operation")
	}
	endpoint := o.endpoint(cfg)
	if auth && cfg.API != endpoint {
		return nil, cfg, path, errors.New("API differs from stored account; login explicitly for this API")
	}
	token := ""
	if auth {
		token = cfg.Account.Token
		if token == "" {
			return nil, cfg, path, errors.New("account is logged out; login first")
		}
	}
	ca := o.ca
	if ca == "" {
		ca = cfg.CAFile
	}
	client, err := remote.New(remote.Options{URL: endpoint, Token: token, CAFile: ca, Timeout: 10 * time.Second})
	return client, cfg, path, err
}
func printJSON(cmd *cobra.Command, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	redactSecrets(value)
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
func redactSecrets(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			switch key {
			case "token", "device_token", "session_token", "password", "credential", "password_hash":
				delete(v, key)
			default:
				redactSecrets(child)
			}
		}
	case []any:
		for _, child := range v {
			redactSecrets(child)
		}
	}
}
func readPassword(cmd *cobra.Command, value string, stdin bool, prompt string) (string, error) {
	if value != "" && stdin {
		return "", errors.New("choose --password or --password-stdin, not both")
	}
	if value != "" {
		return value, nil
	}
	if stdin {
		data, err := bufio.NewReader(io.LimitReader(cmd.InOrStdin(), 4097)).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		if len(data) > 4096 {
			return "", errors.New("password input too long")
		}
		data = strings.TrimSuffix(strings.TrimSuffix(data, "\n"), "\r")
		if data == "" {
			return "", errors.New("password is empty")
		}
		return data, nil
	}
	in, ok := cmd.InOrStdin().(*os.File)
	if !ok || !term.IsTerminal(int(in.Fd())) {
		return "", errors.New("provide --password-stdin (preferred) or --password")
	}
	fmt.Fprint(cmd.ErrOrStderr(), prompt+": ")
	raw, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", err
	}
	if len(raw) == 0 {
		return "", errors.New("password is empty")
	}
	return string(raw), nil
}
func tokenFromFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return "", errors.New("token file must be a private small regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if len(value) < 16 {
		return "", errors.New("token must contain at least 16 characters")
	}
	return value, nil
}
func loopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func serverCommands() *cobra.Command {
	parent := &cobra.Command{Use: "server", Short: "SQLite management and embedded STUN/TURN server"}
	var listen, db, tokenFile, policy, turnListen, publicIP, tlsCert, tlsKey string
	var turnEnabled, allowLoopback, registrationRelay bool
	var relayMinPort, relayMaxPort uint16
	var lease, sessionTTL time.Duration
	var tlsOptions servertls.Options
	serve := &cobra.Command{Use: "serve", Args: cobra.NoArgs, Short: "Run the local-first control plane", RunE: func(cmd *cobra.Command, _ []string) error {
		// Reject an invalid range before reading credentials, creating state, or
		// opening listeners, including when TURN is disabled.
		if (relayMinPort == 0) != (relayMaxPort == 0) || relayMinPort > relayMaxPort {
			return errors.New("--turn-relay-min-port and --turn-relay-max-port must both be zero (ephemeral) or define an inclusive range from 1 to 65535 with min <= max")
		}
		token := os.Getenv("OHECO_BROKER_ADMIN_TOKEN")
		var err error
		if tokenFile != "" {
			token, err = tokenFromFile(tokenFile)
			if err != nil {
				return err
			}
		}
		if len(token) < 16 {
			return errors.New("set OHECO_BROKER_ADMIN_TOKEN or --admin-token-file (at least16characters)")
		}
		tlsOptions.CertFile, tlsOptions.KeyFile = tlsCert, tlsKey
		if err := servertls.Validate(tlsOptions); err != nil {
			return err
		}
		if tlsOptions.ACMEDomain != "" {
			_, port, err := net.SplitHostPort(listen)
			if err != nil || port != "443" {
				return errors.New("--acme-domain requires --listen on port 443 for TLS-ALPN-01 validation")
			}
		}
		if tlsCert == "" && tlsOptions.ACMEDomain == "" && !loopbackAddress(listen) {
			return errors.New("plaintext API is limited to loopback; configure TLS or ACME for other interfaces")
		}
		tlsProvider, err := servertls.New(tlsOptions)
		if err != nil {
			return err
		}
		defer tlsProvider.Close()
		if db == "" {
			path, err := configPath("")
			if err != nil {
				return err
			}
			db = filepath.Join(filepath.Dir(path), "control.sqlite")
		}
		if err = privateDirectory(db); err != nil {
			return err
		}
		service, err := control.New(control.Config{ListenAddr: listen, DBPath: db, AdminToken: token, RegistrationPolicy: policy, RegistrationRelayEnabled: registrationRelay, BrokerLease: lease, SessionTTL: sessionTTL, TURN: control.TURNConfig{Enabled: turnEnabled, ListenAddr: turnListen, PublicIP: publicIP, RelayMinPort: relayMinPort, RelayMaxPort: relayMaxPort, AllowLoopbackPeers: allowLoopback}})
		if err != nil {
			return err
		}
		defer service.Close()
		listener, err := net.Listen("tcp", listen)
		if err != nil {
			return err
		}
		defer listener.Close()
		httpServer := &http.Server{Handler: service.Handler(), TLSConfig: tlsProvider.TLSConfig(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
		scheme := "http"
		if httpServer.TLSConfig != nil {
			scheme = "https"
		}
		result := make(chan error, 1)
		go func() {
			if httpServer.TLSConfig != nil {
				result <- httpServer.ServeTLS(listener, "", "")
			} else {
				result <- httpServer.Serve(listener)
			}
		}()
		if tlsOptions.ACMEDomain != "" {
			acquireCtx, cancel := context.WithTimeout(cmd.Context(), 4*time.Minute)
			err := tlsProvider.Ensure(acquireCtx)
			cancel()
			if err != nil {
				_ = tlsProvider.Close()
				_ = httpServer.Close()
				<-result
				return fmt.Errorf("acquire ACME certificate: %w", err)
			}
		}
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"event": "server_ready", "api": scheme + "://" + listener.Addr().String(), "stun_turn": service.TURNAddr()})
		select {
		case err = <-result:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-cmd.Context().Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = httpServer.Shutdown(shutdown)
			if err != nil {
				_ = httpServer.Close()
			}
			<-result
			return err
		}
	}}
	f := serve.Flags()
	f.StringVar(&listen, "listen", "127.0.0.1:8080", "HTTP(S) API bind address")
	f.StringVar(&db, "db", "", "SQLite path on a private filesystem")
	f.StringVar(&tokenFile, "admin-token-file", "", "Private admin token file (otherwise environment)")
	f.StringVar(&policy, "registration", "approval", "Initial registration policy: open, approval, closed")
	f.BoolVar(&registrationRelay, "registration-relay", false, "Initial TURN eligibility for newly registered accounts (persisted in SQLite)")
	f.BoolVar(&turnEnabled, "turn", true, "Enable embedded STUN/TURN")
	f.StringVar(&turnListen, "turn-listen", "127.0.0.1:3478", "UDP STUN/TURN bind address")
	f.StringVar(&publicIP, "turn-public-ip", "127.0.0.1", "Advertised relay IP")
	f.Uint16Var(&relayMinPort, "turn-relay-min-port", 0, "First UDP relay port (inclusive; both relay bounds zero use ephemeral ports)")
	f.Uint16Var(&relayMaxPort, "turn-relay-max-port", 0, "Last UDP relay port (inclusive; both relay bounds zero use ephemeral ports)")
	f.BoolVar(&allowLoopback, "turn-allow-loopback", false, "Allow loopback relay peers for isolated local tests only")
	f.StringVar(&tlsCert, "tls-cert", "", "API TLS certificate PEM")
	f.StringVar(&tlsKey, "tls-key", "", "API TLS private key PEM")
	f.DurationVar(&tlsOptions.ReloadInterval, "tls-reload-interval", 0, "Static certificate/key reload interval; 0 uses 30s (requires --tls-cert and --tls-key)")
	f.StringVar(&tlsOptions.ACMEDomain, "acme-domain", "", "Single public DNS name for automatic HTTPS via TLS-ALPN-01 on TCP 443")
	f.StringVar(&tlsOptions.ACMEEmail, "acme-email", "", "Optional ACME account contact email")
	f.StringVar(&tlsOptions.ACMECacheDir, "acme-cache", "", "Private persistent ACME account and certificate cache directory (0700)")
	f.StringVar(&tlsOptions.ACMEDirectoryURL, "acme-directory", "", "ACME directory URL; empty uses Let's Encrypt production")
	f.BoolVar(&tlsOptions.ACMEAcceptTOS, "acme-accept-tos", false, "Accept the configured ACME CA's terms of service")
	f.DurationVar(&lease, "broker-lease", 90*time.Second, "Broker heartbeat lease")
	f.DurationVar(&sessionTTL, "session-ttl", 10*time.Minute, "Renewable peer session lifetime")
	parent.AddCommand(serve)
	return parent
}
func splitEndpoint(value string, zero bool) (string, uint16, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || (!zero && p == 0) || host == "" {
		return "", 0, errors.New("invalid host:port")
	}
	return host, uint16(p), nil
}
