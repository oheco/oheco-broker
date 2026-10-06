package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oheco/oheco-broker/sdk/go/remote"
	"github.com/spf13/cobra"
)

type authResponse struct {
	Tenant           struct{ ID, Name, Email string }
	Token            string    `json:"token"`
	RefreshToken     string    `json:"refresh_token"`
	AuthSessionID    string    `json:"auth_session_id"`
	Generation       uint64    `json:"generation"`
	TokenExpiresAt   time.Time `json:"token_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

func (r authResponse) credentials() remote.AuthCredentials {
	return remote.AuthCredentials{AuthSessionID: r.AuthSessionID, Token: r.Token, RefreshToken: r.RefreshToken,
		Generation: r.Generation, TokenExpiresAt: r.TokenExpiresAt, RefreshExpiresAt: r.RefreshExpiresAt}
}
func applyAuthResponse(cfg *config, r authResponse) error {
	if r.Token == "" || r.Tenant.ID == "" {
		return errors.New("management server returned incomplete account")
	}
	cfg.Account.ID, cfg.Account.Name, cfg.Account.Email = r.Tenant.ID, r.Tenant.Name, r.Tenant.Email
	cfg.Account.Token = r.Token
	if r.AuthSessionID != "" {
		cfg.setAuthCredentials(r.credentials())
	} else {
		cfg.Version = 1
		cfg.Auth = nil
	}
	return validateAuthProfile(*cfg)
}

func tenantCommands(o *rootOptions) *cobra.Command {
	tenant := &cobra.Command{Use: "tenant", Short: "Manage your account, brokers and authenticated peer mappings"}
	tenant.AddCommand(registration(o, false), registration(o, true))
	tenant.AddCommand(&cobra.Command{Use: "logout", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		release, err := o.lockProfile()
		if err != nil {
			return err
		}
		defer release()
		client, cfg, path, err := o.newClient(true)
		if err != nil {
			return err
		}
		defer client.Close()
		endpoint := "/v1/tenants/logout"
		if cfg.Auth != nil {
			endpoint = "/v1/auth/logout"
		}
		_, err = client.Request("POST", endpoint, nil, map[string]any{})
		if err != nil {
			return err
		}
		if err = client.Close(); err != nil {
			return err
		}
		cfg.Account.Token = ""
		cfg.Auth = nil
		if err = saveConfig(path, cfg); err != nil {
			return err
		}
		return removePrivatePending(path + ".refresh-pending")
	}})
	accountCmd := &cobra.Command{Use: "account", Short: "Account information and credentials"}
	accountCmd.AddCommand(accountShow(o), accountUpdate(o), accountPassword(o))
	tenant.AddCommand(accountCmd)
	tenant.AddCommand(&cobra.Command{Use: "refresh", Args: cobra.NoArgs, Short: "Refresh login credentials without restarting peers", RunE: func(cmd *cobra.Command, _ []string) error {
		client, cfg, _, err := o.newClient(true)
		if err != nil {
			return err
		}
		defer client.Close()
		if cfg.Auth == nil {
			return errors.New("this profile uses a static token; login to enable automatic refresh")
		}
		if err = client.RefreshAuth(); err != nil {
			return err
		}
		credentials, err := client.AuthCredentials()
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"auth_session_id": credentials.AuthSessionID,
			"generation": credentials.Generation, "token_expires_at": credentials.TokenExpiresAt,
			"refresh_expires_at": credentials.RefreshExpiresAt})
	}})
	tenant.AddCommand(tenantRequest(o, "capabilities", "/v1/capabilities"), tenantUsage(o))
	brokers := &cobra.Command{Use: "broker", Short: "Broker metadata"}
	brokers.AddCommand(tenantRequest(o, "list", "/v1/brokers"))
	for _, action := range []string{"show", "delete", "rename", "register"} {
		action := action
		var name string
		command := &cobra.Command{Use: action + " [broker-id]", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := o.newClient(true)
			if err != nil {
				return err
			}
			defer client.Close()
			method, path, body := "GET", "/v1/brokers/"+args[0], any(nil)
			switch action {
			case "delete":
				method = "DELETE"
			case "rename":
				if name == "" {
					return errors.New("--name is required")
				}
				method = "PATCH"
				body = map[string]any{"name": name}
			case "register":
				method = "POST"
				path = "/v1/brokers"
				body = map[string]any{"name": args[0]}
			}
			raw, err := client.Request(method, path, nil, body)
			if err != nil {
				return err
			}
			return printJSON(cmd, raw)
		}}
		if action == "rename" {
			command.Flags().StringVar(&name, "name", "", "New broker name")
		}
		brokers.AddCommand(command)
	}
	tenant.AddCommand(brokers, serveCommand(o), connectCommand(o))
	return tenant
}
func registration(o *rootOptions, login bool) *cobra.Command {
	var name, password, email string
	var passwordStdin, replace, legacyAuth bool
	verb := "register"
	if login {
		verb = "login"
	}
	command := &cobra.Command{Use: verb, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		path, err := o.path()
		if err != nil {
			return err
		}
		release, err := acquireProfile(path)
		if err != nil {
			return err
		}
		defer release()
		previous, loadErr := loadConfig(path)
		if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
			return loadErr
		}
		if !login && loadErr == nil && !replace {
			return errors.New("account configuration exists; use --replace explicitly or another --config")
		}
		api := o.endpoint(previous)
		ca := o.ca
		if ca == "" && previous.API == api {
			ca = previous.CAFile
		}
		client, err := remote.New(remote.Options{URL: api, CAFile: ca, Timeout: 10 * time.Second})
		if err != nil {
			return err
		}
		defer client.Close()
		refreshEnabled := false
		if !legacyAuth {
			refreshEnabled, err = supportsAuthRefresh(client)
			if err != nil {
				return err
			}
		}
		if login {
			if name == "" {
				name = previous.Account.Name
			}
			if name == "" {
				return errors.New("--name is required")
			}
			if password == "" && !passwordStdin && previous.API == api && previous.Account.Name == name {
				password = previous.Account.Password
			}
			password, err = readPassword(cmd, password, passwordStdin, "Account password")
		} else {
			generatedName, generatedPassword, e := generatedCredentials()
			if e != nil {
				return e
			}
			if name == "" {
				name = generatedName
			}
			if refreshEnabled {
				password, err = readPassword(cmd, password, passwordStdin, "Account password")
			} else if passwordStdin {
				password, err = readPassword(cmd, password, true, "")
			} else if password == "" {
				password = generatedPassword
			}
		}
		if err != nil {
			return err
		}
		body := map[string]any{"name": name, "password": password}
		if !login && email != "" {
			body["email"] = email
		}
		pendingPath := ""
		if !login {
			pendingPath = path + ".pending"
			if _, e := os.Lstat(pendingPath); e == nil && !replace {
				return fmt.Errorf("pending registration credentials exist; recover with tenant login --config %s", pendingPath)
			} else if e != nil && !errors.Is(e, os.ErrNotExist) {
				return e
			}
			draft := config{Version: 1, API: api, CAFile: ca, Account: account{Name: name, Password: password, Email: email}}
			if err = saveConfig(pendingPath, draft); err != nil {
				return err
			}
		}
		empty := ""
		endpoint := "/v1/tenants/" + verb
		if refreshEnabled {
			endpoint = "/v1/auth/" + verb
		}
		raw, err := client.Request("POST", endpoint, &empty, body)
		if err != nil {
			if pendingPath != "" {
				return fmt.Errorf("%w; registration outcome may need checking, credentials retained privately in %s", err, pendingPath)
			}
			return err
		}
		var response authResponse
		if err = json.Unmarshal(raw, &response); err != nil {
			return err
		}
		if response.Token == "" || response.Tenant.ID == "" {
			return errors.New("management server returned incomplete account")
		}
		cfg := config{Version: 1, API: api, CAFile: ca, Account: account{Password: password}}
		if err = applyAuthResponse(&cfg, response); err != nil {
			return err
		}
		if refreshEnabled && cfg.Auth == nil {
			return errors.New("server omitted refresh credentials")
		}
		if err = saveConfig(path, cfg); err != nil {
			if pendingPath != "" {
				return fmt.Errorf("account operation succeeded but configuration save failed; pending credentials at %s can recover login: %w", pendingPath, err)
			}
			return fmt.Errorf("login succeeded but configuration save failed; retry login to persist it: %w", err)
		}
		if err = removePrivatePending(path + ".refresh-pending"); err != nil {
			return err
		}
		if pendingPath != "" {
			if err = removePrivatePending(pendingPath); err != nil {
				return fmt.Errorf("account saved but pending credential cleanup failed: %w", err)
			}
		}
		return printJSON(cmd, raw)
	}}
	command.Flags().StringVar(&name, "name", "", "Tenant name (register: generated when omitted)")
	command.Flags().StringVar(&password, "password", "", "Account password (prefer --password-stdin)")
	command.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read account password from stdin")
	command.Flags().BoolVar(&legacyAuth, "legacy-auth", false, "Use a static account token and a version1 profile for older clients")
	if !login {
		command.Flags().StringVar(&email, "email", "", "Optional contact email")
		command.Flags().BoolVar(&replace, "replace", false, "Explicitly replace this local account profile")
	}
	return command
}
func tenantRequest(o *rootOptions, name, path string) *cobra.Command {
	return &cobra.Command{Use: name, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		client, _, _, err := o.newClient(true)
		if err != nil {
			return err
		}
		defer client.Close()
		raw, err := client.Request("GET", path, nil, nil)
		if err != nil {
			return err
		}
		return printJSON(cmd, raw)
	}}
}
func tenantUsage(o *rootOptions) *cobra.Command {
	var broker string
	cmd := &cobra.Command{Use: "usage", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		client, _, _, err := o.newClient(true)
		if err != nil {
			return err
		}
		defer client.Close()
		path := "/v1/usage"
		if broker != "" {
			path = "/v1/brokers/" + broker + "/usage"
		}
		raw, err := client.Request("GET", path, nil, nil)
		if err != nil {
			return err
		}
		return printJSON(cmd, raw)
	}}
	cmd.Flags().StringVar(&broker, "broker", "", "Restrict usage to this broker UUID")
	return cmd
}
func accountShow(o *rootOptions) *cobra.Command { return tenantRequest(o, "show", "/v1/me") }
func accountUpdate(o *rootOptions) *cobra.Command {
	var name, email string
	cmd := &cobra.Command{Use: "update", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		body := map[string]any{}
		if cmd.Flags().Changed("name") {
			body["name"] = name
		}
		if cmd.Flags().Changed("email") {
			body["email"] = email
		}
		if len(body) == 0 {
			return errors.New("choose --name and/or --email")
		}
		release, err := o.lockProfile()
		if err != nil {
			return err
		}
		defer release()
		client, cfg, path, err := o.newClient(true)
		if err != nil {
			return err
		}
		defer client.Close()
		raw, err := client.Request("PATCH", "/v1/me", nil, body)
		if err != nil {
			return err
		}
		var response authResponse
		if err = json.Unmarshal(raw, &response); err != nil {
			return err
		}
		if err = client.Close(); err != nil {
			return err
		}
		if err = applyAuthResponse(&cfg, response); err != nil {
			return err
		}
		if err = saveConfig(path, cfg); err != nil {
			return err
		}
		if err = removePrivatePending(path + ".refresh-pending"); err != nil {
			return err
		}
		return printJSON(cmd, raw)
	}}
	cmd.Flags().StringVar(&name, "name", "", "New tenant name")
	cmd.Flags().StringVar(&email, "email", "", "New contact email; empty clears it")
	return cmd
}
func accountPassword(o *rootOptions) *cobra.Command {
	var password string
	var stdin bool
	cmd := &cobra.Command{Use: "password", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		pw, err := readPassword(cmd, password, stdin, "New account password")
		if err != nil {
			return err
		}
		release, err := o.lockProfile()
		if err != nil {
			return err
		}
		defer release()
		client, cfg, path, err := o.newClient(true)
		if err != nil {
			return err
		}
		defer client.Close()
		raw, err := client.Request("POST", "/v1/me/password", nil, map[string]any{"password": pw})
		if err != nil {
			return err
		}
		var response authResponse
		if err = json.Unmarshal(raw, &response); err != nil {
			return err
		}
		if err = client.Close(); err != nil {
			return err
		}
		if response.Tenant.ID == "" {
			response.Tenant.ID, response.Tenant.Name, response.Tenant.Email = cfg.Account.ID, cfg.Account.Name, cfg.Account.Email
		}
		cfg.Account.Password = pw
		if err = applyAuthResponse(&cfg, response); err != nil {
			return err
		}
		if err = saveConfig(path, cfg); err != nil {
			return err
		}
		if err = removePrivatePending(path + ".refresh-pending"); err != nil {
			return err
		}
		return printJSON(cmd, raw)
	}}
	cmd.Flags().StringVar(&password, "password", "", "New password (prefer stdin)")
	cmd.Flags().BoolVar(&stdin, "password-stdin", false, "Read password from stdin")
	return cmd
}
func discoverSTUN(client *remote.Client, explicit string) (string, uint16, error) {
	value := explicit
	if value == "" {
		raw, err := client.Request("GET", "/v1/capabilities", nil, nil)
		if err != nil {
			return "", 0, err
		}
		var caps struct {
			STUN string `json:"stun_address"`
		}
		if err = json.Unmarshal(raw, &caps); err != nil {
			return "", 0, err
		}
		value = caps.STUN
	}
	if value == "" {
		return "", 0, nil
	}
	return splitEndpoint(value, false)
}
func parseRule(value string) (remote.Rule, error) {
	parts := strings.SplitN(value, "@", 2)
	if len(parts) != 2 || (parts[0] != "tcp" && parts[0] != "udp") {
		return remote.Rule{}, errors.New("allow format is tcp@host:port or udp@host:port")
	}
	host, port, err := splitEndpoint(parts[1], false)
	return remote.Rule{Host: host, Port: port, Protocol: parts[0]}, err
}
func serveCommand(o *rootOptions) *cobra.Command {
	var name, password, policyFile, stun string
	var stdin, stateEvents bool
	var values []string
	cmd := &cobra.Command{Use: "serve", Args: cobra.NoArgs, Short: "Run a registered broker with a local target allowlist", RunE: func(cmd *cobra.Command, _ []string) error {
		requests, stopRequests := peerReconnectSignals()
		defer stopRequests()
		if name == "" {
			return errors.New("--name is required")
		}
		pw, err := readPassword(cmd, password, stdin, "Private peer password")
		if err != nil {
			return err
		}
		rules := []remote.Rule{}
		if policyFile != "" {
			file, e := os.Open(policyFile)
			if e != nil {
				return e
			}
			defer file.Close()
			var policy struct {
				Allow []remote.Rule `json:"allow"`
			}
			decoder := json.NewDecoder(io.LimitReader(file, 1024*1024))
			decoder.DisallowUnknownFields()
			if e = decoder.Decode(&policy); e != nil {
				return e
			}
			var tail any
			if e = decoder.Decode(&tail); e != io.EOF {
				return errors.New("allow configuration contains trailing data")
			}
			rules = append(rules, policy.Allow...)
		}
		for _, value := range values {
			rule, e := parseRule(value)
			if e != nil {
				return e
			}
			rules = append(rules, rule)
		}
		client, _, _, err := o.newClient(true)
		if err != nil {
			return err
		}
		defer client.Close()
		host, port, err := discoverSTUN(client, stun)
		if err != nil {
			return err
		}
		server, err := client.Serve(name, pw, remote.ServeOptions{Rules: rules, STUNHost: host, STUNPort: port})
		if err != nil {
			return err
		}
		defer server.Close()
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"event": "broker_ready", "broker_id": server.ID(), "name": name, "allow_rules": len(rules)})
		return monitorPeer(cmd, server, "broker", stateEvents, requests)
	}}
	cmd.Flags().StringVar(&name, "name", "", "Unique broker name within your tenant")
	cmd.Flags().StringVar(&password, "password", "", "Private peer password; never sent to management API")
	cmd.Flags().BoolVar(&stdin, "password-stdin", false, "Read peer password from stdin")
	cmd.Flags().StringVar(&policyFile, "allow-config", "", "JSON target policy: {\"allow\":[{\"host\":...,\"port\":...,\"protocol\":\"tcp\"}]}")
	cmd.Flags().StringSliceVar(&values, "allow", nil, "Explicit target, e.g. tcp@127.0.0.1:8080 (repeatable)")
	cmd.Flags().StringVar(&stun, "stun", "", "STUN host:port override; default discovered from control plane")
	cmd.Flags().BoolVar(&stateEvents, "state-events", false, "Emit redacted JSON recovery transitions; SIGUSR1 requests manual recovery")
	return cmd
}
func connectCommand(o *rootOptions) *cobra.Command {
	var name, id, password, protocol, target, local, relay, stun string
	var stdin, stateEvents bool
	cmd := &cobra.Command{Use: "connect", Args: cobra.NoArgs, Short: "Authenticate a peer and expose one fixed TCP/UDP mapping", RunE: func(cmd *cobra.Command, _ []string) error {
		requests, stopRequests := peerReconnectSignals()
		defer stopRequests()
		if (name == "") == (id == "") {
			return errors.New("choose exactly one --name or --broker-id")
		}
		pw, err := readPassword(cmd, password, stdin, "Private peer password")
		if err != nil {
			return err
		}
		targetHost, targetPort, err := splitEndpoint(target, false)
		if err != nil {
			return err
		}
		localHost, localPort := "127.0.0.1", uint16(0)
		if strings.Contains(local, ":") {
			localHost, localPort, err = splitEndpoint(local, true)
		} else {
			var p uint64
			p, err = strconv.ParseUint(local, 10, 16)
			localPort = uint16(p)
		}
		if err != nil {
			return err
		}
		proto := remote.TCP
		if protocol == "udp" {
			proto = remote.UDP
		} else if protocol != "tcp" {
			return errors.New("protocol must be tcp or udp")
		}
		mode := remote.RelayAuto
		switch relay {
		case "never":
			mode = remote.RelayNever
		case "force":
			mode = remote.RelayForce
		case "auto":
		default:
			return errors.New("relay must be auto, never or force")
		}
		client, _, _, err := o.newClient(true)
		if err != nil {
			return err
		}
		defer client.Close()
		if id == "" {
			raw, e := client.Request("GET", "/v1/brokers", nil, nil)
			if e != nil {
				return e
			}
			var result struct{ Brokers []struct{ ID, Name string } }
			if e = json.Unmarshal(raw, &result); e != nil {
				return e
			}
			for _, b := range result.Brokers {
				if b.Name == name {
					if id != "" {
						return errors.New("broker name is ambiguous; use --broker-id")
					}
					id = b.ID
				}
			}
			if id == "" {
				return errors.New("broker name not found")
			}
		}
		stunHost, stunPort, err := discoverSTUN(client, stun)
		if err != nil {
			return err
		}
		peer, err := client.Connect(id, pw, remote.ConnectOptions{Relay: mode, STUNHost: stunHost, STUNPort: stunPort, Timeout: 30 * time.Second})
		if err != nil {
			return err
		}
		defer peer.Close()
		mapping, err := peer.Map(proto, localHost, localPort, targetHost, targetPort)
		if err != nil {
			return err
		}
		defer mapping.Close()
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"event": "mapping_ready", "protocol": protocol, "local": net.JoinHostPort(localHost, strconv.Itoa(int(mapping.Port()))), "broker_id": id, "target": target, "relay_mode": relay})
		return monitorPeer(cmd, peer, "peer", stateEvents, requests)
	}}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "Broker name")
	f.StringVar(&id, "broker-id", "", "Broker UUID")
	f.StringVar(&password, "password", "", "Private peer password (prefer stdin)")
	f.BoolVar(&stdin, "password-stdin", false, "Read peer password from stdin")
	f.StringVar(&protocol, "protocol", "tcp", "tcp or udp")
	f.StringVar(&target, "target", "", "Target host:port as seen by broker")
	f.StringVar(&local, "local", "0", "Local port or numeric IP:port; default random loopback port")
	f.StringVar(&relay, "relay", "auto", "auto, never, force")
	f.StringVar(&stun, "stun", "", "STUN host:port override")
	f.BoolVar(&stateEvents, "state-events", false, "Emit redacted JSON recovery transitions; SIGUSR1 requests manual recovery")
	return cmd
}
