package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v4"
)

func TestServerRelayPortFlags(t *testing.T) {
	server := serverCommands()
	serve, _, err := server.Find([]string{"serve"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"turn-relay-min-port", "turn-relay-max-port"} {
		flag := serve.Flags().Lookup(name)
		if flag == nil || flag.DefValue != "0" || flag.Value.Type() != "uint16" {
			t.Fatalf("%s must be a uint16 flag defaulting to zero: %v", name, flag)
		}
	}
}

func TestServerRelayPortValidationBeforeSideEffects(t *testing.T) {
	t.Setenv("OHECO_BROKER_ADMIN_TOKEN", "isolated-cli-port-test-admin")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"min-only", []string{"--turn-relay-min-port=53000"}, "must both be zero"},
		{"max-only", []string{"--turn-relay-max-port=53199"}, "must both be zero"},
		{"min-zero", []string{"--turn-relay-min-port=0", "--turn-relay-max-port=53199"}, "must both be zero"},
		{"max-zero", []string{"--turn-relay-min-port=53000", "--turn-relay-max-port=0"}, "must both be zero"},
		{"reversed", []string{"--turn-relay-min-port=53199", "--turn-relay-max-port=53000"}, "min <= max"},
		{"disabled-invalid", []string{"--turn=false", "--turn-relay-min-port=53000"}, "must both be zero"},
		{"min-negative", []string{"--turn-relay-min-port=-1"}, "invalid argument"},
		{"max-negative", []string{"--turn-relay-max-port=-1"}, "invalid argument"},
		{"min-overflow", []string{"--turn-relay-min-port=65536"}, "invalid argument"},
		{"max-overflow", []string{"--turn-relay-max-port=65536"}, "invalid argument"},
		{"min-huge", []string{"--turn-relay-min-port=18446744073709551616"}, "invalid argument"},
		{"max-huge", []string{"--turn-relay-max-port=18446744073709551616"}, "invalid argument"},
		{"min-text", []string{"--turn-relay-min-port=invalid"}, "invalid argument"},
		{"max-text", []string{"--turn-relay-max-port=invalid"}, "invalid argument"},
		{"min-fraction", []string{"--turn-relay-min-port=1.5"}, "invalid argument"},
		{"max-fraction", []string{"--turn-relay-max-port=1.5"}, "invalid argument"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			db := filepath.Join(root, "state", "control.sqlite")
			server := serverCommands()
			server.SilenceUsage, server.SilenceErrors = true, true
			var output bytes.Buffer
			server.SetOut(&output)
			server.SetErr(&output)
			args := []string{"serve", "--listen=127.0.0.1:0", "--turn-listen=127.0.0.1:0", "--db=" + db}
			server.SetArgs(append(args, tt.args...))
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := server.ExecuteContext(ctx); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
			if _, err := os.Stat(filepath.Dir(db)); !os.IsNotExist(err) {
				t.Fatalf("invalid flags created database directory: %v", err)
			}
			if strings.Contains(output.String(), "server_ready") {
				t.Fatal("invalid flags opened listeners")
			}
		})
	}
}

func TestServerRelayPortRangeBoundsAndEarlyValidation(t *testing.T) {
	t.Setenv("OHECO_BROKER_ADMIN_TOKEN", "")
	for _, tt := range []struct {
		name string
		min  string
		max  string
	}{
		{"ephemeral", "0", "0"},
		{"lowest", "1", "1"},
		{"highest", "65535", "65535"},
		{"full-range", "1", "65535"},
		{"deployment", "53000", "53199"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := serverCommands()
			server.SilenceUsage, server.SilenceErrors = true, true
			server.SetArgs([]string{"serve", "--turn-relay-min-port=" + tt.min, "--turn-relay-max-port=" + tt.max})
			if err := server.ExecuteContext(context.Background()); err == nil || !strings.Contains(err.Error(), "set OHECO_BROKER_ADMIN_TOKEN") {
				t.Fatalf("valid bounds must reach credential validation: %v", err)
			}
		})
	}
	// Invalid ranges must fail even before trying to read an admin token file.
	server := serverCommands()
	server.SilenceUsage, server.SilenceErrors = true, true
	server.SetArgs([]string{"serve", "--admin-token-file=" + filepath.Join(t.TempDir(), "missing"), "--turn-relay-min-port=53000"})
	if err := server.ExecuteContext(context.Background()); err == nil || !strings.Contains(err.Error(), "must both be zero") {
		t.Fatalf("range validation did not precede credential I/O: %v", err)
	}
}

type serverPortReadyOutput struct{ ready chan []byte }

func (w serverPortReadyOutput) Write(p []byte) (int, error) {
	select {
	case w.ready <- append([]byte(nil), p...):
	default:
	}
	return len(p), nil
}

// Hold two consecutive UDP ports until both the server and client transports
// have bound their random ports. No fixed deployment ports are used by tests.
func serverPortProbeRange(t *testing.T) (int, int, func()) {
	t.Helper()
	for range 100 {
		first, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		min := first.LocalAddr().(*net.UDPAddr).Port
		if min == 65535 {
			first.Close()
			continue
		}
		second, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: min + 1})
		if err != nil {
			first.Close()
			continue
		}
		release := func() { first.Close(); second.Close() }
		t.Cleanup(release)
		return min, min + 1, release
	}
	t.Fatal("could not reserve two consecutive unused UDP ports")
	return 0, 0, nil
}

func serverPortAPICall(t *testing.T, client *http.Client, api, method, path, token string, body any, status int) map[string]any {
	t.Helper()
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequest(method, api+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		t.Fatalf("%s %s status=%d, want=%d", method, path, response.StatusCode, status)
	}
	var result map[string]any
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestServerRelayPortsActualAllocation(t *testing.T) {
	const admin = "isolated-cli-port-test-admin"
	t.Setenv("OHECO_BROKER_ADMIN_TOKEN", admin)
	min, max, release := serverPortProbeRange(t)
	server := serverCommands()
	server.SilenceUsage, server.SilenceErrors = true, true
	ready := make(chan []byte, 1)
	server.SetOut(serverPortReadyOutput{ready: ready})
	server.SetErr(io.Discard)
	server.SetArgs([]string{
		"serve", "--listen=127.0.0.1:0", "--turn-listen=127.0.0.1:0", "--turn-public-ip=127.0.0.1",
		"--db=" + filepath.Join(t.TempDir(), "state", "control.sqlite"), "--registration=open",
		fmt.Sprintf("--turn-relay-min-port=%d", min), fmt.Sprintf("--turn-relay-max-port=%d", max),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	done := make(chan struct{})
	var serveErr error
	go func() { serveErr = server.ExecuteContext(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		timer := time.NewTimer(7 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
			if serveErr != nil {
				t.Errorf("server shutdown: %v", serveErr)
			}
		case <-timer.C:
			t.Error("server did not stop after cancellation")
		}
	})
	var event struct {
		Event string `json:"event"`
		API   string `json:"api"`
		TURN  string `json:"stun_turn"`
	}
	select {
	case data := <-ready:
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatal(err)
		}
		if event.Event != "server_ready" || event.API == "" || event.TURN == "" {
			t.Fatalf("invalid ready event: %+v", event)
		}
	case <-done:
		t.Fatalf("server exited before readiness: %v", serveErr)
	case <-ctx.Done():
		t.Fatal("server did not become ready")
	}
	transport := &http.Transport{Proxy: nil}
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	call := func(method, path, token string, body any, status int) map[string]any {
		return serverPortAPICall(t, httpClient, event.API, method, path, token, body, status)
	}
	registration := call("POST", "/v1/tenants/register", "", map[string]any{"name": "cli-port-range", "password": "isolated-port-range-password"}, 201)
	tenantID := registration["tenant"].(map[string]any)["id"].(string)
	account := registration["token"].(string)
	call("POST", "/v1/admin/tenants/"+tenantID+"/relay", admin, map[string]any{"enabled": true}, 200)
	broker := call("POST", "/v1/brokers", account, map[string]any{"name": "port-range-host"}, 201)
	brokerID := broker["broker"].(map[string]any)["id"].(string)
	device := broker["device_token"].(string)
	session := call("POST", "/v1/sessions", account, map[string]any{"broker_id": brokerID, "relay_mode": "force"}, 201)
	sessionID := session["session_id"].(string)
	sessionToken := session["session_token"].(string)
	call("POST", "/v1/sessions/"+sessionID+"/approve", device, map[string]any{"peer_authenticated": true, "relay": true}, 200)

	// A third client exercises exhaustion: the range must never silently fall
	// back to a kernel-selected ephemeral relay port.
	clients := make([]*turn.Client, 3)
	for i := range clients {
		credentials := call("POST", "/v1/sessions/"+sessionID+"/turn", sessionToken, nil, 200)
		urls := credentials["urls"].([]any)
		if len(urls) != 1 || urls[0] != "turn:"+event.TURN+"?transport=udp" {
			t.Fatalf("TURN credential URL does not match actual listener: %v", urls)
		}
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		logger := logging.NewDefaultLoggerFactory()
		logger.DefaultLogLevel = logging.LogLevelError
		client, err := turn.NewClient(&turn.ClientConfig{
			Conn: conn, STUNServerAddr: event.TURN, TURNServerAddr: event.TURN,
			Username: credentials["username"].(string), Password: credentials["password"].(string),
			Realm: "oheco-broker", RTO: 10 * time.Millisecond, LoggerFactory: logger,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		if err := client.Listen(); err != nil {
			t.Fatal(err)
		}
		mapped, err := client.SendBindingRequest()
		if err != nil || mapped.String() != conn.LocalAddr().String() {
			t.Fatalf("STUN binding = %v, %v; want %s", mapped, err, conn.LocalAddr())
		}
		clients[i] = client
	}
	release()
	allocated := make(map[int]bool)
	for _, client := range clients[:2] {
		relay, err := client.Allocate()
		if err != nil {
			t.Fatal("TURN allocation:", err)
		}
		t.Cleanup(func() { relay.Close() })
		addr := relay.LocalAddr().(*net.UDPAddr)
		if addr.Port < min || addr.Port > max || allocated[addr.Port] || !addr.IP.IsLoopback() {
			t.Fatalf("relay = %s, want unique loopback port in %d-%d", addr, min, max)
		}
		allocated[addr.Port] = true
	}
	if relay, err := clients[2].Allocate(); err == nil {
		relay.Close()
		t.Fatal("allocated outside an exhausted two-port range")
	}
	t.Logf("actual CLI credential/STUN/TURN allocations used both ports %d-%d; third allocation rejected", min, max)
}
