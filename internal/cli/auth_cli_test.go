package cli

import (
	"bytes"
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oheco/oheco-broker/internal/control"
	"github.com/spf13/cobra"
)

func runAuthCommand(t *testing.T, command *cobra.Command, args []string, input string) string {
	t.Helper()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetIn(strings.NewReader(input))
	command.SetArgs(args)
	command.SilenceUsage, command.SilenceErrors = true, true
	if err := command.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

// Exercise the actual CLI/storage/native SDK against SQLite. Explicit login can
// migrate an invalid legacy bearer with its saved password, while routine RPCs
// never silently password-login. Identity/password replacement must preserve v2.
func TestAuthCLILegacyMigrationAndCredentialChanges(t *testing.T) {
	service, err := control.New(control.Config{DBPath: filepath.Join(t.TempDir(), "server", "control.sqlite"),
		AdminToken: "isolated-auth-cli-admin-token", RegistrationPolicy: "open"})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := httptest.NewServer(service.Handler())
	defer server.Close()
	path := filepath.Join(t.TempDir(), "client", "account.json")
	o := &rootOptions{api: server.URL, config: path}
	password := "isolated-auth-cli-password-one"
	output := runAuthCommand(t, registration(o, false), []string{"--legacy-auth", "--name", "cli-refresh-migration", "--password-stdin"}, password+"\n")
	cfg, err := loadConfig(path)
	if err != nil || cfg.Version != 1 || cfg.Account.Password != password {
		t.Fatal("legacy registration contract changed")
	}
	if strings.Contains(output, password) || strings.Contains(output, cfg.Account.Token) {
		t.Fatal("registration printed credentials")
	}
	// Its old access token is unusable; only an explicit login may use password.
	cfg.Account.Token = strings.Repeat("a", 64)
	if err = saveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	runAuthCommand(t, registration(o, true), nil, "")
	cfg, err = loadConfig(path)
	if err != nil || cfg.Version != 2 || cfg.Auth == nil || cfg.Account.Password != "" {
		t.Fatal("explicit login did not migrate the profile")
	}
	firstID := cfg.Auth.AuthSessionID
	firstToken := cfg.Account.Token
	output = runAuthCommand(t, accountUpdate(o), []string{"--name", "cli-refresh-renamed"}, "")
	cfg, err = loadConfig(path)
	if err != nil || cfg.Account.Name != "cli-refresh-renamed" || cfg.Auth == nil || cfg.Auth.AuthSessionID == firstID || cfg.Auth.Generation != 1 {
		t.Fatal("account identity update lost replacement refresh authority")
	}
	if strings.Contains(output, cfg.Account.Token) || strings.Contains(output, cfg.Auth.RefreshToken) {
		t.Fatal("identity response printed secrets")
	}
	secondID := cfg.Auth.AuthSessionID
	output = runAuthCommand(t, accountPassword(o), []string{"--password-stdin"}, "isolated-auth-cli-password-two\n")
	cfg, err = loadConfig(path)
	if err != nil || cfg.Auth == nil || cfg.Auth.AuthSessionID == secondID || cfg.Account.Password != "" {
		t.Fatal("password update lost refresh authority or stored password")
	}
	if strings.Contains(output, cfg.Account.Token) || strings.Contains(output, cfg.Auth.RefreshToken) {
		t.Fatal("password response printed secrets")
	}
	runAuthCommand(t, accountShow(o), nil, "")
	// Original authority is revoked, independently of its old TTL.
	request := httptest.NewRequest("GET", "/v1/me", nil)
	request.Header.Set("Authorization", "Bearer "+firstToken)
	reply := httptest.NewRecorder()
	service.Handler().ServeHTTP(reply, request)
	if reply.Code != 401 {
		t.Fatal("old authority survived credential changes")
	}
}
