package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestGeneratedCredentials(t *testing.T) {
	pattern := regexp.MustCompile(`^tenant-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for range 128 {
		name, pw, err := generatedCredentials()
		if err != nil {
			t.Fatal(err)
		}
		if !pattern.MatchString(name) || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(pw) {
			t.Fatal("invalid generated format")
		}
		if seen[name] || seen[pw] {
			t.Fatal("reused random credential")
		}
		seen[name] = true
		seen[pw] = true
	}
}
func TestPrivateConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "account.json")
	want := config{Version: 1, API: "http://127.0.0.1:8080", Account: account{ID: "id", Name: "tenant-test", Password: "private-test-password", Email: "test@example.invalid", Token: "private-test-token"}}
	if err := saveConfig(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("configuration did not roundtrip")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("credentials not0600")
	}
	want.Account.Token = "replacement"
	if err = saveConfig(path, want); err != nil {
		t.Fatal(err)
	}
	got, err = loadConfig(path)
	if err != nil || got.Account.Token != "replacement" {
		t.Fatal("replacement failed")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".account-*"))
	if err != nil || len(matches) != 0 {
		t.Fatal("temporary secret file leaked")
	}
}
func TestPrivateConfigRejectsUnsafePaths(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.Mkdir(shared, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0770); err != nil {
		t.Fatal(err)
	}
	if err := privateDirectory(filepath.Join(shared, "account.json")); err == nil {
		t.Fatal("accepted shared directory")
	}
	path := filepath.Join(root, "account.json")
	if err := os.WriteFile(path, []byte(`{}`), 0660); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("accepted shared credentials")
	}
	cfg := config{Version: 1, API: "http://127.0.0.1:8080"}
	if err := saveConfig(path, cfg); err == nil {
		t.Fatal("replaced unsafe existing file")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "elsewhere"), path); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(path, cfg); err == nil {
		t.Fatal("followed credential symlink")
	}
}
func TestConfigStrictJSON(t *testing.T) {
	path := privateTestProfile(t)
	for _, raw := range []string{`{"version":1,"api":"http://127.0.0.1","extra":1}`, `{"version":1,"api":"http://127.0.0.1"} {}`, `{"version":2,"api":"http://127.0.0.1"}`, strings.Repeat("x", 65537)} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatal("accepted invalid configuration")
		}
	}
	var decoded any
	if err := json.Unmarshal([]byte(`{"safe":true}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"api":"http://127.0.0.1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatalf("valid configuration must reach parser: %v", err)
	}
}
func TestConfigPathUsesXDG(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	path, err := configPath("")
	if err != nil || path != filepath.Join(root, "oheco-broker", "account.json") {
		t.Fatal("not using XDG")
	}
	t.Setenv("XDG_CONFIG_HOME", "relative")
	if _, err = configPath(""); err == nil {
		t.Fatal("accepted relative XDG")
	}
}
