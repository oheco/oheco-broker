package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func privateTestProfile(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "account.json")
}
func TestProfileLockIsExclusiveAndCrashSafeKernelOwned(t *testing.T) {
	path := privateTestProfile(t)
	release, err := acquireProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := acquireProfile(path); err == nil {
		other()
		release()
		t.Fatal("same profile acquired twice")
	}
	if other, err := acquireProfile(path + ".pending"); err == nil {
		other()
		release()
		t.Fatal("recovery profile used a different lock")
	}
	release()
	next, err := acquireProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	next()
	if err = os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("elsewhere", path+".lock"); err != nil {
		t.Fatal(err)
	}
	if other, err := acquireProfile(path); err == nil {
		other()
		t.Fatal("followed profile-lock symlink")
	}
}
func TestConcurrentRegistrationDoesNotOverwritePendingRecovery(t *testing.T) {
	path := privateTestProfile(t)
	started, finish := make(chan struct{}), make(chan struct{})
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		var credentials struct{ Name, Password string }
		if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		close(started)
		<-finish
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tenant": map[string]string{"id": "12345678-1234-4234-8234-123456789abc", "name": credentials.Name}, "token": "isolated-profile-test-token"})
	}))
	defer server.Close()
	result := make(chan error, 1)
	command := []string{"--api", server.URL, "--config", path, "tenant", "register"}
	go func() {
		result <- Execute(context.Background(), command, "test", func(context.Context) error { return nil })
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(finish)
		t.Fatal("registration request did not start")
	}
	draft, err := loadConfig(path + ".pending")
	if err != nil {
		close(finish)
		t.Fatal(err)
	}
	otherErr := Execute(context.Background(), command, "test", func(context.Context) error { return nil })
	if otherErr == nil || !strings.Contains(otherErr.Error(), "being modified") {
		close(finish)
		t.Fatalf("parallel profile mutation was not rejected: %v", otherErr)
	}
	after, err := loadConfig(path + ".pending")
	if err != nil || after.Account != draft.Account {
		close(finish)
		t.Fatal("parallel registration changed pending credentials")
	}
	close(finish)
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	saved, err := loadConfig(path)
	if err != nil || saved.Account.Password != draft.Account.Password || count.Load() != 1 {
		t.Fatal("registration lost original credentials or sent extra request")
	}
	if _, err = os.Stat(path + ".pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful registration left pending secrets")
	}
}
