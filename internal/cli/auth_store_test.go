package cli

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/oheco/oheco-broker/sdk/go/remote"
)

func testRefreshProfile(t *testing.T) (string, config) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private", "account.json")
	cfg := config{API: "http://127.0.0.1:8080", Account: account{ID: "01234567-89ab-4cde-8fab-0123456789ab", Name: "refresh-test"}}
	cfg.setAuthCredentials(remote.AuthCredentials{AuthSessionID: "11234567-89ab-4cde-8fab-0123456789ab",
		Token: strings.Repeat("a", 64), RefreshToken: strings.Repeat("b", 64), Generation: 1,
		TokenExpiresAt:   time.Now().UTC().Truncate(time.Millisecond).Add(time.Hour),
		RefreshExpiresAt: time.Now().UTC().Truncate(time.Millisecond).Add(30 * 24 * time.Hour)})
	if err := saveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	return path, cfg
}
func testPending(cfg config) remote.AuthPending {
	return remote.AuthPending{AuthSessionID: cfg.Auth.AuthSessionID, ExpectedGeneration: cfg.Auth.Generation,
		RequestID: "21234567-89ab-4cde-8fab-0123456789ab", NextToken: strings.Repeat("c", 64), NextRefreshToken: strings.Repeat("d", 64)}
}
func committedCredentials(cfg config, pending remote.AuthPending) remote.AuthCredentials {
	return remote.AuthCredentials{AuthSessionID: pending.AuthSessionID, Token: pending.NextToken,
		RefreshToken: pending.NextRefreshToken, Generation: pending.ExpectedGeneration + 1,
		TokenExpiresAt: cfg.Auth.TokenExpiresAt.Add(time.Minute), RefreshExpiresAt: cfg.Auth.RefreshExpiresAt.Add(time.Minute)}
}
func TestRefreshProfileWithoutPassword(t *testing.T) {
	path, cfg := testRefreshProfile(t)
	got, err := loadConfig(path)
	if err != nil || !reflect.DeepEqual(got, cfg) {
		t.Fatal("refresh profile did not roundtrip")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "password") {
		t.Fatal("refresh profile persisted an account password")
	}
	cfg.Account.Password = "must-not-be-persisted"
	if err := saveConfig(path, cfg); err == nil {
		t.Fatal("accepted a password in a refresh profile")
	}
}
func TestRefreshStorageRecoversPreparedAttempt(t *testing.T) {
	path, cfg := testRefreshProfile(t)
	pending := testPending(cfg)
	store := newProfileAuthStorage(path, cfg, false)
	credentials, previous, err := store.Begin()
	if err == nil && previous != nil {
		t.Fatal("unexpected pending refresh")
	}
	if err == nil {
		err = store.Prepare(credentials, pending)
	}
	store.End()
	if err != nil {
		t.Fatal(err)
	}
	// Simulate losing the reply or crashing after server commit: only the
	// durable candidate request, not any new plaintext from the server, survives.
	restarted := newProfileAuthStorage(path, cfg, false)
	credentials, previous, err = restarted.Begin()
	if err != nil {
		restarted.End()
		t.Fatal(err)
	}
	if previous == nil || *previous != pending || credentials != cfg.authCredentials() {
		restarted.End()
		t.Fatal("did not recover exact prepared refresh")
	}
	err = restarted.Commit(committedCredentials(cfg, pending), pending)
	restarted.End()
	if err != nil {
		t.Fatal(err)
	}
	got, err := loadConfig(path)
	if err != nil || got.Auth.Generation != 2 || got.Account.Token != pending.NextToken {
		t.Fatal("receipt was not persisted")
	}
	if _, err = os.Stat(path + ".refresh-pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("committed journal remains")
	}
}
func TestRefreshStorageCrashAfterProfileCommit(t *testing.T) {
	path, cfg := testRefreshProfile(t)
	pending := testPending(cfg)
	store := newProfileAuthStorage(path, cfg, false)
	credentials, _, err := store.Begin()
	if err == nil {
		err = store.Prepare(credentials, pending)
	}
	store.End()
	if err != nil {
		t.Fatal(err)
	}
	cfg.setAuthCredentials(committedCredentials(cfg, pending))
	if err = saveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	// Crash between the durable profile rename and journal unlink.
	restarted := newProfileAuthStorage(path, cfg, false)
	credentials, previous, err := restarted.Begin()
	restarted.End()
	if err != nil || previous != nil || credentials.Generation != 2 || credentials.Token != pending.NextToken {
		t.Fatal("did not adopt durable successor after interrupted journal cleanup")
	}
	if _, err = os.Stat(path + ".refresh-pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale journal remains")
	}
}
func TestRefreshStorageCannotOverwriteDifferentLogin(t *testing.T) {
	path, cfg := testRefreshProfile(t)
	store := newProfileAuthStorage(path, cfg, false)
	changed := cfg
	changed.Auth = &authProfile{}
	*changed.Auth = *cfg.Auth
	changed.Auth.AuthSessionID = "31234567-89ab-4cde-8fab-0123456789ab"
	if err := saveConfig(path, changed); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.Begin()
	store.End()
	if err == nil {
		t.Fatal("silently adopted another login authority")
	}
	got, err := loadConfig(path)
	if err != nil || got.Auth.AuthSessionID != changed.Auth.AuthSessionID {
		t.Fatal("replaced a newer login")
	}
	release, err := acquireProfile(path)
	if err != nil {
		t.Fatal("failed Begin left the profile locked")
	}
	release()
}
func TestRefreshStorageRejectsDifferentReceiptAndUnsafeJournal(t *testing.T) {
	path, cfg := testRefreshProfile(t)
	pending := testPending(cfg)
	store := newProfileAuthStorage(path, cfg, false)
	credentials, _, err := store.Begin()
	if err == nil {
		err = store.Prepare(credentials, pending)
	}
	if err != nil {
		store.End()
		t.Fatal(err)
	}
	wrong := committedCredentials(cfg, pending)
	wrong.Token = strings.Repeat("e", 64)
	if err = store.Commit(wrong, pending); err == nil {
		store.End()
		t.Fatal("accepted a mismatched receipt")
	}
	store.End()
	got, err := loadConfig(path)
	if err != nil || got.Auth.Generation != 1 {
		t.Fatal("mismatched receipt modified profile")
	}
	if err = os.Remove(path + ".refresh-pending"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(path, path+".refresh-pending"); err != nil {
		t.Fatal(err)
	}
	_, _, err = store.Begin()
	store.End()
	if err == nil {
		t.Fatal("followed a pending credential symlink")
	}
}
func TestRefreshStorageBorrowedCommandLock(t *testing.T) {
	path, cfg := testRefreshProfile(t)
	o := &rootOptions{config: path}
	release, err := o.lockProfile()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	store := newProfileAuthStorage(path, cfg, o.profileLocked)
	_, _, err = store.Begin()
	store.End()
	if err != nil {
		t.Fatal("borrowed command lock was reacquired")
	}
	if other, err := acquireProfile(path); err == nil {
		other()
		t.Fatal("storage released the outer command lock")
	}
}
