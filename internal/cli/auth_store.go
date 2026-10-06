package cli

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oheco/oheco-broker/sdk/go/remote"
)

// authProfile keeps the access token in account.token, with no duplicate secret.
// Version1 has no auth object; old strict clients use a separate legacy profile.
type authProfile struct {
	AuthSessionID    string    `json:"auth_session_id"`
	RefreshToken     string    `json:"refresh_token"`
	Generation       uint64    `json:"generation"`
	TokenExpiresAt   time.Time `json:"token_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

func supportsAuthRefresh(client *remote.Client) (bool, error) {
	empty := ""
	raw, err := client.Request("GET", "/v1/status", &empty, nil)
	if err != nil {
		var remoteErr *remote.Error
		if errors.As(err, &remoteErr) && remoteErr.HTTPStatus == 404 {
			return false, nil
		}
		return false, err
	}
	var discovery struct {
		Protocol string `json:"account_refresh_protocol"`
	}
	if err = json.Unmarshal(raw, &discovery); err != nil {
		return false, err
	}
	if discovery.Protocol == "" {
		return false, nil
	}
	if discovery.Protocol != "refresh-v1" {
		return false, errors.New("unsupported account refresh protocol")
	}
	return true, nil
}

func validAuthSecret(secret string) bool {
	if len(secret) != 64 || strings.ToLower(secret) != secret {
		return false
	}
	_, err := hex.DecodeString(secret)
	return err == nil
}
func validAuthUUID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validateAuthProfile(cfg config) error {
	if cfg.Version != 2 {
		if cfg.Auth != nil {
			return errors.New("legacy profile cannot contain refresh authority")
		}
		return nil
	}
	if cfg.Account.ID == "" || cfg.Account.Name == "" || cfg.Account.Password != "" {
		return errors.New("refresh profile needs account identity and must not store an account password")
	}
	if cfg.Auth == nil && cfg.Account.Token == "" {
		return nil
	} // explicitly logged out
	if cfg.Auth == nil || !validAuthUUID(cfg.Auth.AuthSessionID) || cfg.Auth.Generation == 0 ||
		!validAuthSecret(cfg.Account.Token) || !validAuthSecret(cfg.Auth.RefreshToken) ||
		cfg.Account.Token == cfg.Auth.RefreshToken || cfg.Auth.TokenExpiresAt.IsZero() || cfg.Auth.RefreshExpiresAt.IsZero() {
		return errors.New("incomplete or invalid refresh credentials")
	}
	return nil
}
func (cfg config) authCredentials() remote.AuthCredentials {
	if cfg.Auth == nil {
		return remote.AuthCredentials{}
	}
	return remote.AuthCredentials{AuthSessionID: cfg.Auth.AuthSessionID, Token: cfg.Account.Token,
		RefreshToken: cfg.Auth.RefreshToken, Generation: cfg.Auth.Generation,
		TokenExpiresAt: cfg.Auth.TokenExpiresAt, RefreshExpiresAt: cfg.Auth.RefreshExpiresAt}
}
func (cfg *config) setAuthCredentials(credentials remote.AuthCredentials) {
	cfg.Version = 2
	cfg.Account.Password = ""
	cfg.Account.Token = credentials.Token
	cfg.Auth = &authProfile{AuthSessionID: credentials.AuthSessionID, RefreshToken: credentials.RefreshToken,
		Generation: credentials.Generation, TokenExpiresAt: credentials.TokenExpiresAt,
		RefreshExpiresAt: credentials.RefreshExpiresAt}
}

type refreshPendingRecord struct {
	Version   int                `json:"version"`
	API       string             `json:"api"`
	AccountID string             `json:"account_id"`
	Pending   remote.AuthPending `json:"pending"`
}

// This adapter holds the original profile lock from Begin through End, including
// durable prepare and the network transaction. C never owns filesystem state.
type profileAuthStorage struct {
	mu                              sync.Mutex
	path, api, accountID, sessionID string
	borrowedLock                    bool
	release                         func()
	current                         config
	attempt                         *remote.AuthPending
}

func newProfileAuthStorage(path string, cfg config, borrowed bool) *profileAuthStorage {
	return &profileAuthStorage{path: path, api: cfg.API, accountID: cfg.Account.ID,
		sessionID: cfg.Auth.AuthSessionID, borrowedLock: borrowed}
}
func (s *profileAuthStorage) pendingPath() string { return s.path + ".refresh-pending" }
func (s *profileAuthStorage) Begin() (remote.AuthCredentials, *remote.AuthPending, error) {
	s.mu.Lock()
	// End must follow Begin even on error; it releases any acquired coordination.
	if !s.borrowedLock {
		deadline := time.Now().Add(15 * time.Second)
		for {
			release, err := acquireProfile(s.path)
			if err == nil {
				s.release = release
				break
			}
			if !errors.Is(err, errProfileBusy) || !time.Now().Before(deadline) {
				return remote.AuthCredentials{}, nil, err
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	cfg, err := loadConfig(s.path)
	if err != nil {
		return remote.AuthCredentials{}, nil, err
	}
	if cfg.API != s.api || cfg.Account.ID != s.accountID || cfg.Auth == nil || cfg.Auth.AuthSessionID != s.sessionID {
		return remote.AuthCredentials{}, nil, errors.New("account login changed; restart this command with the current profile")
	}
	s.current = cfg
	s.attempt = nil
	var record refreshPendingRecord
	err = readPrivateJSON(s.pendingPath(), &record)
	if errors.Is(err, os.ErrNotExist) {
		return cfg.authCredentials(), nil, nil
	}
	if err != nil {
		return remote.AuthCredentials{}, nil, err
	}
	p := record.Pending
	if record.Version != 1 || record.API != s.api || record.AccountID != s.accountID ||
		p.AuthSessionID != s.sessionID || !validAuthUUID(p.RequestID) || p.ExpectedGeneration == 0 ||
		!validAuthSecret(p.NextToken) || !validAuthSecret(p.NextRefreshToken) || p.NextToken == p.NextRefreshToken {
		return remote.AuthCredentials{}, nil, errors.New("invalid pending credential refresh")
	}
	if p.ExpectedGeneration < cfg.Auth.Generation {
		// A durable newer profile is authoritative; an older journal cannot
		// overwrite it. This also finishes a crash after rename, before unlink.
		if err = removePrivatePending(s.pendingPath()); err != nil {
			return remote.AuthCredentials{}, nil, err
		}
		return cfg.authCredentials(), nil, nil
	}
	if p.ExpectedGeneration != cfg.Auth.Generation {
		return remote.AuthCredentials{}, nil, errors.New("pending refresh generation is ahead of the profile")
	}
	s.attempt = &p
	return cfg.authCredentials(), &p, nil
}
func (s *profileAuthStorage) Prepare(credentials remote.AuthCredentials, pending remote.AuthPending) error {
	if credentials.AuthSessionID != s.sessionID || pending.AuthSessionID != s.sessionID ||
		credentials.Generation != s.current.Auth.Generation || pending.ExpectedGeneration != credentials.Generation ||
		credentials.Token != s.current.Account.Token || credentials.RefreshToken != s.current.Auth.RefreshToken ||
		!validAuthUUID(pending.RequestID) || !validAuthSecret(pending.NextToken) || !validAuthSecret(pending.NextRefreshToken) ||
		pending.NextToken == pending.NextRefreshToken || pending.NextToken == credentials.Token || pending.NextRefreshToken == credentials.RefreshToken {
		return errors.New("credential refresh preparation does not match the locked profile")
	}
	if s.attempt != nil && *s.attempt != pending {
		return errors.New("refusing to replace an unresolved refresh attempt")
	}
	if err := savePrivateJSON(s.pendingPath(), refreshPendingRecord{Version: 1, API: s.api, AccountID: s.accountID, Pending: pending}); err != nil {
		return err
	}
	s.attempt = &pending
	return nil
}
func (s *profileAuthStorage) Commit(credentials remote.AuthCredentials, pending remote.AuthPending) error {
	if s.attempt == nil || *s.attempt != pending || credentials.AuthSessionID != s.sessionID ||
		credentials.Generation != pending.ExpectedGeneration+1 || credentials.Token != pending.NextToken ||
		credentials.RefreshToken != pending.NextRefreshToken {
		return errors.New("credential refresh receipt does not match the durable attempt")
	}
	latest, err := loadConfig(s.path)
	if err != nil {
		return err
	}
	if latest.API != s.api || latest.Account.ID != s.accountID || latest.Auth == nil ||
		latest.Auth.AuthSessionID != s.sessionID || latest.Auth.Generation != pending.ExpectedGeneration {
		return errors.New("account profile changed before credential refresh commit")
	}
	latest.setAuthCredentials(credentials)
	if err = saveConfig(s.path, latest); err != nil {
		return err
	}
	s.current = latest
	// Profile+directory are durable before the journal is removed.
	if err = removePrivatePending(s.pendingPath()); err != nil {
		return err
	}
	s.attempt = nil
	return nil
}
func (s *profileAuthStorage) End() {
	if s.release != nil {
		s.release()
		s.release = nil
	}
	s.mu.Unlock()
}
func readPrivateJSON(path string, value any) error {
	if err := privateDirectory(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return errors.New("pending credential file is unsafe")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Getuid()) {
		return errors.New("pending credentials belong to another user")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 || opened.Size() > 65536 {
		return errors.New("opened pending credential file is unsafe")
	}
	if stat, ok := opened.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Getuid()) {
		return errors.New("opened pending credentials belong to another user")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(value); err != nil {
		return errors.New("invalid pending credential JSON")
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return errors.New("pending credentials contain trailing data")
	}
	return nil
}
func removePrivatePending(path string) error {
	if info, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	} else if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("refusing to remove unsafe pending credentials")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
