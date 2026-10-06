package remote

/*
#include <stdlib.h>
#include "auth_bridge.h"
*/
import "C"

import (
	"errors"
	"runtime/cgo"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type AuthCredentials struct {
	AuthSessionID    string    `json:"auth_session_id"`
	Token            string    `json:"token"`
	RefreshToken     string    `json:"refresh_token"`
	Generation       uint64    `json:"generation"`
	TokenExpiresAt   time.Time `json:"token_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}
type AuthPending struct {
	AuthSessionID      string `json:"auth_session_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	RequestID          string `json:"request_id"`
	NextToken          string `json:"next_token"`
	NextRefreshToken   string `json:"next_refresh_token"`
}

// AuthStorage coordinates a shared credential store. End runs unconditionally
// after Begin, including Begin failure. Hooks must be bounded and must not call
// RefreshAuth, Close, or close borrowed peers/servers from a hook. Snapshot
// inspection through AuthCredentials is safe. Prepare saves the exact attempt BEFORE
// RPC; Commit saves confirmed credentials BEFORE removing the pending record.
// Callbacks execute outside native peer/client locks; SDK performs no disk I/O.
type AuthStorage interface {
	Begin() (AuthCredentials, *AuthPending, error)
	Prepare(AuthCredentials, AuthPending) error
	Commit(AuthCredentials, AuthPending) error
	End()
}
type AuthOptions struct {
	Credentials   AuthCredentials
	Storage       AuthStorage
	RefreshBefore time.Duration
}

type authStorageBridge struct {
	storage AuthStorage
	mu      sync.Mutex
	last    error
}

func (b *authStorageBridge) failed(err error) C.int {
	b.mu.Lock()
	b.last = err
	b.mu.Unlock()
	return 1
}

// StorageError preserves caller storage errors for errors.Is/As without putting
// credentials or caller-controlled error strings in SDK diagnostics.
type StorageError struct{ Cause error }

func (e *StorageError) Error() string { return "remote: credential storage failed" }
func (e *StorageError) Unwrap() error { return e.Cause }
func bridge(handle C.uintptr_t) *authStorageBridge {
	return cgo.Handle(handle).Value().(*authStorageBridge)
}
func copyString(out []C.char, value string) error {
	if strings.IndexByte(value, 0) >= 0 || len(value) >= len(out) {
		return errors.New("remote: invalid credential field")
	}
	clear(out)
	for i := range value {
		out[i] = C.char(value[i])
	}
	return nil
}
func credentialsToC(value AuthCredentials) (C.ob_auth_credentials, error) {
	var result C.ob_auth_credentials
	if err := copyString(result.auth_session_id[:], value.AuthSessionID); err != nil {
		return result, err
	}
	if err := copyString(result.token[:], value.Token); err != nil {
		return result, err
	}
	if err := copyString(result.refresh_token[:], value.RefreshToken); err != nil {
		return result, err
	}
	if value.TokenExpiresAt.IsZero() || value.RefreshExpiresAt.IsZero() {
		return result, errors.New("remote: missing credential deadlines")
	}
	result.generation = C.uint64_t(value.Generation)
	result.token_expires_at_ms = C.int64_t(value.TokenExpiresAt.UnixMilli())
	result.refresh_expires_at_ms = C.int64_t(value.RefreshExpiresAt.UnixMilli())
	return result, nil
}
func credentialsFromC(c *C.ob_auth_credentials) AuthCredentials {
	return AuthCredentials{AuthSessionID: C.GoString(&c.auth_session_id[0]), Token: C.GoString(&c.token[0]),
		RefreshToken: C.GoString(&c.refresh_token[0]), Generation: uint64(c.generation),
		TokenExpiresAt: time.UnixMilli(int64(c.token_expires_at_ms)).UTC(), RefreshExpiresAt: time.UnixMilli(int64(c.refresh_expires_at_ms)).UTC()}
}
func pendingToC(value AuthPending) (C.ob_auth_pending, error) {
	var result C.ob_auth_pending
	if err := copyString(result.auth_session_id[:], value.AuthSessionID); err != nil {
		return result, err
	}
	if err := copyString(result.request_id[:], value.RequestID); err != nil {
		return result, err
	}
	if err := copyString(result.next_token[:], value.NextToken); err != nil {
		return result, err
	}
	if err := copyString(result.next_refresh_token[:], value.NextRefreshToken); err != nil {
		return result, err
	}
	result.expected_generation = C.uint64_t(value.ExpectedGeneration)
	return result, nil
}
func pendingFromC(p *C.ob_auth_pending) AuthPending {
	return AuthPending{AuthSessionID: C.GoString(&p.auth_session_id[0]), RequestID: C.GoString(&p.request_id[0]),
		ExpectedGeneration: uint64(p.expected_generation), NextToken: C.GoString(&p.next_token[0]), NextRefreshToken: C.GoString(&p.next_refresh_token[0])}
}

//export go_ob_auth_begin
func go_ob_auth_begin(handle C.uintptr_t, c *C.ob_auth_credentials, p *C.ob_auth_pending, present *C.int) (result C.int) {
	b := bridge(handle)
	defer func() {
		if recover() != nil {
			result = b.failed(errors.New("remote: storage Begin panicked"))
		}
	}()
	value, pending, err := b.storage.Begin()
	if err != nil {
		return b.failed(err)
	}
	native, err := credentialsToC(value)
	if err != nil {
		return b.failed(err)
	}
	*c = native
	*present = 0
	if pending != nil {
		nativePending, err := pendingToC(*pending)
		if err != nil {
			return b.failed(err)
		}
		*p = nativePending
		*present = 1
	}
	return 0
}

//export go_ob_auth_prepare
func go_ob_auth_prepare(handle C.uintptr_t, c *C.ob_auth_credentials, p *C.ob_auth_pending) (result C.int) {
	b := bridge(handle)
	defer func() {
		if recover() != nil {
			result = b.failed(errors.New("remote: storage Prepare panicked"))
		}
	}()
	if err := b.storage.Prepare(credentialsFromC(c), pendingFromC(p)); err != nil {
		return b.failed(err)
	}
	return 0
}

//export go_ob_auth_commit
func go_ob_auth_commit(handle C.uintptr_t, c *C.ob_auth_credentials, p *C.ob_auth_pending) (result C.int) {
	b := bridge(handle)
	defer func() {
		if recover() != nil {
			result = b.failed(errors.New("remote: storage Commit panicked"))
		}
	}()
	if err := b.storage.Commit(credentialsFromC(c), pendingFromC(p)); err != nil {
		return b.failed(err)
	}
	return 0
}

//export go_ob_auth_end
func go_ob_auth_end(handle C.uintptr_t) {
	b := bridge(handle)
	defer func() {
		if recover() != nil {
			b.failed(errors.New("remote: storage End panicked"))
		}
	}()
	b.storage.End()
}

// NewWithAuth creates a stable native client with an independent refresh timer.
// It never logs in with a password. The timer and callbacks are joined on Close;
// peers/servers must be closed first, as for a legacy Client.
func NewWithAuth(options Options, auth AuthOptions) (*Client, error) {
	for label, value := range map[string]string{"URL": options.URL, "token": options.Token, "CA file": options.CAFile} {
		if err := text(label, value); err != nil {
			return nil, err
		}
	}
	if err := duration("HTTP timeout", options.Timeout); err != nil {
		return nil, err
	}
	if options.Token != "" && options.Token != auth.Credentials.Token {
		return nil, errors.New("remote: access credential mismatch")
	}
	if auth.RefreshBefore < 0 || auth.RefreshBefore%time.Millisecond != 0 {
		return nil, errors.New("remote: refresh lead must be nonnegative whole milliseconds")
	}
	native, err := credentialsToC(auth.Credentials)
	if err != nil {
		return nil, err
	}
	defer C.ob_auth_credentials_clear(&native)
	url := C.CString(options.URL)
	defer C.free(unsafe.Pointer(url))
	var ca *C.char
	if options.CAFile != "" {
		ca = C.CString(options.CAFile)
		defer C.free(unsafe.Pointer(ca))
	}
	base := C.ob_api_options{base_url: url, ca_file: ca, timeout_ms: C.long(options.Timeout.Milliseconds())}
	config := C.ob_auth_options{struct_size: C.uint32_t(C.sizeof_ob_auth_options), version: 1, credentials: native, refresh_before_ms: C.int64_t(auth.RefreshBefore.Milliseconds())}
	var handle cgo.Handle
	if auth.Storage != nil {
		handle = cgo.NewHandle(&authStorageBridge{storage: auth.Storage})
		C.ob_go_auth_storage_init(&config, C.uintptr_t(handle))
	}
	var diag C.ob_api_error
	ptr := C.ob_api_client_create_with_auth(&base, &config, &diag)
	C.ob_auth_credentials_clear(&config.credentials)
	if ptr == nil {
		if handle != 0 {
			handle.Delete()
		}
		return nil, apiError(&diag)
	}
	client := &Client{ptr: ptr, authHandle: handle}
	client.cond = sync.NewCond(&client.mu)
	return client, nil
}
func (c *Client) AuthCredentials() (AuthCredentials, error) {
	ptr, err := c.beginRequest()
	if err != nil {
		return AuthCredentials{}, err
	}
	defer c.endRequest()
	var value C.ob_auth_credentials
	var diag C.ob_api_error
	if C.ob_auth_manager_snapshot(C.ob_api_client_auth_manager(ptr), &value, &diag) != 0 {
		return AuthCredentials{}, apiError(&diag)
	}
	defer C.ob_auth_credentials_clear(&value)
	return credentialsFromC(&value), nil
}
func (c *Client) RefreshAuth() error {
	ptr, err := c.beginRequest()
	if err != nil {
		return err
	}
	defer c.endRequest()
	var diag C.ob_api_error
	if C.ob_auth_manager_refresh(C.ob_api_client_auth_manager(ptr), 1, &diag) != 0 {
		return c.authError(&diag)
	}
	return nil
}
func (c *Client) authError(diag *C.ob_api_error) error {
	if diag.code == C.OB_API_STORAGE && c.authHandle != 0 {
		b := c.authHandle.Value().(*authStorageBridge)
		b.mu.Lock()
		cause := b.last
		b.mu.Unlock()
		if cause != nil {
			return &StorageError{Cause: cause}
		}
	}
	return apiError(diag)
}
