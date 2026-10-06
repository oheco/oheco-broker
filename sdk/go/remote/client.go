// Package remote wraps the native C management and authenticated peer SDK.
// It does not implement a second ICE, TURN, QUIC or cryptographic stack.
package remote

/*
#cgo CFLAGS: -I${SRCDIR}/../../c/remote
#cgo LDFLAGS: -lob_remote
#include <stdlib.h>
#include "ob_api.h"
#include "ob_auth.h"
#include "ob_remote.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime/cgo"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// Error preserves the native stage/result and HTTP status without credentials.
type Error struct {
	Code          int
	HTTPStatus    int
	TransportCode int
	Message       string
}

func (e *Error) Error() string {
	return fmt.Sprintf("remote: %s (code=%d, HTTP=%d)", e.Message, e.Code, e.HTTPStatus)
}
func apiError(e *C.ob_api_error) error {
	return &Error{Code: int(e.code), HTTPStatus: int(e.http_status), TransportCode: int(e.transport_code), Message: C.GoString(&e.message[0])}
}
func peerError(e *C.ob_remote_error) error {
	return &Error{Code: int(e.code), HTTPStatus: int(e.http_status), Message: C.GoString(&e.message[0])}
}

// Options configures the native HTTP client. HTTP is accepted only on loopback;
// HTTPS verifies certificates and hostnames. Timeout applies per HTTP request.
type Options struct {
	URL, Token, CAFile string
	Timeout            time.Duration
}
type Client struct {
	mu         sync.RWMutex
	ptr        *C.ob_api_client
	refs       atomic.Int64
	cond       *sync.Cond
	requests   int
	closing    bool
	authHandle cgo.Handle
}

func New(options Options) (*Client, error) {
	for label, value := range map[string]string{"URL": options.URL, "token": options.Token, "CA file": options.CAFile} {
		if err := text(label, value); err != nil {
			return nil, err
		}
	}
	if err := duration("HTTP timeout", options.Timeout); err != nil {
		return nil, err
	}
	url, token := C.CString(options.URL), C.CString(options.Token)
	var ca *C.char
	if options.CAFile != "" {
		ca = C.CString(options.CAFile)
	}
	defer C.free(unsafe.Pointer(url))
	defer C.free(unsafe.Pointer(token))
	defer C.free(unsafe.Pointer(ca))
	cfg := C.ob_api_options{base_url: url, tenant_token: token, ca_file: ca, timeout_ms: C.long(options.Timeout.Milliseconds())}
	var diag C.ob_api_error
	ptr := C.ob_api_client_create(&cfg, &diag)
	if ptr == nil {
		return nil, apiError(&diag)
	}
	client := &Client{ptr: ptr}
	client.cond = sync.NewCond(&client.mu)
	return client, nil
}

// Close rejects destruction while a server or peer is alive. Active requests
// finish before destruction. Callers close mappings, peers/servers, then client.
func (c *Client) Close() error {
	c.mu.Lock()
	for c.closing {
		c.cond.Wait()
	}
	if c.ptr == nil {
		c.mu.Unlock()
		return nil
	}
	if c.refs.Load() != 0 {
		c.mu.Unlock()
		return errors.New("remote: close peers and servers before closing client")
	}
	c.closing = true
	ptr := c.ptr
	c.mu.Unlock()
	C.ob_auth_manager_cancel(C.ob_api_client_auth_manager(ptr))
	c.mu.Lock()
	for c.requests != 0 {
		c.cond.Wait()
	}
	c.mu.Unlock()
	// Storage callbacks must finish outside the client lock before their cgo
	// handle is released; the native destructor cancels and joins its worker.
	C.ob_api_client_destroy(ptr)
	c.mu.Lock()
	if c.authHandle != 0 {
		c.authHandle.Delete()
		c.authHandle = 0
	}
	c.ptr = nil
	c.closing = false
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}
func (c *Client) beginRequest() (*C.ob_api_client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ptr == nil || c.closing {
		return nil, errors.New("remote: client closed")
	}
	c.requests++
	return c.ptr, nil
}
func (c *Client) endRequest() {
	c.mu.Lock()
	c.requests--
	c.cond.Broadcast()
	c.mu.Unlock()
}
func (c *Client) retain() (*C.ob_api_client, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || c.closing {
		return nil, errors.New("remote: client closed")
	}
	c.refs.Add(1)
	return c.ptr, nil
}

// Request executes a bounded native HTTP request. bearer nil uses the configured
// account token; a pointer to "" explicitly omits authentication. The response
// may be present on HTTP errors. No Go network callbacks are used by the SDK.
func (c *Client) Request(method, path string, bearer *string, body any) (json.RawMessage, error) {
	if err := text("HTTP method", method); err != nil {
		return nil, err
	}
	if err := text("API path", path); err != nil {
		return nil, err
	}
	if bearer != nil {
		if err := text("bearer", *bearer); err != nil {
			return nil, err
		}
	}
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	cm, cp := C.CString(method), C.CString(path)
	defer C.free(unsafe.Pointer(cm))
	defer C.free(unsafe.Pointer(cp))
	var cb, ct *C.char
	if body != nil {
		cb = C.CString(string(data))
		defer C.free(unsafe.Pointer(cb))
	}
	if bearer != nil {
		ct = C.CString(*bearer)
		defer C.free(unsafe.Pointer(ct))
	}
	ptr, err := c.beginRequest()
	if err != nil {
		return nil, err
	}
	defer c.endRequest()
	var response *C.char
	var diag C.ob_api_error
	rc := C.ob_api_request(ptr, cm, cp, ct, cb, &response, &diag)
	var result json.RawMessage
	if response != nil {
		result = json.RawMessage(C.GoString(response))
		C.ob_api_response_free(response)
	}
	if rc != 0 {
		return result, c.authError(&diag)
	}
	return result, nil
}

type RelayMode int

const (
	RelayAuto RelayMode = iota
	RelayNever
	RelayForce
)

type Protocol int

const (
	TCP Protocol = 1
	UDP Protocol = 2
)

type Rule struct {
	Host     string `json:"host"`
	Port     uint16 `json:"port,omitempty"`
	PortLast uint16 `json:"port_last,omitempty"`
	Protocol string `json:"protocol"`
}
type ServeOptions struct {
	Rules                       []Rule
	STUNHost                    string
	STUNPort                    uint16
	SetupTimeout                time.Duration
	MaxPeers, MaxMaps, MaxFlows uint32
	UDPIdleTimeout              time.Duration
}
type ConnectOptions struct {
	Relay             RelayMode
	STUNHost          string
	STUNPort          uint16
	Timeout           time.Duration
	MaxMaps, MaxFlows uint32
	UDPIdleTimeout    time.Duration
}

// ReconnectPolicy configures the native recovery manager. Zero fields select
// its defaults; Disabled stops automatic retries without disabling Reconnect.
type ReconnectPolicy struct {
	Disabled                                 bool
	MaxAttempts                              uint32
	InitialDelay, MaxDelay, TransportTimeout time.Duration
	RetryBudget, FlowGrace, StableReset      time.Duration
}

type ConnectionState int

const (
	StateConnecting   ConnectionState = C.OB_REMOTE_STATE_CONNECTING
	StateConnected    ConnectionState = C.OB_REMOTE_STATE_CONNECTED
	StateReconnecting ConnectionState = C.OB_REMOTE_STATE_RECONNECTING
	StateRetryWait    ConnectionState = C.OB_REMOTE_STATE_RETRY_WAIT
	StatePaused       ConnectionState = C.OB_REMOTE_STATE_PAUSED
	StateFailed       ConnectionState = C.OB_REMOTE_STATE_FAILED
	StateClosed       ConnectionState = C.OB_REMOTE_STATE_CLOSED
)

func (s ConnectionState) String() string {
	switch s {
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	case StateRetryWait:
		return "retry_wait"
	case StatePaused:
		return "paused"
	case StateFailed:
		return "failed"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// ConnectionInfo is a copied snapshot. NextRetry is relative to the snapshot;
// LastError is a redacted native diagnostic and is nil when no error occurred.
type ConnectionInfo struct {
	State      ConnectionState
	Attempts   uint32
	Generation uint64
	NextRetry  time.Duration
	LastError  *Error
}

func nativeReconnectPolicy(policy ReconnectPolicy) (C.ob_remote_reconnect_policy, error) {
	if err := validateReconnectPolicy(policy); err != nil {
		return C.ob_remote_reconnect_policy{}, err
	}
	var disabled C.uint32_t
	if policy.Disabled {
		disabled = 1
	}
	return C.ob_remote_reconnect_policy{
		struct_size: C.uint32_t(C.sizeof_ob_remote_reconnect_policy), disabled: disabled,
		max_attempts:         C.uint32_t(policy.MaxAttempts),
		initial_delay_ms:     C.uint32_t(policy.InitialDelay.Milliseconds()),
		max_delay_ms:         C.uint32_t(policy.MaxDelay.Milliseconds()),
		retry_budget_ms:      C.uint32_t(policy.RetryBudget.Milliseconds()),
		flow_grace_ms:        C.uint32_t(policy.FlowGrace.Milliseconds()),
		stable_reset_ms:      C.uint32_t(policy.StableReset.Milliseconds()),
		transport_timeout_ms: C.uint32_t(policy.TransportTimeout.Milliseconds()),
	}, nil
}

func connectionInfo(info C.ob_remote_connection_info) ConnectionInfo {
	result := ConnectionInfo{State: ConnectionState(info.state), Attempts: uint32(info.attempts),
		Generation: uint64(info.generation), NextRetry: time.Duration(info.next_retry_ms) * time.Millisecond}
	if info.last_error.code != 0 {
		result.LastError = &Error{Code: int(info.last_error.code), HTTPStatus: int(info.last_error.http_status),
			Message: C.GoString(&info.last_error.message[0])}
	}
	return result
}

type Server struct {
	mu        sync.Mutex
	ptr       *C.ob_remote_server
	client    *Client
	closeDone chan struct{}
}
type Peer struct {
	mu        sync.Mutex
	ptr       *C.ob_remote_peer
	client    *Client
	maps      map[*Mapping]struct{}
	closeDone chan struct{}
}
type Mapping struct {
	ptr  *C.ob_remote_map
	peer *Peer
	port uint16
}

func (c *Client) Serve(name, password string, options ServeOptions) (*Server, error) {
	for label, value := range map[string]string{"name": name, "peer password": password, "STUN host": options.STUNHost} {
		if err := text(label, value); err != nil {
			return nil, err
		}
	}
	if err := duration("setup timeout", options.SetupTimeout); err != nil {
		return nil, err
	}
	if err := duration("UDP idle timeout", options.UDPIdleTimeout); err != nil {
		return nil, err
	}
	for _, rule := range options.Rules {
		if err := text("rule host", rule.Host); err != nil {
			return nil, err
		}
	}
	api, err := c.retain()
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			c.refs.Add(-1)
		}
	}()
	nameC, pw := C.CString(name), C.CString(password)
	var stun *C.char
	if options.STUNHost != "" {
		stun = C.CString(options.STUNHost)
	}
	defer C.free(unsafe.Pointer(nameC))
	defer C.free(unsafe.Pointer(pw))
	defer C.free(unsafe.Pointer(stun))
	var rules *C.ob_remote_allow_rule
	if len(options.Rules) > 0 {
		p := C.calloc(C.size_t(len(options.Rules)), C.size_t(C.sizeof_ob_remote_allow_rule))
		if p == nil {
			return nil, errors.New("remote: allocation failed")
		}
		defer C.free(p)
		rules = (*C.ob_remote_allow_rule)(p)
		array := unsafe.Slice(rules, len(options.Rules))
		for i, rule := range options.Rules {
			proto := C.OB_REMOTE_TCP
			if rule.Protocol == "udp" {
				proto = C.OB_REMOTE_UDP
			} else if rule.Protocol != "tcp" {
				return nil, fmt.Errorf("invalid rule protocol %q", rule.Protocol)
			}
			host := C.CString(rule.Host)
			defer C.free(unsafe.Pointer(host))
			last := rule.PortLast
			if last == 0 {
				last = rule.Port
			}
			array[i] = C.ob_remote_allow_rule{host: host, port_first: C.uint16_t(rule.Port), port_last: C.uint16_t(last), protocol: C.ob_remote_protocol(proto)}
		}
	}
	cfg := C.ob_remote_serve_options{allow_rules: rules, allow_rule_count: C.size_t(len(options.Rules)), stun_server: stun, stun_port: C.uint16_t(options.STUNPort), setup_timeout_ms: C.uint32_t(options.SetupTimeout.Milliseconds()), max_peers: C.uint32_t(options.MaxPeers), max_maps_per_peer: C.uint32_t(options.MaxMaps), max_flows_per_peer: C.uint32_t(options.MaxFlows), udp_idle_timeout_ms: C.uint32_t(options.UDPIdleTimeout.Milliseconds())}
	var ptr *C.ob_remote_server
	var diag C.ob_remote_error
	if C.ob_remote_serve(api, nameC, pw, &cfg, &ptr, &diag) != 0 {
		return nil, peerError(&diag)
	}
	ok = true
	return &Server{ptr: ptr, client: c}, nil
}
func (s *Server) ID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ptr == nil {
		return ""
	}
	return C.GoString(C.ob_remote_server_id(s.ptr))
}
func (s *Server) Status() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ptr == nil {
		return errors.New("remote: server closed")
	}
	var e C.ob_remote_error
	if C.ob_remote_server_status(s.ptr, &e) != 0 {
		return peerError(&e)
	}
	return nil
}

// SetReconnectPolicy replaces the native policy. A zero policy restores defaults.
func (s *Server) SetReconnectPolicy(policy ReconnectPolicy) error {
	cfg, err := nativeReconnectPolicy(policy)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ptr == nil {
		return errors.New("remote: server closed")
	}
	var diagnostic C.ob_remote_error
	if C.ob_remote_server_set_reconnect_policy(s.ptr, &cfg, &diagnostic) != 0 {
		return peerError(&diagnostic)
	}
	return nil
}

func (s *Server) GetConnectionInfo() (ConnectionInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ptr == nil {
		return ConnectionInfo{State: StateClosed}, errors.New("remote: server closed")
	}
	var info C.ob_remote_connection_info
	if result := C.ob_remote_server_get_state(s.ptr, &info); result != 0 {
		return ConnectionInfo{}, &Error{Code: int(result), Message: C.GoString(C.ob_remote_strerror(result))}
	}
	return connectionInfo(info), nil
}

// Reconnect is nonblocking: nil means accepted. A healthy server is unchanged;
// recovery still requires valid credentials and cannot override revocation.
func (s *Server) Reconnect() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ptr == nil {
		return errors.New("remote: server closed")
	}
	var diagnostic C.ob_remote_error
	if C.ob_remote_server_reconnect(s.ptr, &diagnostic) != 0 {
		return peerError(&diagnostic)
	}
	return nil
}

func (s *Server) Close() {
	s.mu.Lock()
	if s.ptr == nil {
		done := s.closeDone
		s.mu.Unlock()
		if done != nil {
			<-done
		}
		return
	}
	ptr := s.ptr
	s.ptr = nil
	s.closeDone = make(chan struct{})
	done := s.closeDone
	s.mu.Unlock()
	// Native close may perform account RPCs/storage callbacks; no Go handle
	// lock remains held while its worker and borrowed API use are joined.
	C.ob_remote_server_close(ptr)
	s.client.refs.Add(-1)
	close(done)
}
func (c *Client) Connect(brokerID, password string, options ConnectOptions) (*Peer, error) {
	return c.connect(brokerID, password, options, false)
}

// ConnectAsync returns a persistent peer before network setup completes. A
// failed initial attempt can be retried on that same handle with Reconnect.
func (c *Client) ConnectAsync(brokerID, password string, options ConnectOptions) (*Peer, error) {
	return c.connect(brokerID, password, options, true)
}

func (c *Client) connect(brokerID, password string, options ConnectOptions, asynchronous bool) (*Peer, error) {
	for label, value := range map[string]string{"broker ID": brokerID, "peer password": password, "STUN host": options.STUNHost} {
		if err := text(label, value); err != nil {
			return nil, err
		}
	}
	if err := duration("setup timeout", options.Timeout); err != nil {
		return nil, err
	}
	if err := duration("UDP idle timeout", options.UDPIdleTimeout); err != nil {
		return nil, err
	}
	api, err := c.retain()
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			c.refs.Add(-1)
		}
	}()
	broker, pw := C.CString(brokerID), C.CString(password)
	var stun *C.char
	if options.STUNHost != "" {
		stun = C.CString(options.STUNHost)
	}
	defer C.free(unsafe.Pointer(broker))
	defer C.free(unsafe.Pointer(pw))
	defer C.free(unsafe.Pointer(stun))
	cfg := C.ob_remote_connect_options{relay_mode: C.ob_remote_relay_mode(options.Relay), timeout_ms: C.uint32_t(options.Timeout.Milliseconds()), stun_server: stun, stun_port: C.uint16_t(options.STUNPort), max_maps: C.uint32_t(options.MaxMaps), max_flows: C.uint32_t(options.MaxFlows), udp_idle_timeout_ms: C.uint32_t(options.UDPIdleTimeout.Milliseconds())}
	var ptr *C.ob_remote_peer
	var diag C.ob_remote_error
	var result C.int
	if asynchronous {
		result = C.ob_remote_connect_async(api, broker, pw, &cfg, &ptr, &diag)
	} else {
		result = C.ob_remote_connect(api, broker, pw, &cfg, &ptr, &diag)
	}
	if result != 0 {
		return nil, peerError(&diag)
	}
	ok = true
	return &Peer{ptr: ptr, client: c, maps: make(map[*Mapping]struct{})}, nil
}
func (p *Peer) Status() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ptr == nil {
		return errors.New("remote: peer closed")
	}
	var e C.ob_remote_error
	if C.ob_remote_peer_status(p.ptr, &e) != 0 {
		return peerError(&e)
	}
	return nil
}

// SetReconnectPolicy replaces the native policy. A zero policy restores defaults.
func (p *Peer) SetReconnectPolicy(policy ReconnectPolicy) error {
	cfg, err := nativeReconnectPolicy(policy)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ptr == nil {
		return errors.New("remote: peer closed")
	}
	var diagnostic C.ob_remote_error
	if C.ob_remote_peer_set_reconnect_policy(p.ptr, &cfg, &diagnostic) != 0 {
		return peerError(&diagnostic)
	}
	return nil
}

func (p *Peer) GetConnectionInfo() (ConnectionInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ptr == nil {
		return ConnectionInfo{State: StateClosed}, errors.New("remote: peer closed")
	}
	var info C.ob_remote_connection_info
	if result := C.ob_remote_peer_get_state(p.ptr, &info); result != 0 {
		return ConnectionInfo{}, &Error{Code: int(result), Message: C.GoString(C.ob_remote_strerror(result))}
	}
	return connectionInfo(info), nil
}

// Reconnect is nonblocking: nil means accepted, not connected. Repeated calls
// coalesce and preserve this peer, its mapping handles and local listening ports.
func (p *Peer) Reconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ptr == nil {
		return errors.New("remote: peer closed")
	}
	var diagnostic C.ob_remote_error
	if C.ob_remote_peer_reconnect(p.ptr, &diagnostic) != 0 {
		return peerError(&diagnostic)
	}
	return nil
}

func (p *Peer) Map(protocol Protocol, localHost string, localPort uint16, targetHost string, targetPort uint16) (*Mapping, error) {
	if err := text("local host", localHost); err != nil {
		return nil, err
	}
	if err := text("target host", targetHost); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ptr == nil {
		return nil, errors.New("remote: peer closed")
	}
	local, target := C.CString(localHost), C.CString(targetHost)
	defer C.free(unsafe.Pointer(local))
	defer C.free(unsafe.Pointer(target))
	var ptr *C.ob_remote_map
	var e C.ob_remote_error
	var rc C.int
	switch protocol {
	case TCP:
		rc = C.ob_remote_portmap_tcp(p.ptr, local, C.uint16_t(localPort), target, C.uint16_t(targetPort), &ptr, &e)
	case UDP:
		rc = C.ob_remote_portmap_udp(p.ptr, local, C.uint16_t(localPort), target, C.uint16_t(targetPort), &ptr, &e)
	default:
		return nil, errors.New("remote: invalid protocol")
	}
	if rc != 0 {
		return nil, peerError(&e)
	}
	m := &Mapping{ptr: ptr, peer: p, port: uint16(C.ob_remote_map_local_port(ptr))}
	p.maps[m] = struct{}{}
	return m, nil
}
func (m *Mapping) Port() uint16 { return m.port }
func (m *Mapping) Close() {
	p := m.peer
	p.mu.Lock()
	defer p.mu.Unlock()
	if m.ptr != nil {
		C.ob_remote_map_close(m.ptr)
		m.ptr = nil
		delete(p.maps, m)
	}
}
func (p *Peer) Close() {
	p.mu.Lock()
	if p.ptr == nil {
		done := p.closeDone
		p.mu.Unlock()
		if done != nil {
			<-done
		}
		return
	}
	ptr := p.ptr
	p.ptr = nil
	p.closeDone = make(chan struct{})
	done := p.closeDone
	maps := make([]*C.ob_remote_map, 0, len(p.maps))
	for m := range p.maps {
		maps = append(maps, m.ptr)
		m.ptr = nil
		delete(p.maps, m)
	}
	p.mu.Unlock()
	for _, mapping := range maps {
		C.ob_remote_map_close(mapping)
	}
	C.ob_remote_peer_close(ptr)
	p.client.refs.Add(-1)
	close(done)
}
