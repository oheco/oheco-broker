// Package remote wraps the native C management and authenticated peer SDK.
// It does not implement a second ICE, TURN, QUIC or cryptographic stack.
package remote

/*
#cgo CFLAGS: -I${SRCDIR}/../../c/remote
#cgo LDFLAGS: -lob_remote
#include <stdlib.h>
#include "ob_api.h"
#include "ob_remote.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
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
	mu   sync.RWMutex
	ptr  *C.ob_api_client
	refs atomic.Int64
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
	return &Client{ptr: ptr}, nil
}

// Close rejects destruction while a server or peer is alive. Active requests
// finish before destruction. Callers close mappings, peers/servers, then client.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ptr == nil {
		return nil
	}
	if c.refs.Load() != 0 {
		return errors.New("remote: close peers and servers before closing client")
	}
	C.ob_api_client_destroy(c.ptr)
	c.ptr = nil
	return nil
}
func (c *Client) retain() (*C.ob_api_client, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil {
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
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil {
		return nil, errors.New("remote: client closed")
	}
	var response *C.char
	var diag C.ob_api_error
	rc := C.ob_api_request(c.ptr, cm, cp, ct, cb, &response, &diag)
	var result json.RawMessage
	if response != nil {
		result = json.RawMessage(C.GoString(response))
		C.ob_api_response_free(response)
	}
	if rc != 0 {
		return result, apiError(&diag)
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
type Server struct {
	mu     sync.Mutex
	ptr    *C.ob_remote_server
	client *Client
}
type Peer struct {
	mu     sync.Mutex
	ptr    *C.ob_remote_peer
	client *Client
	maps   map[*Mapping]struct{}
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
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ptr != nil {
		C.ob_remote_server_close(s.ptr)
		s.ptr = nil
		s.client.refs.Add(-1)
	}
}
func (c *Client) Connect(brokerID, password string, options ConnectOptions) (*Peer, error) {
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
	if C.ob_remote_connect(api, broker, pw, &cfg, &ptr, &diag) != 0 {
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
	defer p.mu.Unlock()
	if p.ptr == nil {
		return
	}
	for m := range p.maps {
		C.ob_remote_map_close(m.ptr)
		m.ptr = nil
		delete(p.maps, m)
	}
	C.ob_remote_peer_close(p.ptr)
	p.ptr = nil
	p.client.refs.Add(-1)
}
