package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
)

// Deliberately test-only fault injection; never mounted by the production CLI.
type testGate struct {
	next                                             http.Handler
	admin                                            string
	mu                                               sync.Mutex
	session, broker                                  chan struct{}
	sessionWaiting, brokerWaiting                    atomic.Int32
	httpSignalPolls, httpBrokerPolls, httpHeartbeats atomic.Int64
	wsRequests, wsBrokerUpgrades, wsSessionUpgrades  atomic.Int64
	wsDisconnects                                    atomic.Int64
	connections                                      map[*gateConnection]struct{}
	refresh                                          chan struct{}
	refreshWaiting                                   atomic.Int32
	refreshRequests, refreshRepliesDropped           atomic.Int64
	authRegisterCalls, authLoginCalls                atomic.Int64
	httpAccountRequests                              atomic.Int64
	dropRefreshReplies                               atomic.Int64
}

func newGate(next http.Handler, admin string) *testGate {
	return &testGate{next: next, admin: admin, connections: make(map[*gateConnection]struct{})}
}

type gateConnection struct {
	net.Conn
	gate *testGate
	once sync.Once
}

func (c *gateConnection) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.gate.mu.Lock()
		delete(c.gate.connections, c)
		c.gate.mu.Unlock()
	})
	return err
}

type gateWriter struct {
	http.ResponseWriter
	gate *testGate
}

func (w gateWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	connection, buffer, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	wrapped := &gateConnection{Conn: connection, gate: w.gate}
	w.gate.mu.Lock()
	w.gate.connections[wrapped] = struct{}{}
	w.gate.mu.Unlock()
	return wrapped, buffer, nil
}
func (g *testGate) dropWS() {
	g.mu.Lock()
	connections := make([]*gateConnection, 0, len(g.connections))
	for connection := range g.connections {
		connections = append(connections, connection)
	}
	g.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	g.wsDisconnects.Add(int64(len(connections)))
}

// Installed only by this disposable fixture. Stalling the authenticated WS
// heartbeat must not grant a lease merely because network ping/pong continues.
func (g *testGate) beforeWS(ctx context.Context, role, op string) error {
	g.wsRequests.Add(1)
	var channel chan struct{}
	var count *atomic.Int32
	g.mu.Lock()
	if role == "session" && op == "heartbeat" {
		channel, count = g.session, &g.sessionWaiting
	}
	if role == "broker" && op == "heartbeat" {
		channel, count = g.broker, &g.brokerWaiting
	}
	g.mu.Unlock()
	if channel == nil {
		return nil
	}
	count.Add(1)
	defer count.Add(-1)
	select {
	case <-channel:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (g *testGate) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.session != nil {
		close(g.session)
		g.session = nil
	}
	if g.broker != nil {
		close(g.broker)
		g.broker = nil
	}
	if g.refresh != nil {
		close(g.refresh)
		g.refresh = nil
	}
}
func toggle(channel *chan struct{}, pause bool) {
	if pause {
		if *channel == nil {
			*channel = make(chan struct{})
		}
	} else if *channel != nil {
		close(*channel)
		*channel = nil
	}
}
func (g *testGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/__test/gates" {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(g.admin)) != 1 {
			w.WriteHeader(403)
			return
		}
		if r.Method == "POST" {
			var body struct {
				Sessions           *bool `json:"sessions"`
				Broker             *bool `json:"broker"`
				DropWS             *bool `json:"drop_ws"`
				DropRefreshReplies *int  `json:"drop_refresh_replies"`
				HoldRefreshReplies *bool `json:"hold_refresh_replies"`
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			if body.DropRefreshReplies != nil && (*body.DropRefreshReplies < 0 || *body.DropRefreshReplies > 100) {
				w.WriteHeader(400)
				return
			}
			if body.DropRefreshReplies != nil {
				g.dropRefreshReplies.Store(int64(*body.DropRefreshReplies))
			}
			g.mu.Lock()
			if body.HoldRefreshReplies != nil {
				toggle(&g.refresh, *body.HoldRefreshReplies)
			}
			if body.Sessions != nil {
				toggle(&g.session, *body.Sessions)
			}
			if body.Broker != nil {
				toggle(&g.broker, *body.Broker)
			}
			g.mu.Unlock()
			if body.DropWS != nil && *body.DropWS {
				g.dropWS()
			}
		} else if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int64{
			"sessions_waiting": int64(g.sessionWaiting.Load()), "broker_waiting": int64(g.brokerWaiting.Load()),
			"http_signal_polls": g.httpSignalPolls.Load(), "http_broker_polls": g.httpBrokerPolls.Load(),
			"http_heartbeats": g.httpHeartbeats.Load(), "ws_requests": g.wsRequests.Load(),
			"ws_broker_upgrades": g.wsBrokerUpgrades.Load(), "ws_session_upgrades": g.wsSessionUpgrades.Load(),
			"ws_disconnects":  g.wsDisconnects.Load(),
			"refresh_waiting": int64(g.refreshWaiting.Load()), "refresh_requests": g.refreshRequests.Load(),
			"refresh_dropped":     g.refreshRepliesDropped.Load(),
			"auth_register_calls": g.authRegisterCalls.Load(), "auth_login_calls": g.authLoginCalls.Load(),
			"http_account_requests": g.httpAccountRequests.Load(),
		})
		return
	}
	if r.Method == "GET" && (r.URL.Path == "/v1/me" || r.URL.Path == "/v1/capabilities" || r.URL.Path == "/v1/brokers" || r.URL.Path == "/v1/usage") {
		g.httpAccountRequests.Add(1)
	}
	if r.Method == "POST" && r.URL.Path == "/v1/auth/register" {
		g.authRegisterCalls.Add(1)
	}
	if r.Method == "POST" && r.URL.Path == "/v1/auth/login" {
		g.authLoginCalls.Add(1)
	}
	if r.Method == "POST" && r.URL.Path == "/v1/auth/refresh" {
		g.refreshRequests.Add(1)
		reply := httptest.NewRecorder()
		// The real service commits before the test-only reply fault is applied.
		g.next.ServeHTTP(reply, r)
		g.mu.Lock()
		hold := g.refresh
		g.mu.Unlock()
		if hold != nil {
			g.refreshWaiting.Add(1)
			defer g.refreshWaiting.Add(-1)
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		if reply.Code == http.StatusOK {
			for left := g.dropRefreshReplies.Load(); left > 0; left = g.dropRefreshReplies.Load() {
				if g.dropRefreshReplies.CompareAndSwap(left, left-1) {
					g.refreshRepliesDropped.Add(1)
					if hijacker, ok := w.(http.Hijacker); ok {
						if connection, _, err := hijacker.Hijack(); err == nil {
							_ = connection.Close()
						}
					}
					return
				}
			}
		}
		for key, values := range reply.Header() {
			w.Header()[key] = append([]string(nil), values...)
		}
		w.WriteHeader(reply.Code)
		_, _ = w.Write(reply.Body.Bytes())
		return
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/ws/brokers/") {
		g.wsBrokerUpgrades.Add(1)
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/ws/sessions/") {
		g.wsSessionUpgrades.Add(1)
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/sessions/") && strings.HasSuffix(r.URL.Path, "/messages") {
		g.httpSignalPolls.Add(1)
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/brokers/") && strings.HasSuffix(r.URL.Path, "/sessions") {
		g.httpBrokerPolls.Add(1)
	}
	if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/heartbeat") {
		g.httpHeartbeats.Add(1)
	}
	var channel chan struct{}
	var count *atomic.Int32
	g.mu.Lock()
	if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/sessions/") && strings.HasSuffix(r.URL.Path, "/heartbeat") {
		channel = g.session
		count = &g.sessionWaiting
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/brokers/") && strings.HasSuffix(r.URL.Path, "/sessions") {
		channel = g.broker
		count = &g.brokerWaiting
	}
	g.mu.Unlock()
	if channel != nil {
		count.Add(1)
		defer count.Add(-1)
		select {
		case <-channel:
		case <-r.Context().Done():
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, "/v1/ws/") {
		g.next.ServeHTTP(gateWriter{ResponseWriter: w, gate: g}, r)
	} else {
		g.next.ServeHTTP(w, r)
	}
}
