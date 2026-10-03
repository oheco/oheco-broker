package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocket fixtures avoid unrelated expensive password hashing. Identity/login
// behavior remains covered by the existing real cost-12 REST tests.
func wsFixture(t *testing.T, cfg Config, secure bool) (*Server, *httptest.Server, string, string, string, string, string, string) {
	t.Helper()
	s := apiFixture(t, cfg)
	tenant := uuid()
	if _, err := s.db.Exec("INSERT INTO tenants(id,name,email,password_hash,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", tenant, "ws-fixture", "ws@example.invalid", "not-used-for-login", "active", now(), now()); err != nil {
		t.Fatal(err)
	}
	account, err := s.accountToken(tenant, 1)
	if err != nil {
		t.Fatal(err)
	}
	broker, device := fixtureBroker(t, s, account, "host")
	session, caller := fixtureSession(t, s, account, broker)
	var h *httptest.Server
	if secure {
		h = httptest.NewTLSServer(s.Handler())
	} else {
		h = httptest.NewServer(s.Handler())
	}
	t.Cleanup(h.Close)
	return s, h, tenant, account, broker, device, session, caller
}
func wsDialer(h *httptest.Server) *websocket.Dialer {
	d := &websocket.Dialer{Subprotocols: []string{wsProtocol}, HandshakeTimeout: 3 * time.Second, EnableCompression: false}
	if h.TLS != nil {
		roots := x509.NewCertPool()
		roots.AddCert(h.Certificate())
		d.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return d
}
func wsURL(h *httptest.Server, path string) string {
	return strings.Replace(h.URL, "http", "ws", 1) + path
}
func wsConnect(t *testing.T, h *httptest.Server, path, token string) *websocket.Conn {
	t.Helper()
	head := http.Header{"Authorization": []string{"Bearer " + token}}
	c, res, err := wsDialer(h).Dial(wsURL(h, path), head)
	if err != nil {
		if res != nil {
			t.Fatalf("WS handshake status=%d: %v", res.StatusCode, err)
		}
		t.Fatal(err)
	}
	if c.Subprotocol() != wsProtocol {
		t.Fatal("wrong negotiated protocol")
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func wsRead(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	kind, data, err := c.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if kind != websocket.TextMessage {
		t.Fatal("non-text application result")
	}
	var out map[string]any
	if err = json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out["v"] != float64(1) {
		t.Fatal("missing v1", out)
	}
	return out
}
func wsUntil(t *testing.T, c *websocket.Conn, kind string) map[string]any {
	t.Helper()
	for i := 0; i < 32; i++ {
		out := wsRead(t, c)
		if out["type"] == kind {
			return out
		}
	}
	t.Fatalf("no %s frame", kind)
	return nil
}
func wsRequest(t *testing.T, c *websocket.Conn, id int64, op string, body any, status int) map[string]any {
	t.Helper()
	if err := c.WriteJSON(map[string]any{"v": 1, "type": "request", "id": id, "op": op, "body": body}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		out := wsRead(t, c)
		if out["type"] == "result" && out["id"] == float64(id) {
			if out["status"] != float64(status) {
				t.Fatalf("%s result=%v want=%d", op, out, status)
			}
			return out["body"].(map[string]any)
		}
	}
	t.Fatal("missing RPC result")
	return nil
}
func wsACK(t *testing.T, c *websocket.Conn, n int64) {
	t.Helper()
	if err := c.WriteJSON(map[string]any{"v": 1, "type": "ack", "sequence": n}); err != nil {
		t.Fatal(err)
	}
}
func wsClosed(t *testing.T, c *websocket.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	for i := 0; i < 32; i++ {
		if _, _, err := c.ReadMessage(); err != nil {
			if _, ok := err.(*websocket.CloseError); ok {
				return
			}
			t.Fatal("expected bounded close, not timeout", err)
		}
	}
	t.Fatal("socket never closed")
}

func TestWSHandshakeRolesScopesOriginProtocolAndWSS(t *testing.T) {
	s, h, _, account, broker, device, sid, caller := wsFixture(t, Config{}, true)
	otherBroker, otherDevice := fixtureBroker(t, s, account, "other")
	otherSession, otherCaller := fixtureSession(t, s, account, otherBroker)
	_ = otherSession
	_, siblingCaller := fixtureSession(t, s, account, broker)
	foreignTenant := uuid()
	if _, err := s.db.Exec("INSERT INTO tenants(id,name,email,password_hash,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", foreignTenant, "foreign-tenant", "foreign@example.invalid", "unused", "active", now(), now()); err != nil {
		t.Fatal(err)
	}
	foreignAccount, err := s.accountToken(foreignTenant, 1)
	if err != nil {
		t.Fatal(err)
	}
	foreignBroker, foreignDevice := fixtureBroker(t, s, foreignAccount, "foreign-host")
	_, foreignCaller := fixtureSession(t, s, foreignAccount, foreignBroker)
	cases := []struct {
		name, path, token, origin, protocol string
		status                              int
	}{
		{"missing bearer", "/v1/ws/brokers/" + broker, "", "", wsProtocol, 401},
		{"account watcher", "/v1/ws/brokers/" + broker, account, "", wsProtocol, 403},
		{"session watcher", "/v1/ws/brokers/" + broker, caller, "", wsProtocol, 403},
		{"admin watcher", "/v1/ws/brokers/" + broker, fixtureAdmin, "", wsProtocol, 401},
		{"wrong broker", "/v1/ws/brokers/" + broker, otherDevice, "", wsProtocol, 403},
		{"wrong caller", "/v1/ws/sessions/" + sid, otherCaller, "", wsProtocol, 403},
		{"same broker wrong session", "/v1/ws/sessions/" + sid, siblingCaller, "", wsProtocol, 403},
		{"foreign tenant watcher", "/v1/ws/brokers/" + broker, foreignDevice, "", wsProtocol, 403},
		{"foreign tenant session", "/v1/ws/sessions/" + sid, foreignCaller, "", wsProtocol, 403},
		{"foreign tenant cursor", "/v1/ws/sessions/" + sid + "?after=3", foreignDevice, "", wsProtocol, 403},
		{"account session", "/v1/ws/sessions/" + sid, account, "", wsProtocol, 403},
		{"missing protocol", "/v1/ws/brokers/" + broker, device, "", "", 400},
		{"wrong protocol", "/v1/ws/brokers/" + broker, device, "", "other-v1", 400},
		{"foreign origin", "/v1/ws/brokers/" + broker, device, "https://foreign.invalid", wsProtocol, 403},
		{"wrong origin scheme", "/v1/ws/brokers/" + broker, device, strings.Replace(h.URL, "https:", "http:", 1), wsProtocol, 403},
		{"origin path", "/v1/ws/brokers/" + broker, device, h.URL + "/path", wsProtocol, 403},
		{"origin credentials", "/v1/ws/brokers/" + broker, device, strings.Replace(h.URL, "https://", "https://user@", 1), wsProtocol, 403},
		{"query secret", "/v1/ws/brokers/" + broker + "?token=secret", device, "", wsProtocol, 400},
		{"query cursor on watcher", "/v1/ws/brokers/" + broker + "?after=0", device, "", wsProtocol, 400},
		{"unknown query", "/v1/ws/sessions/" + sid + "?side=broker", caller, "", wsProtocol, 400},
		{"repeated cursor", "/v1/ws/sessions/" + sid + "?after=0&after=0", caller, "", wsProtocol, 400},
		{"cursor past history", "/v1/ws/sessions/" + sid + "?after=1", caller, "", wsProtocol, 400},
		{"negative cursor", "/v1/ws/sessions/" + sid + "?after=-1", caller, "", wsProtocol, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := wsDialer(h)
			d.Subprotocols = nil
			if tc.protocol != "" {
				d.Subprotocols = []string{tc.protocol}
			}
			head := http.Header{}
			if tc.token != "" {
				head.Set("Authorization", "Bearer "+tc.token)
			}
			if tc.origin != "" {
				head.Set("Origin", tc.origin)
			}
			c, res, err := d.Dial(wsURL(h, tc.path), head)
			if c != nil {
				_ = c.Close()
				t.Fatal("forbidden upgrade succeeded")
			}
			if err == nil || res == nil || res.StatusCode != tc.status {
				t.Fatalf("status=%v err=%v want=%d", res, err, tc.status)
			}
			_ = res.Body.Close()
		})
	}
	d := wsDialer(h)
	c, res, err := d.Dial(wsURL(h, "/v1/ws/brokers/"+broker), http.Header{"Authorization": []string{"Bearer " + device}, "Origin": []string{h.URL}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if res.Header.Get("Sec-WebSocket-Extensions") != "" {
		t.Fatal("compression negotiated")
	}
	if wsRead(t, c)["type"] != "sessions" {
		t.Fatal("no initial snapshot")
	}
	wsRequest(t, c, 9007199254740991, "heartbeat", nil, 200)
}

func TestWSPushDirectionDurableReplayIdempotencyAndACK(t *testing.T) {
	s, h, _, account, broker, device, sid, caller := wsFixture(t, Config{MaxMessagesPerDirection: 8}, false)
	watch := wsConnect(t, h, "/v1/ws/brokers/"+broker, device)
	initial := wsRead(t, watch)
	if initial["type"] != "sessions" || len(initial["body"].(map[string]any)["sessions"].([]any)) != 1 {
		t.Fatal("wrong initial broker snapshot", initial)
	}
	newID, _ := fixtureSession(t, s, account, broker)
	push := wsUntil(t, watch, "sessions")
	sessions := push["body"].(map[string]any)["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatal("creation did not push snapshot", newID, push)
	}
	client := wsConnect(t, h, "/v1/ws/sessions/"+sid+"?after=0", caller)
	host := wsConnect(t, h, "/v1/ws/sessions/"+sid, device)
	if wsRead(t, client)["type"] != "capabilities" || wsRead(t, host)["type"] != "capabilities" {
		t.Fatal("missing initial capabilities")
	}
	wsRequest(t, client, 1, "send", Message{1, "opaque-client"}, 201)
	m := wsUntil(t, host, "message")
	if m["sequence"] != float64(1) || m["data"] != "opaque-client" {
		t.Fatal("wrong recipient direction", m)
	}
	wsACK(t, host, 1)
	wsRequest(t, client, 2, "send", Message{1, "opaque-client"}, 200)
	wsRequest(t, client, 3, "send", Message{1, "changed"}, 409)
	wsRequest(t, client, 4, "send", Message{3, "gap"}, 409)
	wsRequest(t, host, 1, "send", Message{1, "opaque-broker"}, 201)
	m = wsUntil(t, client, "message")
	if m["data"] != "opaque-broker" {
		t.Fatal("wrong caller direction", m)
	}
	wsACK(t, client, 1)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/messages", device, Message{2, "REST and WS share one mailbox"}, 201)
	m = wsUntil(t, client, "message")
	if m["sequence"] != float64(2) {
		t.Fatal("REST commit did not push", m)
	}
	_ = client.Close() // lost ACK, reconnect using LAST consumed sequence, not last bytes
	resumed := wsConnect(t, h, "/v1/ws/sessions/"+sid+"?after=1", caller)
	if wsRead(t, resumed)["type"] != "capabilities" {
		t.Fatal("reconnect missing caps")
	}
	m = wsRead(t, resumed)
	if m["type"] != "message" || m["sequence"] != float64(2) {
		t.Fatal("lost-ACK replay missing", m)
	}
	wsACK(t, resumed, 2)
	wsRequest(t, resumed, 8, "heartbeat", nil, 200)
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM messages WHERE session_id=?", sid).Scan(&count); err != nil || count != 3 {
		t.Fatal("ACK deleted immutable history", count, err)
	}
	// Sender loses its success result while the receiver observes the durable
	// commit. A reconnect retries IDENTICAL sequence/data, not a fresh number.
	if err := host.WriteJSON(map[string]any{"v": 1, "type": "request", "id": 2, "op": "send", "body": Message{3, "lost-send-result"}}); err != nil {
		t.Fatal(err)
	}
	m = wsUntil(t, resumed, "message")
	if m["sequence"] != float64(3) || m["data"] != "lost-send-result" {
		t.Fatal("missing committed send", m)
	}
	wsACK(t, resumed, 3)
	_ = host.Close()
	host = wsConnect(t, h, "/v1/ws/sessions/"+sid+"?after=1", device)
	_ = wsRead(t, host)
	wsRequest(t, host, 3, "send", Message{3, "lost-send-result"}, 200)
	wsRequest(t, host, 4, "approve", map[string]any{"peer_authenticated": true, "relay": false}, 200)
	approved := false
	for n := 0; n < 8; n++ {
		caps := wsUntil(t, resumed, "capabilities")
		if caps["body"].(map[string]any)["peer_authenticated"] == true {
			approved = true
			break
		}
	}
	if !approved {
		t.Fatal("approval did not wake caller")
	}
	wsRequest(t, resumed, 9, "capabilities", nil, 200) // relay-only revoke did not kill direct WS
	wsRequest(t, resumed, 10, "approve", map[string]any{"peer_authenticated": true, "relay": false}, 403)
	wsRequest(t, resumed, 11, "heartbeat", nil, 200) // permission denial is not identity revocation
	wsRequest(t, resumed, 12, "delete", nil, 200)
	wsClosed(t, resumed)
	wsClosed(t, host)
}

func TestWSACKCannotSkipUnsentWindowAndReplayCatchup(t *testing.T) {
	s, h, _, _, _, device, sid, caller := wsFixture(t, Config{MaxMessagesPerDirection: 8}, false)
	for n := int64(1); n <= 6; n++ {
		apiCall(t, s, "POST", "/v1/sessions/"+sid+"/messages", device, Message{n, fmt.Sprintf("message-%d", n)}, 201)
	}
	c := wsConnect(t, h, "/v1/ws/sessions/"+sid, caller)
	_ = wsRead(t, c)
	for n := int64(1); n <= 4; n++ {
		m := wsRead(t, c)
		if m["sequence"] != float64(n) {
			t.Fatal("unordered replay", m)
		}
	}
	wsACK(t, c, 5) // actual history is six, but only four were SENT on this connection
	r := wsUntil(t, c, "revoked")
	if r["status"] != float64(400) {
		t.Fatal("unsent ACK accepted", r)
	}
	wsClosed(t, c)
	resumed := wsConnect(t, h, "/v1/ws/sessions/"+sid+"?after=4", caller)
	_ = wsRead(t, resumed)
	for n := int64(5); n <= 6; n++ {
		m := wsRead(t, resumed)
		if m["sequence"] != float64(n) {
			t.Fatal("cursor catchup", m)
		}
		wsACK(t, resumed, n)
	}
	wsACK(t, resumed, 6)
	wsRequest(t, resumed, 1, "capabilities", nil, 200)
}

func TestWSIdleRevocationTokenExpiryAndOfflineRecovery(t *testing.T) {
	for _, mode := range []string{"tenant disable", "token expiry", "version change", "broker delete", "rotate device", "offline"} {
		t.Run(mode, func(t *testing.T) {
			s, h, tenant, account, broker, device, sid, caller := wsFixture(t, Config{}, false)
			watch := wsConnect(t, h, "/v1/ws/brokers/"+broker, device)
			_ = wsRead(t, watch)
			client := wsConnect(t, h, "/v1/ws/sessions/"+sid, caller)
			_ = wsRead(t, client)
			switch mode {
			case "tenant disable":
				apiCall(t, s, "POST", "/v1/admin/tenants/"+tenant+"/disable", fixtureAdmin, nil, 200)
			case "token expiry":
				if _, err := s.db.Exec("UPDATE tokens SET expires_at=0 WHERE tenant_id=?", tenant); err != nil {
					t.Fatal(err)
				}
			case "version change":
				if _, err := s.db.Exec("UPDATE tenants SET version=version+1 WHERE id=?", tenant); err != nil {
					t.Fatal(err)
				}
			case "broker delete":
				apiCall(t, s, "DELETE", "/v1/brokers/"+broker, account, nil, 200)
			case "rotate device":
				if _, err := s.db.Exec("UPDATE brokers SET lease_expires_at=0 WHERE id=?", broker); err != nil {
					t.Fatal(err)
				}
				apiCall(t, s, "POST", "/v1/brokers/"+broker+"/token", account, nil, 200)
			case "offline":
				wsRequest(t, watch, 1, "offline", nil, 200)
			}
			if wsUntil(t, watch, "revoked")["status"] == float64(200) {
				t.Fatal("invalid revoke status")
			}
			wsClosed(t, watch)
			_ = wsUntil(t, client, "revoked")
			wsClosed(t, client)
			if mode == "offline" {
				fresh := wsConnect(t, h, "/v1/ws/brokers/"+broker, device)
				snapshot := wsRead(t, fresh)
				if len(snapshot["body"].(map[string]any)["sessions"].([]any)) != 0 {
					t.Fatal("offline retained sessions")
				}
				wsRequest(t, fresh, 1, "heartbeat", nil, 200)
				fixtureSession(t, s, account, broker)
				_ = wsUntil(t, fresh, "sessions")
			}
		})
	}
}

func TestWSLeaseExpiryDoesNotRenewOnPingOrACK(t *testing.T) {
	s, h, _, _, broker, device, sid, caller := wsFixture(t, Config{BrokerLease: 250 * time.Millisecond, SessionTTL: 3 * time.Second}, false)
	watch := wsConnect(t, h, "/v1/ws/brokers/"+broker, device)
	_ = wsRead(t, watch)
	client := wsConnect(t, h, "/v1/ws/sessions/"+sid, caller)
	_ = wsRead(t, client)
	if err := client.WriteControl(websocket.PingMessage, []byte("not a lease"), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	wsACK(t, client, 0)
	if wsUntil(t, client, "revoked")["status"] != float64(409) {
		t.Fatal("broker lease did not expire")
	}
	wsClosed(t, client)
	before, err := s.broker(broker)
	if err != nil || before.Online {
		t.Fatal("ping renewed broker lease")
	}
	wsRequest(t, watch, 1, "heartbeat", nil, 200)
	after, err := s.broker(broker)
	if err != nil || !after.Online {
		t.Fatal("offline watcher could not renew")
	}
}

func TestWSStrictFramesAndConnectionLimits(t *testing.T) {
	_, h, _, _, broker, device, sid, caller := wsFixture(t, Config{}, false)
	bad := []struct {
		name string
		kind int
		data string
	}{
		{"binary", websocket.BinaryMessage, `{}`},
		{"duplicate envelope", websocket.TextMessage, `{"v":1,"v":1,"type":"request","id":1,"op":"heartbeat","body":null}`},
		{"duplicate body", websocket.TextMessage, `{"v":1,"type":"request","id":1,"op":"send","body":{"sequence":1,"data":"a","data":"b"}}`},
		{"unknown field", websocket.TextMessage, `{"v":1,"type":"request","id":1,"op":"heartbeat","body":null,"side":"broker"}`},
		{"case mismatch", websocket.TextMessage, `{"V":1,"type":"request","id":1,"op":"heartbeat","body":null}`},
		{"unsafe ID", websocket.TextMessage, `{"v":1,"type":"request","id":9007199254740992,"op":"heartbeat","body":null}`},
		{"fraction ID", websocket.TextMessage, `{"v":1,"type":"request","id":1.0,"op":"heartbeat","body":null}`},
		{"wrong body type", websocket.TextMessage, `{"v":1,"type":"request","id":1,"op":"heartbeat","body":{}}`},
		{"unknown op", websocket.TextMessage, `{"v":1,"type":"request","id":1,"op":"/v1/admin/info","body":null}`},
		{"wrong version", websocket.TextMessage, `{"v":2,"type":"ack","sequence":0}`},
		{"trailing JSON", websocket.TextMessage, `{"v":1,"type":"ack","sequence":0}{}`},
		{"invalid UTF8", websocket.TextMessage, string([]byte{0xff, 0xfe})},
		{"unpaired surrogate", websocket.TextMessage, `{"v":1,"type":"request","id":1,"op":"send","body":{"sequence":1,"data":"\ud800"}}`},
		{"oversized", websocket.TextMessage, strings.Repeat(" ", wsMaxFrame+1)},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			c := wsConnect(t, h, "/v1/ws/sessions/"+sid, caller)
			_ = wsRead(t, c)
			_ = c.WriteMessage(tc.kind, []byte(tc.data))
			wsClosed(t, c)
			_ = c.Close()
		})
	}
	watchers := []*websocket.Conn{}
	for i := 0; i < wsMaxScopeConnections; i++ {
		c := wsConnect(t, h, "/v1/ws/brokers/"+broker, device)
		_ = wsRead(t, c)
		watchers = append(watchers, c)
	}
	c, res, err := wsDialer(h).Dial(wsURL(h, "/v1/ws/brokers/"+broker), http.Header{"Authorization": []string{"Bearer " + device}})
	if c != nil {
		_ = c.Close()
		t.Fatal("scope limit ignored")
	}
	if err == nil || res == nil || res.StatusCode != 429 {
		t.Fatalf("connection bound status=%v err=%v", res, err)
	}
	_ = res.Body.Close()
	for _, c := range watchers {
		_ = c.Close()
	}
}

func TestWSCloseJoinsHijackedSocketsBeforeSQLite(t *testing.T) {
	s, h, _, _, broker, device, sid, caller := wsFixture(t, Config{}, false)
	watch := wsConnect(t, h, "/v1/ws/brokers/"+broker, device)
	_ = wsRead(t, watch)
	client := wsConnect(t, h, "/v1/ws/sessions/"+sid, caller)
	_ = wsRead(t, client)
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("Close did not join WebSocket handlers")
	}
	wsClosed(t, watch)
	wsClosed(t, client)
	s.ws.mu.Lock()
	peers, queued := len(s.ws.peers), s.ws.queuedBytes
	s.ws.mu.Unlock()
	if peers != 0 || queued != 0 || len(s.ws.readSlots) != 0 {
		t.Fatal("WS resources leaked", peers, queued, len(s.ws.readSlots))
	}
	if err := s.db.Ping(); err == nil {
		t.Fatal("SQLite remains open")
	}
}

func TestWSHubQueueBoundsAndCoalescedNotifications(t *testing.T) {
	s := apiFixture(t, Config{})
	t.Cleanup(func() {
		s.ws.mu.Lock()
		peers := make([]*wsPeer, 0, len(s.ws.peers))
		for p := range s.ws.peers {
			peers = append(peers, p)
		}
		s.ws.mu.Unlock()
		for _, p := range peers {
			p.stop()
			s.ws.unregister(p)
		}
	})
	p := &wsPeer{s: s, identity: principal{tenant: "isolated"}, target: "target", done: make(chan struct{}), wake: make(chan struct{}, 1), out: make(chan wsPacket, wsMaxQueueFrames)}
	if err := s.ws.register(p); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		s.ws.wake(func(*wsPeer) bool { return true })
	}
	if len(p.wake) != 1 {
		t.Fatal("unbounded notification channel")
	}
	for i := 0; i < wsMaxQueueFrames; i++ {
		if !p.enqueue(map[string]any{"v": 1, "type": "result", "body": "small"}, 0, false, 0) {
			t.Fatal("early queue overflow")
		}
	}
	if p.enqueue(map[string]any{"v": 1, "type": "result", "body": "overflow"}, 0, false, 0) {
		t.Fatal("frame-count bound ignored")
	}
	select {
	case <-p.done:
	default:
		t.Fatal("overflow did not disconnect")
	}
	s.ws.unregister(p)
	p = &wsPeer{s: s, identity: principal{tenant: "isolated"}, target: "target", done: make(chan struct{}), wake: make(chan struct{}, 1), out: make(chan wsPacket, wsMaxQueueFrames)}
	if err := s.ws.register(p); err != nil {
		t.Fatal(err)
	}
	if !p.enqueue(map[string]any{"body": strings.Repeat("x", wsMaxQueueBytes/2)}, 0, false, 0) {
		t.Fatal("first bounded frame refused")
	}
	if p.enqueue(map[string]any{"body": strings.Repeat("y", wsMaxQueueBytes/2)}, 0, false, 0) {
		t.Fatal("byte bound ignored")
	}
	s.ws.unregister(p)
	s.ws.mu.Lock()
	queued := s.ws.queuedBytes
	s.ws.mu.Unlock()
	if queued != 0 {
		t.Fatal("queue accounting leaked", queued)
	}
	// Global-byte admission must fail closed independently of per-peer bounds.
	p = &wsPeer{s: s, identity: principal{tenant: "byte-limit"}, done: make(chan struct{}), out: make(chan wsPacket, wsMaxQueueFrames)}
	if err := s.ws.register(p); err != nil {
		t.Fatal(err)
	}
	s.ws.mu.Lock()
	s.ws.queuedBytes = wsMaxGlobalQueueBytes
	s.ws.mu.Unlock()
	if p.enqueue(map[string]any{"body": "small"}, 0, false, 0) {
		t.Fatal("global byte bound ignored")
	}
	s.ws.unregister(p)
	s.ws.mu.Lock()
	s.ws.queuedBytes = 0
	s.ws.mu.Unlock()
	for i := 0; i < wsMaxConnections; i++ {
		p = &wsPeer{s: s, hash: fmt.Sprintf("hash-%d", i), target: fmt.Sprintf("target-%d", i), identity: principal{tenant: fmt.Sprintf("tenant-%d", i/wsMaxTenantConnections)}, done: make(chan struct{})}
		if err := s.ws.register(p); err != nil {
			t.Fatal("premature global admission denial", i, err)
		}
		if i == wsMaxTenantConnections-1 {
			extra := &wsPeer{identity: principal{tenant: "tenant-0"}, hash: "different", target: "different", done: make(chan struct{})}
			if err := s.ws.register(extra); err == nil {
				t.Fatal("tenant connection bound ignored")
			}
		}
	}
	if err := s.ws.register(&wsPeer{identity: principal{tenant: "fresh-tenant"}, done: make(chan struct{})}); err == nil {
		t.Fatal("global connection bound ignored")
	}
}

func TestWSRESTConcurrentCommitSameDirectionalSequence(t *testing.T) {
	s, h, _, _, _, device, sid, caller := wsFixture(t, Config{}, false)
	client := wsConnect(t, h, "/v1/ws/sessions/"+sid, caller)
	_ = wsRead(t, client)
	host := wsConnect(t, h, "/v1/ws/sessions/"+sid, device)
	_ = wsRead(t, host)
	start := make(chan struct{})
	restStatus := make(chan int, 1)
	go func() {
		<-start
		r := httptest.NewRequest("POST", "/v1/sessions/"+sid+"/messages", strings.NewReader(`{"sequence":1,"data":"shared-immutable"}`))
		r.Header.Set("Authorization", "Bearer "+caller)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		restStatus <- w.Code
	}()
	close(start)
	if err := client.WriteJSON(map[string]any{"v": 1, "type": "request", "id": 91, "op": "send", "body": Message{1, "shared-immutable"}}); err != nil {
		t.Fatal(err)
	}
	result := wsUntil(t, client, "result")
	wsStatus := int(result["status"].(float64))
	var httpStatus int
	select {
	case httpStatus = <-restStatus:
	case <-time.After(3 * time.Second):
		t.Fatal("REST/WS SQLite deadlock")
	}
	if !((wsStatus == 201 && httpStatus == 200) || (wsStatus == 200 && httpStatus == 201)) {
		t.Fatal("commit/idempotency differed by transport", wsStatus, httpStatus)
	}
	m := wsUntil(t, host, "message")
	if m["sequence"] != float64(1) || m["data"] != "shared-immutable" {
		t.Fatal("shared owner delivered wrong message", m)
	}
	wsACK(t, host, 1)
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM messages WHERE session_id=? AND side='client'", sid).Scan(&count); err != nil || count != 1 {
		t.Fatal("two transports duplicated durable message", count, err)
	}
	// Sender's own history must never authorize an opposite-side cursor.
	c, res, err := wsDialer(h).Dial(wsURL(h, "/v1/ws/sessions/"+sid+"?after=1"), http.Header{"Authorization": []string{"Bearer " + caller}})
	if c != nil {
		_ = c.Close()
		t.Fatal("after used wrong-direction history")
	}
	if err == nil || res == nil || res.StatusCode != 400 {
		t.Fatal("invalid cross-direction cursor accepted", res, err)
	}
	_ = res.Body.Close()
}

func TestWSHookCancellationAndDelayedAuthorization(t *testing.T) {
	for _, mode := range []string{"disconnect", "revalidate"} {
		t.Run(mode, func(t *testing.T) {
			entered, release, canceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
			cfg := Config{BeforeWebSocketRequest: func(ctx context.Context, role, op string) error {
				if role != "session" || op != "heartbeat" {
					return nil
				}
				close(entered)
				select {
				case <-ctx.Done():
					close(canceled)
					return ctx.Err()
				case <-release:
					return nil
				}
			}}
			s, h, _, _, _, _, sid, caller := wsFixture(t, cfg, false)
			c := wsConnect(t, h, "/v1/ws/sessions/"+sid, caller)
			_ = wsRead(t, c)
			if err := c.WriteJSON(map[string]any{"v": 1, "type": "request", "id": 1, "op": "heartbeat", "body": nil}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("hook not entered")
			}
			if mode == "disconnect" {
				_ = c.Close()
				select {
				case <-canceled:
				case <-time.After(3 * time.Second):
					t.Fatal("socket close did not cancel hook")
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := s.db.Exec("DELETE FROM tokens WHERE hash=?", tokenHash(caller)); err != nil {
					t.Fatal(err)
				}
				close(release)
				result := wsUntil(t, c, "result")
				if result["status"] != float64(401) {
					t.Fatal("delayed request used stale authorization", result)
				}
				_ = wsUntil(t, c, "revoked")
				wsClosed(t, c)
			}
		})
	}
}

func TestWSSFiveSecondAuthorizationCutoff(t *testing.T) {
	_, h, _, _, _, _, sid, caller := wsFixture(t, Config{BrokerLease: 5 * time.Second, SessionTTL: 5 * time.Second}, true)
	c := wsConnect(t, h, "/v1/ws/sessions/"+sid, caller)
	_ = wsRead(t, c)
	start := time.Now()
	_ = c.SetReadDeadline(start.Add(7 * time.Second))
	_, data, err := c.ReadMessage()
	if err != nil {
		t.Fatal("no idle WSS revocation", err)
	}
	var out map[string]any
	if err = json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out["type"] != "revoked" || (out["status"] != float64(401) && out["status"] != float64(409) && out["status"] != float64(410) && out["status"] != float64(404)) {
		t.Fatal("lease cutoff not fail closed", out)
	}
	if time.Since(start) > 7*time.Second {
		t.Fatal("authorization cutoff unbounded")
	}
	wsClosed(t, c)
}

func TestWSLargeEscapedMessageWithinEnvelopeAndHTTPDeadlineCleared(t *testing.T) {
	s, _, _, _, broker, device, sid, caller := wsFixture(t, Config{}, false)
	h := httptest.NewUnstartedServer(s.Handler())
	h.Config.ReadTimeout = 30 * time.Millisecond
	h.Config.WriteTimeout = 30 * time.Millisecond
	h.Start()
	t.Cleanup(h.Close)
	c := wsConnect(t, h, "/v1/ws/sessions/"+sid, caller)
	_ = wsRead(t, c)
	wait := time.NewTimer(80 * time.Millisecond)
	defer wait.Stop()
	<-wait.C
	message := strings.Repeat("\x01", s.cfg.MaxMessageBytes)
	wsRequest(t, c, 1, "send", Message{1, message}, 201)
	host := wsConnect(t, h, "/v1/ws/sessions/"+sid, device)
	_ = wsRead(t, host)
	m := wsUntil(t, host, "message")
	if m["data"] != message {
		t.Fatal("JSON escaping changed opaque body")
	}
	wsACK(t, host, 1)
	watch := wsConnect(t, h, "/v1/ws/brokers/"+broker, device)
	_ = wsRead(t, watch)
	wsRequest(t, watch, 1, "heartbeat", nil, 200)
}

func TestWSRegistrationSnapshotRaceNoMissedCreate(t *testing.T) {
	s, h, _, account, broker, device, _, _ := wsFixture(t, Config{}, false)
	// Exercise concurrent subscription and SQL commit without periodic HTTP polls.
	for round := 0; round < 8; round++ {
		start := make(chan struct{})
		var c *websocket.Conn
		var dialErr error
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, _, dialErr = wsDialer(h).Dial(wsURL(h, "/v1/ws/brokers/"+broker), http.Header{"Authorization": []string{"Bearer " + device}})
		}()
		close(start)
		sid, _ := fixtureSession(t, s, account, broker)
		wg.Wait()
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		seen := false
		for n := 0; n < 4 && !seen; n++ {
			push := wsUntil(t, c, "sessions")
			for _, raw := range push["body"].(map[string]any)["sessions"].([]any) {
				if raw.(map[string]any)["session_id"] == sid {
					seen = true
				}
			}
		}
		_ = c.Close()
		if !seen {
			t.Fatal("session lost during registration", sid)
		}
	}
}
