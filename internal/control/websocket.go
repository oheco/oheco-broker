package control

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

const (
	wsProtocol             = "ob-signaling-v1"
	wsMaxFrame             = 262144
	wsMaxConnections       = 1024
	wsMaxTenantConnections = 128
	wsMaxScopeConnections  = 4
	wsMaxQueueFrames       = 32
	wsMaxQueueBytes        = 262144
	wsMaxGlobalQueueBytes  = 32 << 20
	wsWriteTimeout         = 2 * time.Second
	wsNetworkTimeout       = 45 * time.Second
	wsRevalidateInterval   = time.Second
	wsMessageWindow        = 4
)

// Only this package can attach the hashed bearer to an internal, scoped request.
// Upgraded peers retain no plaintext credential and never cache authorization.
type wsAuthKey struct{}

type wsHub struct {
	mu          sync.Mutex
	peers       map[*wsPeer]struct{}
	closed      bool
	queuedBytes int
	wg          sync.WaitGroup
	// At most 32 MiB of maximum-sized application frames are decoded at once.
	readSlots    chan struct{}
	writeSlots   chan struct{}
	marshalSlots chan struct{}
}

func newWSHub() *wsHub {
	return &wsHub{peers: make(map[*wsPeer]struct{}), readSlots: make(chan struct{}, 128), writeSlots: make(chan struct{}, 128), marshalSlots: make(chan struct{}, 32)}
}

func (h *wsHub) register(p *wsPeer) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return fail(503, "server closed")
	}
	tenant, scope := 0, 0
	for other := range h.peers {
		if other.identity.tenant == p.identity.tenant {
			tenant++
		}
		if other.hash == p.hash && other.target == p.target && other.brokerWatch == p.brokerWatch {
			scope++
		}
	}
	if len(h.peers) >= wsMaxConnections || tenant >= wsMaxTenantConnections || scope >= wsMaxScopeConnections {
		return fail(429, "WebSocket connection limit reached")
	}
	h.peers[p] = struct{}{}
	h.wg.Add(1)
	return nil
}

func (h *wsHub) unregister(p *wsPeer) {
	h.mu.Lock()
	delete(h.peers, p)
	// All writes have joined before releasing remaining queue accounting.
	h.queuedBytes -= p.queueBytes
	p.queueBytes = 0
	h.mu.Unlock()
	h.wg.Done()
}

// Notification hooks never access SQLite. In particular, they can safely be
// called after a commit while a REST handler is still unwinding a deferred rollback.
func (h *wsHub) wake(match func(*wsPeer) bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for p := range h.peers {
		if match(p) {
			select {
			case p.wake <- struct{}{}:
			default:
			}
		}
	}
}

func (h *wsHub) close() {
	h.mu.Lock()
	h.closed = true
	peers := make([]*wsPeer, 0, len(h.peers))
	for p := range h.peers {
		peers = append(peers, p)
	}
	h.mu.Unlock()
	for _, p := range peers {
		p.stop()
	}
	h.wg.Wait()
}

func (s *Server) notifyWSBroker(id string) {
	s.ws.wake(func(p *wsPeer) bool { return p.identity.broker == id })
}
func (s *Server) notifyWSSession(id string) {
	s.ws.wake(func(p *wsPeer) bool { return !p.brokerWatch && p.target == id })
}
func (s *Server) notifyWSTenant(id string) {
	s.ws.wake(func(p *wsPeer) bool { return p.identity.tenant == id })
}

// Explicit offline is recoverable by the same device on a NEW connection, but
// its old sockets must not survive and accidentally revive old forwarding peers.
func (s *Server) offlineWSBroker(id string) {
	s.ws.mu.Lock()
	defer s.ws.mu.Unlock()
	for p := range s.ws.peers {
		if p.identity.broker == id {
			p.offline = true
			select {
			case p.wake <- struct{}{}:
			default:
			}
		}
	}
}

type wsPacket struct {
	data      []byte
	sequence  int64
	terminal  bool
	result    bool
	closeCode int
}
type wsInput struct {
	kind     string
	id       int64
	op       string
	body     json.RawMessage
	sequence int64
}
type wsPeer struct {
	s            *Server
	ctx          context.Context
	cancel       context.CancelFunc
	hash         string
	identity     principal
	target, side string
	brokerWatch  bool
	connMu       sync.Mutex
	conn         *websocket.Conn
	stopOnce     sync.Once
	terminating  atomic.Bool
	done         chan struct{}
	wake         chan struct{}
	in           chan wsInput
	out          chan wsPacket
	// Protected by hub.mu; no socket I/O under the hub lock.
	queueBytes int
	offline    bool
	// Writer commits sent after a successful network write. ACK checks under the
	// same lock, so a very fast ACK cannot race the WriteMessage completion.
	sentMu        sync.Mutex
	sent          int64
	acked, queued int64  // owner-loop only
	lastSnapshot  []byte // owner-loop only
}

func (p *wsPeer) stop() {
	p.stopOnce.Do(func() {
		close(p.done)
		if p.cancel != nil {
			p.cancel()
		}
		p.connMu.Lock()
		if p.conn != nil {
			_ = p.conn.Close()
		}
		p.connMu.Unlock()
	})
}
func (p *wsPeer) attach(c *websocket.Conn) bool {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	select {
	case <-p.done:
		_ = c.Close()
		return false
	default:
	}
	p.conn = c
	return true
}
func (p *wsPeer) request(body []byte) *http.Request {
	r, _ := http.NewRequestWithContext(context.WithValue(p.ctx, wsAuthKey{}, p.hash), "POST", "http://internal.invalid/", bytes.NewReader(body))
	r.SetPathValue("id", p.target)
	return r
}
func (p *wsPeer) validate() error {
	r := p.request(nil)
	var identity principal
	var side string
	var err error
	if p.brokerWatch {
		identity, _, err = p.s.deviceBroker(r, false)
	} else {
		identity, _, side, err = p.s.sessionPrincipal(r)
	}
	if err != nil {
		return err
	}
	if identity != p.identity || (!p.brokerWatch && side != p.side) {
		return fail(401, "authorization changed")
	}
	p.s.ws.mu.Lock()
	offline := p.offline
	p.s.ws.mu.Unlock()
	if offline {
		return fail(409, "broker offline; reconnect required")
	}
	return nil
}

func wsError(err error) (int, map[string]string) {
	var a *apiError
	if errors.As(err, &a) {
		return a.code, map[string]string{"error": a.message}
	}
	return 500, map[string]string{"error": "internal server error"}
}
func (p *wsPeer) enqueue(v any, sequence int64, terminal bool, code int) bool {
	select {
	case p.s.ws.marshalSlots <- struct{}{}:
	case <-p.done:
		return false
	}
	defer func() { <-p.s.ws.marshalSlots }()
	data, err := json.Marshal(v)
	if err != nil || len(data) > wsMaxFrame {
		p.stop()
		return false
	}
	h := p.s.ws
	h.mu.Lock()
	select {
	case <-p.done:
		h.mu.Unlock()
		return false
	default:
	}
	if p.queueBytes+len(data) > wsMaxQueueBytes || h.queuedBytes+len(data) > wsMaxGlobalQueueBytes {
		h.mu.Unlock()
		p.stop()
		return false
	}
	isResult := false
	if fields, ok := v.(map[string]any); ok {
		isResult = fields["type"] == "result"
	}
	packet := wsPacket{data: data, sequence: sequence, terminal: terminal, result: isResult, closeCode: code}
	select {
	case p.out <- packet:
		p.queueBytes += len(data)
		h.queuedBytes += len(data)
		h.mu.Unlock()
		return true
	default:
		h.mu.Unlock()
		p.stop()
		return false
	}
}
func (p *wsPeer) revoked(err error) {
	// Never drain stale authenticated pushes ahead of revocation. Already
	// committed RPC results (especially offline/delete) keep their FIFO order.
	p.terminating.Store(true)
	status, body := wsError(err)
	code := websocket.ClosePolicyViolation
	if status >= 500 {
		code = websocket.CloseInternalServerErr
	}
	p.enqueue(map[string]any{"v": 1, "type": "revoked", "status": status, "body": body}, 0, true, code)
}

func wsCheckOrigin(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	if len(origins) == 0 {
		return true
	} // native bearer-authenticated clients
	if len(origins) != 1 || strings.Contains(origins[0], ",") {
		return false
	}
	u, err := url.Parse(origins[0])
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return err == nil && u.Scheme == scheme && strings.EqualFold(u.Host, r.Host) && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Path == "" && u.Opaque == ""
}
func wsAfter(r *http.Request, max int) (int64, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, fail(400, "invalid WebSocket query")
	}
	for key, values := range q {
		if key != "after" || len(values) != 1 || values[0] == "" {
			return 0, fail(400, "only one after cursor is allowed")
		}
	}
	text := q.Get("after")
	if text == "" {
		return 0, nil
	}
	for _, ch := range text {
		if ch < '0' || ch > '9' {
			return 0, fail(400, "invalid after cursor")
		}
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n > int64(max) {
		return 0, fail(400, "invalid after cursor")
	}
	return n, nil
}
func (s *Server) websocketBroker(w http.ResponseWriter, r *http.Request) error {
	return s.websocketConnect(w, r, true)
}
func (s *Server) websocketSession(w http.ResponseWriter, r *http.Request) error {
	return s.websocketConnect(w, r, false)
}
func (s *Server) websocketConnect(w http.ResponseWriter, r *http.Request, brokerWatch bool) error {
	if len(r.Header.Values("Authorization")) != 1 || bearer(r) == "" {
		return fail(401, "one bearer is required")
	}
	// Cookies never participate in authentication; query credentials are rejected.
	if !wsCheckOrigin(r) {
		return fail(403, "WebSocket origin denied")
	}
	accepted := false
	for _, sub := range websocket.Subprotocols(r) {
		if sub == wsProtocol {
			accepted = true
		}
	}
	if !accepted {
		return fail(400, "ob-signaling-v1 subprotocol required")
	}
	after, err := wsAfter(r, s.cfg.MaxMessagesPerDirection)
	if err != nil {
		return err
	}
	if brokerWatch && r.URL.RawQuery != "" {
		return fail(400, "broker watcher has no query parameters")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &wsPeer{s: s, ctx: ctx, cancel: cancel, hash: tokenHash(bearer(r)), target: r.PathValue("id"), brokerWatch: brokerWatch, done: make(chan struct{}), wake: make(chan struct{}, 1), in: make(chan wsInput, 8), out: make(chan wsPacket, wsMaxQueueFrames), acked: after, queued: after, sent: after}
	if brokerWatch {
		p.identity, _, err = s.deviceBroker(r, false)
	} else {
		p.identity, _, p.side, err = s.sessionPrincipal(r)
	}
	if err != nil {
		return err
	}
	if !brokerWatch {
		var history int64
		err = s.db.QueryRow("SELECT COALESCE(MAX(sequence),0) FROM messages WHERE session_id=? AND side=?", p.target, oppositeSide(p.side)).Scan(&history)
		if err != nil {
			return err
		}
		if after > history {
			return fail(400, "after cursor exceeds directional history")
		}
	}
	// Register BEFORE fetching any snapshot. An event concurrent with initial
	// state is either included by the query or leaves a wake for the next pass.
	if err = s.ws.register(p); err != nil {
		return err
	}
	defer s.ws.unregister(p)
	defer p.stop()
	// The HTTP request may stay on its handler stack for the socket lifetime.
	// After scope validation, only the digest is needed for fresh authorization.
	r.Header.Del("Authorization")
	r.Header.Del("Cookie")
	u := websocket.Upgrader{Subprotocols: []string{wsProtocol}, ReadBufferSize: 4096, WriteBufferSize: 4096, HandshakeTimeout: 5 * time.Second, EnableCompression: false, CheckOrigin: wsCheckOrigin}
	c, err := u.Upgrade(w, r, nil)
	if err != nil {
		return nil
	} // Gorilla already wrote the HTTP failure
	if !p.attach(c) {
		return nil
	}
	// Hijacking must not inherit an HTTP listener's absolute read/write timeout.
	_ = c.UnderlyingConn().SetDeadline(time.Time{})
	c.SetReadLimit(wsMaxFrame)
	_ = c.SetReadDeadline(time.Now().Add(wsNetworkTimeout))
	c.SetPongHandler(func(string) error { return c.SetReadDeadline(time.Now().Add(wsNetworkTimeout)) })
	c.SetPingHandler(func(data string) error {
		return c.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(wsWriteTimeout))
	})
	var joins sync.WaitGroup
	joins.Add(2)
	go func() { defer joins.Done(); p.writer() }()
	go func() { defer joins.Done(); p.reader() }()
	p.run()
	p.stop()
	joins.Wait()
	// The reader has joined; release any queued, never-executed input budget.
	for {
		select {
		case <-p.in:
			<-s.ws.readSlots
		default:
			return nil
		}
	}
}
func oppositeSide(side string) string {
	if side == "broker" {
		return "client"
	}
	return "broker"
}

func (p *wsPeer) reader() {
	defer p.stop()
	for {
		kind, rd, err := p.conn.NextReader()
		if err != nil {
			return
		}
		if kind != websocket.TextMessage {
			_ = p.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseUnsupportedData, "text frames required"), time.Now().Add(wsWriteTimeout))
			return
		}
		select {
		case p.s.ws.readSlots <- struct{}{}:
		case <-p.done:
			return
		}
		data, err := io.ReadAll(io.LimitReader(rd, wsMaxFrame+1))
		var input wsInput
		if err == nil && len(data) <= wsMaxFrame && utf8.Valid(data) {
			input, err = parseWSInput(data, p.brokerWatch, p.s.cfg.MaxMessageBytes, p.s.cfg.MaxMessagesPerDirection)
		} else if err == nil {
			err = errors.New("invalid text frame")
		}
		if err != nil {
			<-p.s.ws.readSlots
			_ = p.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "invalid signaling frame"), time.Now().Add(wsWriteTimeout))
			return
		}
		select {
		case p.in <- input:
			// The owner releases this slot after processing. Continue reading to
			// observe network close and cancel a blocked embedder hook.
		case <-p.done:
			<-p.s.ws.readSlots
			return
		default:
			<-p.s.ws.readSlots
			return // bounded incoming queue overflow: fail closed, never grow RAM
		}
		select {
		case <-p.done:
			return
		default:
		}
	}
}
func (p *wsPeer) writer() {
	defer p.stop()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ping.C:
			if p.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(wsWriteTimeout)) != nil {
				return
			}
		case packet := <-p.out:
			if p.terminating.Load() && !packet.result && !packet.terminal {
				p.s.ws.mu.Lock()
				p.queueBytes -= len(packet.data)
				p.s.ws.queuedBytes -= len(packet.data)
				p.s.ws.mu.Unlock()
				continue
			}
			// Held packets remain charged to the global queue until a bounded
			// network writer slot is available (at most 32 MiB in-flight).
			select {
			case p.s.ws.writeSlots <- struct{}{}:
			case <-p.done:
				return
			}
			p.s.ws.mu.Lock()
			p.queueBytes -= len(packet.data)
			p.s.ws.queuedBytes -= len(packet.data)
			p.s.ws.mu.Unlock()
			_ = p.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if packet.sequence != 0 {
				p.sentMu.Lock()
			}
			err := p.conn.WriteMessage(websocket.TextMessage, packet.data)
			if packet.sequence != 0 {
				if err == nil {
					p.sent = packet.sequence
				}
				p.sentMu.Unlock()
			}
			<-p.s.ws.writeSlots
			if err != nil {
				return
			}
			if packet.terminal {
				_ = p.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(packet.closeCode, "signaling scope unavailable"), time.Now().Add(wsWriteTimeout))
				return
			}
		}
	}
}
func (p *wsPeer) run() {
	tick := time.NewTicker(wsRevalidateInterval)
	defer tick.Stop()
	if err := p.catchup(true); err != nil {
		p.revoked(err)
		<-p.done
		return
	}
	for {
		select {
		case <-p.done:
			return
		case <-tick.C:
			if err := p.validate(); err != nil {
				p.revoked(err)
				<-p.done
				return
			}
		case <-p.wake:
			if err := p.catchup(false); err != nil {
				p.revoked(err)
				<-p.done
				return
			}
		case in := <-p.in:
			if err := p.validate(); err != nil {
				<-p.s.ws.readSlots
				p.revoked(err)
				<-p.done
				return
			}
			if in.kind == "ack" {
				p.sentMu.Lock()
				valid := in.sequence <= p.sent
				p.sentMu.Unlock()
				if !valid {
					<-p.s.ws.readSlots
					p.revoked(fail(400, "ACK exceeds sent history"))
					<-p.done
					return
				}
				if in.sequence > p.acked {
					p.acked = in.sequence
				}
				<-p.s.ws.readSlots
				if err := p.catchup(false); err != nil {
					p.revoked(err)
					<-p.done
					return
				}
			} else {
				status, body := p.rpc(in)
				p.enqueue(map[string]any{"v": 1, "type": "result", "id": in.id, "status": status, "body": body}, 0, false, 0)
				<-p.s.ws.readSlots
				if status == 401 || status == 403 || status == 404 || status == 410 {
					// Permission-specific errors (caller approve / TURN policy) are
					// not necessarily revoked identity: consult the scope again.
					if err := p.validate(); err != nil {
						p.revoked(err)
						<-p.done
						return
					}
				}
			}
		}
	}
}

// captureWriter bridges only explicitly allowed business handlers. There is no
// ServeMux dispatch, caller-provided method/path, or admin/account operation.
type wsCaptureWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *wsCaptureWriter) Header() http.Header { return w.header }
func (w *wsCaptureWriter) WriteHeader(n int) {
	if w.status == 0 {
		w.status = n
	}
}
func (w *wsCaptureWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.body.Write(b)
}
func (p *wsPeer) rpc(in wsInput) (int, any) {
	if hook := p.s.cfg.BeforeWebSocketRequest; hook != nil {
		role := "session"
		if p.brokerWatch {
			role = "broker"
		}
		if err := hook(p.ctx, role, in.op); err != nil {
			return wsError(err)
		}
		// A delayed request cannot use its pre-hook authorization snapshot.
		if err := p.validate(); err != nil {
			return wsError(err)
		}
	}
	var handler func(http.ResponseWriter, *http.Request) error
	if p.brokerWatch {
		switch in.op {
		case "heartbeat":
			handler = p.s.heartbeat
		case "offline":
			handler = p.s.offlineBroker
		}
	} else {
		switch in.op {
		case "heartbeat":
			handler = p.s.sessionHeartbeat
		case "capabilities":
			handler = p.s.getSession
		case "send":
			handler = p.s.sendMessage
		case "approve":
			handler = p.s.approveSession
		case "turn":
			handler = p.s.sessionTURN
		case "delete":
			handler = p.s.deleteSession
		}
	}
	if handler == nil {
		return 400, map[string]string{"error": "operation unavailable on this scope"}
	}
	w := &wsCaptureWriter{header: make(http.Header)}
	if err := handler(w, p.request(in.body)); err != nil {
		return wsError(err)
	}
	if !json.Valid(w.body.Bytes()) {
		return 500, map[string]string{"error": "invalid internal result"}
	}
	return w.status, json.RawMessage(append([]byte(nil), w.body.Bytes()...))
}

func (p *wsPeer) catchup(initial bool) error {
	if err := p.validate(); err != nil {
		return err
	}
	var snapshot any
	kind := "capabilities"
	if p.brokerWatch {
		kind = "sessions"
		// Materialize rows fully before any nested query: SQLite has one owner.
		rows, err := p.s.db.Query("SELECT id,tenant_id,broker_id,relay_mode,peer_authenticated,relay_approved,expires_at FROM sessions WHERE broker_id=? AND expires_at>? ORDER BY expires_at,id LIMIT 129", p.target, now())
		if err != nil {
			return err
		}
		out := make([]Session, 0)
		for rows.Next() {
			var v Session
			var peer, relay int
			var expiry int64
			if err = rows.Scan(&v.ID, &v.TenantID, &v.BrokerID, &v.RelayMode, &peer, &relay, &expiry); err != nil {
				_ = rows.Close()
				return err
			}
			v.PeerAuthenticated = peer != 0
			v.RelayApproved = relay != 0
			v.ExpiresAt = fromTimestamp(expiry)
			out = append(out, v)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return err
		}
		if len(out) > 128 {
			return fail(429, "broker snapshot exceeds 128 sessions")
		}
		snapshot = map[string]any{"sessions": out}
	} else {
		v, err := p.s.session(p.target)
		if err != nil {
			return err
		}
		snapshot, err = p.s.sessionStatus(v)
		if err != nil {
			return err
		}
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if initial || !bytes.Equal(encoded, p.lastSnapshot) {
		if !p.enqueue(map[string]any{"v": 1, "type": kind, "body": json.RawMessage(encoded)}, 0, false, 0) {
			return nil
		}
		p.lastSnapshot = encoded
	}
	if p.brokerWatch {
		return nil
	}
	// ACK-gated bounded window, one durable row at a time. Do not allocate a
	// whole mailbox per socket or drop history when a wake channel coalesces.
	for p.queued-p.acked < wsMessageWindow {
		var m Message
		err = p.s.db.QueryRow("SELECT sequence,data FROM messages WHERE session_id=? AND side=? AND sequence>? ORDER BY sequence LIMIT 1", p.target, oppositeSide(p.side), p.queued).Scan(&m.Sequence, &m.Data)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		if m.Sequence != p.queued+1 {
			return fail(409, "directional history gap")
		}
		if !p.enqueue(map[string]any{"v": 1, "type": "message", "sequence": m.Sequence, "data": m.Data}, m.Sequence, false, 0) {
			return nil
		}
		p.queued = m.Sequence
	}
	return nil
}

// parseObject rejects duplicate keys before unmarshalling. encoding/json alone
// silently accepts duplicate fields and matches struct fields case-insensitively.
func parseObject(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("object required")
	}
	out := make(map[string]json.RawMessage)
	for d.More() {
		tok, err = d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("key required")
		}
		if _, dup := out[key]; dup {
			return nil, errors.New("duplicate key")
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, err
		}
		out[key] = value
	}
	if _, err = d.Token(); err != nil {
		return nil, err
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	return out, nil
}
func exactKeys(fields map[string]json.RawMessage, keys ...string) bool {
	if len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	return true
}
func wsInteger(data []byte, min, max int64) (int64, error) {
	if len(data) == 0 {
		return 0, errors.New("integer required")
	}
	for _, c := range data {
		if c < '0' || c > '9' {
			return 0, errors.New("integer required")
		}
	}
	n, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil || n < min || n > max {
		return 0, errors.New("integer bounds")
	}
	return n, nil
}
func wsString(data []byte) (string, error) {
	var value string
	if len(data) == 0 || data[0] != '"' {
		return "", errors.New("string required")
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return "", err
	}
	// encoding/json replaces lone UTF-16 surrogates with U+FFFD. Opaque
	// envelopes must not be silently changed before durable idempotency checks.
	for i := 1; i < len(data)-1; i++ {
		if data[i] != '\\' {
			continue
		}
		if data[i+1] != 'u' {
			i++
			continue
		}
		n, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		if err != nil {
			return "", err
		}
		if n >= 0xdc00 && n <= 0xdfff {
			return "", errors.New("unpaired surrogate")
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+12 > len(data)-1 || data[i+6] != '\\' || data[i+7] != 'u' {
				return "", errors.New("unpaired surrogate")
			}
			low, err := strconv.ParseUint(string(data[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return "", errors.New("unpaired surrogate")
			}
			i += 11
		} else {
			i += 5
		}
	}
	return value, nil
}
func parseWSInput(data []byte, broker bool, maxBytes, maxMessages int) (wsInput, error) {
	var in wsInput
	fields, err := parseObject(data)
	if err != nil {
		return in, err
	}
	if _, err = wsInteger(fields["v"], 1, 1); err != nil {
		return in, err
	}
	in.kind, err = wsString(fields["type"])
	if err != nil {
		return in, err
	}
	if in.kind == "ack" {
		if broker || !exactKeys(fields, "v", "type", "sequence") {
			return in, errors.New("invalid ACK")
		}
		in.sequence, err = wsInteger(fields["sequence"], 0, int64(maxMessages))
		return in, err
	}
	if in.kind != "request" || !exactKeys(fields, "v", "type", "id", "op", "body") {
		return in, errors.New("invalid request")
	}
	in.id, err = wsInteger(fields["id"], 1, 9007199254740991)
	if err != nil {
		return in, err
	}
	in.op, err = wsString(fields["op"])
	if err != nil {
		return in, err
	}
	in.body = fields["body"]
	if in.op == "send" && !broker {
		body, err := parseObject(in.body)
		if err != nil || !exactKeys(body, "sequence", "data") {
			return in, errors.New("invalid send body")
		}
		if _, err = wsInteger(body["sequence"], 1, int64(maxMessages)); err != nil {
			return in, err
		}
		message, err := wsString(body["data"])
		if err != nil || len(message) > maxBytes {
			return in, errors.New("invalid message bounds")
		}
	} else if in.op == "approve" && !broker {
		body, err := parseObject(in.body)
		if err != nil || !exactKeys(body, "peer_authenticated", "relay") {
			return in, errors.New("invalid approval body")
		}
		for _, key := range []string{"peer_authenticated", "relay"} {
			if !bytes.Equal(body[key], []byte("true")) && !bytes.Equal(body[key], []byte("false")) {
				return in, errors.New("boolean required")
			}
		}
	} else {
		if !bytes.Equal(in.body, []byte("null")) {
			return in, errors.New("null body required")
		}
		valid := in.op == "heartbeat" || (broker && in.op == "offline") || (!broker && (in.op == "capabilities" || in.op == "turn" || in.op == "delete"))
		if !valid {
			return in, errors.New("unknown scoped operation")
		}
	}
	return in, nil
}
