// A disposable local fixture for C SDK acceptance; not a production launcher.
package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/oheco/oheco-broker/internal/control"
)

func main() {
	db := flag.String("db", "", "Private test SQLite file")
	ready := flag.String("ready", "", "Write endpoint information JSON here")
	listen := flag.String("listen", "127.0.0.1:0", "Local HTTP fixture address")
	turnListen := flag.String("turn-listen", "127.0.0.1:0", "Local TURN fixture address")
	turnSocketBuffer := flag.Int("turn-socket-buffer", 0, "Local TURN socket buffer bytes; zero selects the production default")
	lease := flag.Duration("broker-lease", 15*time.Second, "Local broker lease for failure injection")
	flag.Parse()
	token := os.Getenv("OB_PEER_TEST_ADMIN_TOKEN")
	if len(token) < 16 || *db == "" {
		fmt.Fprintln(os.Stderr, "fixture needs private DB and test admin token")
		os.Exit(2)
	}
	gate := newGate(nil, token)
	service, err := control.New(control.Config{DBPath: *db, AdminToken: token, RegistrationPolicy: "open", BrokerLease: *lease, SessionTTL: time.Minute, BeforeWebSocketRequest: gate.beforeWS, TURN: control.TURNConfig{Enabled: true, ListenAddr: *turnListen, PublicIP: "127.0.0.1", AllowLoopbackPeers: true, SocketBufferBytes: *turnSocketBuffer}})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer service.Close()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer listener.Close()
	info := map[string]string{"api": "http://" + listener.Addr().String(), "turn": service.TURNAddr()}
	if *ready != "" {
		data, _ := json.Marshal(info)
		if err = os.WriteFile(*ready, data, 0600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(info)
	gate.next = service.Handler()
	defer gate.release()
	// Recovery tests need nonsecret logical IDs for explicit revocation, while
	// the public C peer API deliberately keeps transport credentials private.
	// This route exists only in the disposable fixture and requires its admin.
	inspection, err := sql.Open("sqlite3", *db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	inspection.SetMaxOpenConns(1)
	defer inspection.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__test/connections" {
			gate.ServeHTTP(w, r)
			return
		}
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(token)) != 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		rows, e := inspection.QueryContext(r.Context(), "SELECT id,generation,current_session_id,revoked_reason FROM connections WHERE broker_id=? ORDER BY created_at,id LIMIT 129", r.URL.Query().Get("broker_id"))
		if e != nil {
			http.Error(w, "fixture inspection failed", 500)
			return
		}
		defer rows.Close()
		out := make([]map[string]any, 0)
		for rows.Next() {
			var id, sid, revoked string
			var generation uint64
			if e = rows.Scan(&id, &generation, &sid, &revoked); e != nil {
				http.Error(w, "fixture scan failed", 500)
				return
			}
			out = append(out, map[string]any{"connection_id": id, "generation": generation, "session_id": sid, "revoked": revoked != ""})
		}
		if e = rows.Err(); e != nil {
			http.Error(w, "fixture read failed", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"connections": out})
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
		gate.release()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		<-done
	case err = <-done:
		if err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, err)
		}
	}
}
