// A disposable local fixture for C SDK acceptance; not a production launcher.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oheco/oheco-broker/internal/control"
)

func main() {
	db := flag.String("db", "", "Private test SQLite file")
	ready := flag.String("ready", "", "Write endpoint information JSON here")
	listen := flag.String("listen", "127.0.0.1:0", "Local HTTP fixture address")
	turnListen := flag.String("turn-listen", "127.0.0.1:0", "Local TURN fixture address")
	lease := flag.Duration("broker-lease", 15*time.Second, "Local broker lease for failure injection")
	flag.Parse()
	token := os.Getenv("OB_PEER_TEST_ADMIN_TOKEN")
	if len(token) < 16 || *db == "" {
		fmt.Fprintln(os.Stderr, "fixture needs private DB and test admin token")
		os.Exit(2)
	}
	gate := newGate(nil, token)
	service, err := control.New(control.Config{DBPath: *db, AdminToken: token, RegistrationPolicy: "open", BrokerLease: *lease, SessionTTL: time.Minute, BeforeWebSocketRequest: gate.beforeWS, TURN: control.TURNConfig{Enabled: true, ListenAddr: *turnListen, PublicIP: "127.0.0.1", AllowLoopbackPeers: true}})
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
	server := &http.Server{Handler: gate, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16384}
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
