package remote

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReconnectPolicyValidation(t *testing.T) {
	for _, policy := range []ReconnectPolicy{
		{}, {Disabled: true},
		{MaxAttempts: 10000, InitialDelay: time.Second, MaxDelay: 5 * time.Minute,
			TransportTimeout: time.Second, RetryBudget: time.Hour, FlowGrace: time.Hour, StableReset: time.Hour},
	} {
		if _, err := nativeReconnectPolicy(policy); err != nil {
			t.Fatalf("rejected supported policy %+v: %v", policy, err)
		}
	}
	for _, policy := range []ReconnectPolicy{
		{MaxAttempts: 10001}, {InitialDelay: -time.Millisecond},
		{InitialDelay: time.Microsecond}, {InitialDelay: 16 * time.Second},
		{MaxDelay: 500 * time.Millisecond}, {MaxDelay: 301 * time.Second},
		{TransportTimeout: 999 * time.Millisecond}, {TransportTimeout: 301 * time.Second},
		{RetryBudget: time.Hour + time.Millisecond}, {FlowGrace: -time.Millisecond},
		{StableReset: time.Hour + time.Millisecond},
	} {
		if _, err := nativeReconnectPolicy(policy); err == nil {
			t.Fatalf("accepted unsupported policy %+v", policy)
		}
	}
}

func TestClosedRecoveryHandles(t *testing.T) {
	peer, server := &Peer{}, &Server{}
	for label, handle := range map[string]interface {
		SetReconnectPolicy(ReconnectPolicy) error
		GetConnectionInfo() (ConnectionInfo, error)
		Reconnect() error
	}{"peer": peer, "server": server} {
		if err := handle.SetReconnectPolicy(ReconnectPolicy{}); err == nil {
			t.Fatalf("%s: updated a closed handle", label)
		}
		if err := handle.Reconnect(); err == nil {
			t.Fatalf("%s: requested recovery on a closed handle", label)
		}
		if info, err := handle.GetConnectionInfo(); err == nil || info.State != StateClosed {
			t.Fatalf("%s: unexpected closed snapshot %+v, %v", label, info, err)
		}
	}
}

// Exercise actual C background setup against a temporary unavailable HTTP
// service. The handle, listener and client reference must survive PAUSED and a
// manual retry; no successful grant or target connection is faked here.
func TestAsyncRecoveryPreservesHandleAndListener(t *testing.T) {
	var requests atomic.Uint64
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"fixture unavailable"}`))
	}))
	defer service.Close()
	client, err := New(Options{URL: service.URL, Token: "fixture-account", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := client.ConnectAsync("12345678-1234-4234-8234-123456789abc", "fixture-peer", ConnectOptions{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err = peer.SetReconnectPolicy(ReconnectPolicy{Disabled: true}); err != nil {
		t.Fatal(err)
	}
	mapping, err := peer.Map(TCP, "127.0.0.1", 0, "127.0.0.1", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer mapping.Close()
	port := mapping.Port()
	if port == 0 {
		t.Fatal("pending mapping did not bind a local port")
	}
	checkListener := func() {
		t.Helper()
		connection, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), time.Second)
		if e != nil {
			t.Fatalf("persistent listener is unavailable: %v", e)
		}
		connection.Close()
	}
	checkListener()
	if err = client.Close(); err == nil {
		t.Fatal("client destruction ignored live asynchronous peer reference")
	}
	wait := func(stage string, ready func() bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for !ready() {
			if time.Now().After(deadline) {
				t.Fatalf("asynchronous recovery did not complete %s", stage)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	var initialGeneration uint64
	wait("PAUSED snapshot", func() bool {
		info, e := peer.GetConnectionInfo()
		if e != nil {
			t.Fatal(e)
		}
		if info.State != StatePaused {
			return false
		}
		if info.NextRetry != 0 {
			t.Fatalf("paused peer advertised an automatic retry: %+v", info)
		}
		initialGeneration = info.Generation
		return true
	})
	if err = peer.Status(); err != nil {
		t.Fatalf("paused peer became terminal: %v", err)
	}
	before := requests.Load()
	if err = peer.Reconnect(); err != nil {
		t.Fatal(err)
	}
	wait("manual HTTP attempt with automatic retries disabled", func() bool { return requests.Load() > before })
	wait("manual PAUSED snapshot", func() bool {
		info, e := peer.GetConnectionInfo()
		if e != nil {
			t.Fatal(e)
		}
		if info.State != StatePaused || info.Generation <= initialGeneration {
			return false
		}
		if info.NextRetry != 0 {
			t.Fatalf("disabled manual attempt advertised an automatic retry: %+v", info)
		}
		return true
	})
	if err = peer.SetReconnectPolicy(ReconnectPolicy{MaxAttempts: 2, InitialDelay: time.Second, MaxDelay: time.Second}); err != nil {
		t.Fatal(err)
	}
	if err = peer.Reconnect(); err != nil {
		t.Fatal(err)
	}
	wait("automatic RETRY_WAIT snapshot", func() bool {
		info, e := peer.GetConnectionInfo()
		if e != nil {
			t.Fatal(e)
		}
		if info.State != StateRetryWait {
			return false
		}
		if info.NextRetry <= 0 || info.NextRetry > time.Second {
			t.Fatalf("waiting peer did not advertise its bounded retry: %+v", info)
		}
		return true
	})
	if mapping.Port() != port {
		t.Fatal("manual retry replaced local listening port")
	}
	checkListener()
	var callers sync.WaitGroup
	for range 4 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			for range 8 {
				_, _ = peer.GetConnectionInfo()
				_ = peer.SetReconnectPolicy(ReconnectPolicy{Disabled: true})
				_ = peer.Reconnect()
			}
		}()
	}
	peer.Close()
	callers.Wait()
	mapping.Close()
	if err = client.Close(); err != nil {
		t.Fatalf("peer close leaked its client reference: %v", err)
	}
}
