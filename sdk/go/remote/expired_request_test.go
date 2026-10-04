package remote

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Exercise the native coordinator's retained request credentials and typed
// expiry handling. The fixture commits the first request but loses its reply;
// no successful transport grant, PAKE exchange or target socket is fabricated.
func TestExpiredCommittedRequestRetriesFreshGeneration(t *testing.T) {
	type sessionRequest struct {
		Broker             string `json:"broker_id"`
		Relay              string `json:"relay_mode"`
		ExpectedGeneration uint64 `json:"expected_generation"`
		RequestID          string `json:"request_id"`
		SessionToken       string `json:"session_token"`
	}
	type receivedRequest struct {
		path string
		body sessionRequest
	}

	const brokerID = "12345678-1234-4234-8234-123456789abc"
	var mu sync.Mutex
	var requests []receivedRequest
	problems := make(chan string, 8)
	report := func(problem string) {
		select {
		case problems <- problem:
		default:
		}
	}
	start := make(chan struct{})
	thirdArrived := make(chan struct{}, 1)
	finishThird := make(chan struct{})
	var startOnce, finishOnce sync.Once
	releaseStart := func() { startOnce.Do(func() { close(start) }) }
	releaseThird := func() { finishOnce.Do(func() { close(finishThird) }) }

	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/v1/status" {
			_, _ = io.WriteString(w, `{"connection_recovery_version":1}`)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/connections/") && r.Method == http.MethodDelete {
			_, _ = io.WriteString(w, `{"deleted":true}`)
			return
		}
		if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/v1/connections/") || !strings.HasSuffix(r.URL.Path, "/session") {
			report("native coordinator used an unexpected control route")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"unexpected route"}`)
			return
		}
		var body sessionRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			report("native coordinator sent an invalid session request")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid request"}`)
			return
		}
		mu.Lock()
		// This retained record is the fixture's committed first generation.
		requests = append(requests, receivedRequest{r.URL.Path, body})
		attempt, committed := len(requests), requests[0]
		mu.Unlock()
		switch attempt {
		case 1:
			if body.Broker != brokerID || body.Relay != "never" || body.ExpectedGeneration != 0 || body.RequestID == "" || body.SessionToken == "" {
				report("initial managed request did not propose generation zero credentials")
			}
			// Ensure the caller installs its policy and persistent mapping before
			// this committed request encounters the simulated response loss.
			select {
			case <-start:
			case <-r.Context().Done():
				return
			}
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				report("fixture could not drop the committed response")
				return
			}
			_ = connection.Close()
		case 2:
			if r.URL.Path != committed.path || body != committed.body {
				report("ambiguous committed request was not replayed exactly")
			}
			w.WriteHeader(http.StatusGone)
			_, _ = io.WriteString(w, `{"error":"committed session expired","error_code":"session_expired","generation":1}`)
		case 3:
			if r.URL.Path != committed.path || body.Broker != committed.body.Broker || body.Relay != committed.body.Relay || body.ExpectedGeneration != 1 || body.RequestID == "" || body.RequestID == committed.body.RequestID || body.SessionToken == "" || body.SessionToken == committed.body.SessionToken {
				report("expired replay did not produce fresh credentials at generation one")
			}
			thirdArrived <- struct{}{}
			// Preserve an observable interval after HTTP 410 and before the
			// next response overwrites the last-error snapshot.
			select {
			case <-finishThird:
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"broker unavailable","error_code":"broker_offline","generation":1}`)
		default:
			report("native coordinator exceeded the three-attempt recovery limit")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":"unexpected extra attempt"}`)
		}
	}))
	defer service.Close()
	defer releaseStart()
	defer releaseThird()

	client, err := New(Options{URL: service.URL, Token: "fixture-account", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := client.ConnectAsync(brokerID, "fixture-peer", ConnectOptions{Relay: RelayNever, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err = peer.SetReconnectPolicy(ReconnectPolicy{MaxAttempts: 3, InitialDelay: 30 * time.Millisecond, MaxDelay: 30 * time.Millisecond, RetryBudget: 2 * time.Second}); err != nil {
		t.Fatal(err)
	}
	mapping, err := peer.Map(TCP, "127.0.0.1", 0, "127.0.0.1", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer mapping.Close()
	peerHandle, mapHandle := peer.ptr, mapping.ptr
	port := mapping.Port()
	if port == 0 {
		t.Fatal("pending mapping did not bind a local port")
	}
	checkListener := func() {
		t.Helper()
		connection, dialErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), time.Second)
		if dialErr != nil {
			t.Fatalf("retained mapping listener is unavailable: %v", dialErr)
		}
		_ = connection.Close()
	}
	checkProblem := func() {
		t.Helper()
		select {
		case problem := <-problems:
			t.Fatal(problem)
		default:
		}
	}
	checkListener()
	releaseStart()
	select {
	case <-thirdArrived:
	case problem := <-problems:
		t.Fatal(problem)
	case <-time.After(3 * time.Second):
		info, stateErr := peer.GetConnectionInfo()
		t.Fatalf("expired committed request never reached a fresh third POST: state=%s attempts=%d snapshot_error=%v", info.State, info.Attempts, stateErr)
	}
	checkProblem()
	info, err := peer.GetConnectionInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.State == StateFailed || info.Attempts != 3 || info.LastError == nil || info.LastError.HTTPStatus != http.StatusGone {
		t.Fatalf("typed session expiry was not retained as a recoverable HTTP 410: state=%s attempts=%d last_error=%v", info.State, info.Attempts, info.LastError)
	}
	if err = peer.Status(); err != nil {
		t.Fatalf("typed session expiry terminally failed the peer: %v", err)
	}
	releaseThird()
	deadline := time.Now().Add(3 * time.Second)
	for {
		checkProblem()
		info, err = peer.GetConnectionInfo()
		if err != nil {
			t.Fatal(err)
		}
		if info.State == StateFailed {
			t.Fatal("expired request recovery became terminal instead of pausing")
		}
		if info.State == StatePaused {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("three-attempt recovery did not pause: state=%s attempts=%d", info.State, info.Attempts)
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	count := len(requests)
	mu.Unlock()
	if count != 3 || info.Attempts != 3 {
		t.Fatalf("unexpected recovery attempt count: HTTP_POSTs=%d native_attempts=%d", count, info.Attempts)
	}
	if info.LastError == nil || info.LastError.HTTPStatus != http.StatusConflict {
		t.Fatal("paused peer did not retain the final broker-offline HTTP error")
	}
	if err = peer.Status(); err != nil {
		t.Fatalf("retry exhaustion terminally failed the peer: %v", err)
	}
	if peer.ptr != peerHandle || mapping.ptr != mapHandle || mapping.Port() != port {
		t.Fatal("expired request recovery replaced a retained handle or mapping port")
	}
	checkListener()
	checkProblem()
}
