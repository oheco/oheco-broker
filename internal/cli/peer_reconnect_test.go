package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oheco/oheco-broker/sdk/go/remote"
	"github.com/spf13/cobra"
)

type monitorTestHandle struct {
	queries    chan chan remote.ConnectionInfo
	reconnects chan struct{}
	statusErr  error
}

func (h *monitorTestHandle) GetConnectionInfo() (remote.ConnectionInfo, error) {
	reply := make(chan remote.ConnectionInfo)
	h.queries <- reply
	return <-reply, nil
}
func (h *monitorTestHandle) Status() error { return h.statusErr }
func (h *monitorTestHandle) Reconnect() error {
	h.reconnects <- struct{}{}
	return nil
}

type monitorTest struct {
	handle   *monitorTestHandle
	ticks    chan time.Time
	requests chan os.Signal
	cancel   context.CancelFunc
	done     chan error
	stdout   bytes.Buffer
	stderr   bytes.Buffer
}

func startMonitorTest(t *testing.T, options peerMonitorOptions, statusErr error) *monitorTest {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	m := &monitorTest{
		handle: &monitorTestHandle{queries: make(chan chan remote.ConnectionInfo), reconnects: make(chan struct{}, 16), statusErr: statusErr},
		ticks:  make(chan time.Time), requests: make(chan os.Signal), cancel: cancel, done: make(chan error, 1),
	}
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	cmd.SetOut(&m.stdout)
	cmd.SetErr(&m.stderr)
	go func() { m.done <- monitorPeerTicks(cmd, m.handle, options, m.requests, m.ticks) }()
	m.reply(t, remote.ConnectionInfo{State: remote.StateConnected})
	t.Cleanup(cancel)
	return m
}
func (m *monitorTest) reply(t *testing.T, info remote.ConnectionInfo) {
	t.Helper()
	select {
	case reply := <-m.handle.queries:
		reply <- info
	case err := <-m.done:
		t.Fatalf("monitor ended before snapshot: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("monitor did not request a snapshot")
	}
}
func (m *monitorTest) tick(t *testing.T, seconds int, state remote.ConnectionState) {
	t.Helper()
	select {
	case m.ticks <- time.Unix(int64(seconds), 0):
	case err := <-m.done:
		t.Fatalf("monitor ended before tick: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("monitor did not consume tick")
	}
	m.reply(t, remote.ConnectionInfo{State: state})
}
func (m *monitorTest) reconnected(t *testing.T) {
	t.Helper()
	select {
	case <-m.handle.reconnects:
	case <-time.After(3 * time.Second):
		t.Fatal("expected a reconnect request")
	}
}
func (m *monitorTest) finish(t *testing.T) error {
	t.Helper()
	m.cancel()
	select {
	case err := <-m.done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("monitor did not stop promptly")
		return nil
	}
}

func TestBrokerPausedRecoveryRounds(t *testing.T) {
	for _, stateEvents := range []bool{false, true} {
		name := "default-output"
		if stateEvents {
			name = "json-events"
		}
		t.Run(name, func(t *testing.T) {
			m := startMonitorTest(t, peerMonitorOptions{kind: "broker", stateEvents: stateEvents, pausedRetryInterval: brokerPausedRetryInterval}, nil)
			m.tick(t, 0, remote.StatePaused)
			m.tick(t, 29, remote.StatePaused)
			m.tick(t, 30, remote.StatePaused)
			m.reconnected(t)
			// Asynchronous acceptance can leave a stale paused snapshot. It must
			// not produce another request on the following poll.
			m.tick(t, 31, remote.StatePaused)
			m.tick(t, 40, remote.StateRetryWait)
			m.tick(t, 100, remote.StatePaused)
			m.tick(t, 129, remote.StatePaused)
			m.tick(t, 130, remote.StatePaused)
			m.reconnected(t)
			m.tick(t, 131, remote.StateConnected)
			if err := m.finish(t); err != nil {
				t.Fatal(err)
			}
			if len(m.handle.reconnects) != 0 {
				t.Fatal("duplicate or early reconnect request")
			}
			if strings.Count(m.stderr.String(), "automatic retries exhausted") != 2 || strings.Count(m.stderr.String(), "connection restored") != 1 {
				t.Fatalf("missing or repeated transition notice: %q", m.stderr.String())
			}
			if !stateEvents {
				if m.stdout.Len() != 0 {
					t.Fatalf("default monitor changed stdout: %q", m.stdout.String())
				}
				return
			}
			decoder := json.NewDecoder(&m.stdout)
			requests := 0
			for decoder.More() {
				var event map[string]any
				if err := decoder.Decode(&event); err != nil {
					t.Fatal(err)
				}
				if event["event"] == "reconnect_requested" {
					requests++
					if event["automatic"] != true || event["accepted"] != true {
						t.Fatalf("invalid automatic event: %v", event)
					}
				}
			}
			if requests != 2 {
				t.Fatalf("got %d automatic events", requests)
			}
		})
	}
}

func TestManualRecoverySupersedesBrokerTimer(t *testing.T) {
	m := startMonitorTest(t, peerMonitorOptions{kind: "broker", pausedRetryInterval: brokerPausedRetryInterval}, nil)
	m.tick(t, 0, remote.StatePaused)
	m.tick(t, 20, remote.StatePaused)
	m.requests <- syscall.SIGUSR1
	m.reconnected(t)
	// The original deadline was 30; the manual request has superseded it.
	m.tick(t, 30, remote.StatePaused)
	m.tick(t, 31, remote.StateReconnecting)
	m.tick(t, 32, remote.StateConnected)
	if err := m.finish(t); err != nil {
		t.Fatal(err)
	}
	if len(m.handle.reconnects) != 0 || strings.Count(m.stderr.String(), "automatic retries exhausted") != 1 {
		t.Fatal("manual request caused a duplicate retry or notice")
	}
}

func TestManualRecoveryMergesWithAcceptedAutomaticRound(t *testing.T) {
	m := startMonitorTest(t, peerMonitorOptions{kind: "broker", pausedRetryInterval: brokerPausedRetryInterval}, nil)
	m.tick(t, 0, remote.StatePaused)
	m.tick(t, 30, remote.StatePaused)
	m.reconnected(t)
	// Exercise the opposite select order: the automatic round was accepted
	// first, then a signal arrived before polling observed the new round.
	m.requests <- syscall.SIGUSR1
	m.tick(t, 31, remote.StatePaused)
	m.tick(t, 32, remote.StateRetryWait)
	m.tick(t, 33, remote.StateConnected)
	if err := m.finish(t); err != nil {
		t.Fatal(err)
	}
	if len(m.handle.reconnects) != 0 {
		t.Fatal("signal reset an already accepted automatic round")
	}
}

func TestBrokerCancellationWhilePaused(t *testing.T) {
	m := startMonitorTest(t, peerMonitorOptions{kind: "broker", pausedRetryInterval: brokerPausedRetryInterval}, nil)
	m.tick(t, 0, remote.StatePaused)
	if err := m.finish(t); err != nil {
		t.Fatal(err)
	}
	if len(m.handle.reconnects) != 0 {
		t.Fatal("cancellation started a scheduled recovery round")
	}
}

func TestConnectPausedRecoveryRemainsManual(t *testing.T) {
	m := startMonitorTest(t, peerMonitorOptions{kind: "peer"}, nil)
	m.tick(t, 0, remote.StatePaused)
	m.tick(t, 3600, remote.StatePaused)
	m.requests <- syscall.SIGUSR1
	m.reconnected(t)
	m.tick(t, 3601, remote.StateConnected)
	if err := m.finish(t); err != nil {
		t.Fatal(err)
	}
	if len(m.handle.reconnects) != 0 || m.stderr.Len() != 0 || m.stdout.Len() != 0 {
		t.Fatal("connect acquired automatic recovery or unsolicited output")
	}
}

func TestBrokerTerminalFailureStopsScheduledRecovery(t *testing.T) {
	for _, state := range []remote.ConnectionState{remote.StateFailed, remote.StateClosed} {
		t.Run(state.String(), func(t *testing.T) {
			terminal := &remote.Error{HTTPStatus: 401, Message: "device authorization revoked"}
			m := startMonitorTest(t, peerMonitorOptions{kind: "broker", pausedRetryInterval: brokerPausedRetryInterval}, terminal)
			m.tick(t, 0, remote.StatePaused)
			m.tick(t, 30, state)
			if err := m.finish(t); !errors.Is(err, terminal) {
				t.Fatalf("lost terminal error: %v", err)
			}
			if len(m.handle.reconnects) != 0 {
				t.Fatal("terminal authorization failure requested another round")
			}
		})
	}
}
