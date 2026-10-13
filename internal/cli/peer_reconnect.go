package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oheco/oheco-broker/sdk/go/remote"
	"github.com/spf13/cobra"
)

const brokerPausedRetryInterval = 30 * time.Second

type reconnectHandle interface {
	Status() error
	GetConnectionInfo() (remote.ConnectionInfo, error)
	Reconnect() error
}

type peerMonitorOptions struct {
	kind                string
	stateEvents         bool
	pausedRetryInterval time.Duration // Zero preserves manual-only paused recovery.
}

func peerReconnectSignals() (<-chan os.Signal, func()) {
	requests := make(chan os.Signal, 1)
	signal.Notify(requests, syscall.SIGUSR1)
	return requests, func() { signal.Stop(requests) }
}

func connectionInfoChanged(previous, current remote.ConnectionInfo) bool {
	if previous.State != current.State || previous.Attempts != current.Attempts || previous.Generation != current.Generation {
		return true
	}
	if (previous.LastError == nil) != (current.LastError == nil) {
		return true
	}
	return previous.LastError != nil && *previous.LastError != *current.LastError
}

func printConnectionState(cmd *cobra.Command, kind string, info remote.ConnectionInfo) error {
	event := map[string]any{
		"event": "connection_state", "handle": kind, "state": info.State.String(),
		"attempts": info.Attempts, "generation": info.Generation,
		"next_retry_ms": info.NextRetry.Milliseconds(),
	}
	if info.LastError != nil {
		event["error_code"] = info.LastError.Code
		event["http_status"] = info.LastError.HTTPStatus
		event["reason"] = info.LastError.Message
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(event)
}

// The native manager owns each bounded retry round. A long-running serve command
// starts another round after a paused interval without replacing its SDK handle.
func monitorPeer(cmd *cobra.Command, handle reconnectHandle, options peerMonitorOptions, requests <-chan os.Signal) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	return monitorPeerTicks(cmd, handle, options, requests, ticker.C)
}

func monitorPeerTicks(cmd *cobra.Command, handle reconnectHandle, options peerMonitorOptions, requests <-chan os.Signal, ticks <-chan time.Time) error {
	last, err := handle.GetConnectionInfo()
	if err != nil {
		return err
	}
	if options.stateEvents {
		if err = printConnectionState(cmd, options.kind, last); err != nil {
			return err
		}
	}
	roundRequested := false
	requestReconnect := func(automatic bool) error {
		// Merge serve requests until a poll observes the native worker leave
		// paused. A signal racing the automatic deadline must not reset the
		// just-started round's retry budget a second time.
		if options.pausedRetryInterval == 0 || !roundRequested {
			if err := handle.Reconnect(); err != nil {
				return err
			}
			roundRequested = options.pausedRetryInterval > 0
		}
		if !options.stateEvents {
			return nil
		}
		event := map[string]any{"event": "reconnect_requested", "handle": options.kind, "accepted": true}
		if automatic {
			event["automatic"] = true
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(event)
	}
	var nextPausedRetry time.Time
	outageReported := false
	for {
		select {
		case <-cmd.Context().Done():
			return nil
		case <-requests:
			alreadyRequested := roundRequested
			if err = requestReconnect(false); err != nil {
				return err
			}
			// A new manual request supersedes the scheduled round. A merged
			// request keeps the existing deadline rather than postponing it.
			if !alreadyRequested {
				nextPausedRetry = time.Time{}
			}
		case now := <-ticks:
			info, e := handle.GetConnectionInfo()
			if e != nil {
				return e
			}
			if options.stateEvents && connectionInfoChanged(last, info) {
				if e = printConnectionState(cmd, options.kind, info); e != nil {
					return e
				}
			}
			switch info.State {
			case remote.StateFailed, remote.StateClosed:
				if e = handle.Status(); e != nil {
					return e
				}
				if info.LastError != nil {
					return info.LastError
				}
				return errors.New("peer connection ended")
			case remote.StateConnected:
				if e = handle.Status(); e != nil {
					return e
				}
			}
			if options.pausedRetryInterval > 0 && info.State == remote.StatePaused {
				if nextPausedRetry.IsZero() {
					nextPausedRetry = now.Add(options.pausedRetryInterval)
					if last.State != remote.StatePaused || !outageReported {
						if _, e = fmt.Fprintf(cmd.ErrOrStderr(), "Broker control connection lost; automatic retries exhausted. Retrying in %s.\n", options.pausedRetryInterval); e != nil {
							return e
						}
						outageReported = true
					}
				} else if !now.Before(nextPausedRetry) {
					roundRequested = false
					if e = requestReconnect(true); e != nil {
						return e
					}
					// Reconnect is asynchronous; do not issue another request on
					// every tick while the native worker still reports paused.
					nextPausedRetry = now.Add(options.pausedRetryInterval)
				}
			} else {
				nextPausedRetry = time.Time{}
				roundRequested = false
				if outageReported && info.State == remote.StateConnected {
					if _, e = fmt.Fprintln(cmd.ErrOrStderr(), "Broker control connection restored."); e != nil {
						return e
					}
					outageReported = false
				}
			}
			last = info
		}
	}
}
