package cli

import (
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oheco/oheco-broker/sdk/go/remote"
	"github.com/spf13/cobra"
)

type reconnectHandle interface {
	Status() error
	GetConnectionInfo() (remote.ConnectionInfo, error)
	Reconnect() error
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

// The native manager owns every retry. The foreground command keeps the same
// handle and mapping alive while reconnecting or paused; SIGUSR1 only wakes it.
func monitorPeer(cmd *cobra.Command, handle reconnectHandle, kind string, stateEvents bool, requests <-chan os.Signal) error {
	last, err := handle.GetConnectionInfo()
	if err != nil {
		return err
	}
	if stateEvents {
		if err = printConnectionState(cmd, kind, last); err != nil {
			return err
		}
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-cmd.Context().Done():
			return nil
		case <-requests:
			if err = handle.Reconnect(); err != nil {
				return err
			}
			if stateEvents {
				if err = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"event": "reconnect_requested", "handle": kind, "accepted": true,
				}); err != nil {
					return err
				}
			}
		case <-ticker.C:
			info, e := handle.GetConnectionInfo()
			if e != nil {
				return e
			}
			if stateEvents && connectionInfoChanged(last, info) {
				if e = printConnectionState(cmd, kind, info); e != nil {
					return e
				}
			}
			last = info
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
		}
	}
}
