package remote

import (
	"fmt"
	"strings"
	"time"
)

func text(label, value string) error {
	if strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("remote: %s contains NUL", label)
	}
	return nil
}
func duration(label string, value time.Duration) error {
	if value < 0 || value > 300*time.Second {
		return fmt.Errorf("remote: %s must be between zero and 300 seconds", label)
	}
	return nil
}

func validateReconnectPolicy(policy ReconnectPolicy) error {
	if policy.MaxAttempts > 10000 {
		return fmt.Errorf("remote: reconnect attempts must not exceed 10000")
	}
	for _, field := range []struct {
		name         string
		value, limit time.Duration
	}{
		{"initial reconnect delay", policy.InitialDelay, 300 * time.Second},
		{"maximum reconnect delay", policy.MaxDelay, 300 * time.Second},
		{"transport timeout", policy.TransportTimeout, 300 * time.Second},
		{"reconnect budget", policy.RetryBudget, time.Hour},
		{"flow recovery grace", policy.FlowGrace, time.Hour},
		{"stable reset interval", policy.StableReset, time.Hour},
	} {
		if field.value < 0 || field.value > field.limit || field.value%time.Millisecond != 0 {
			return fmt.Errorf("remote: %s must be whole milliseconds between zero and %s", field.name, field.limit)
		}
	}
	if policy.TransportTimeout != 0 && policy.TransportTimeout < time.Second {
		return fmt.Errorf("remote: transport timeout must be at least one second")
	}
	initial, maximum := policy.InitialDelay, policy.MaxDelay
	if initial == 0 {
		initial = time.Second
	}
	if maximum == 0 {
		maximum = 15 * time.Second
	}
	if initial > maximum {
		return fmt.Errorf("remote: initial reconnect delay exceeds maximum delay")
	}
	return nil
}
