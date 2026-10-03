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
