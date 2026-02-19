package srt

import (
	"testing"
	"time"
)

// waitFor polls cond every 5ms until it returns true or timeout elapses.
// Calls t.Helper so the failure location points to the caller.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}
