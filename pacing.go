//go:build !js

package srt

import (
	"runtime"
	"time"
)

const pacingSpinThresholdUS = 200 // below this (µs), use Gosched instead of time.Sleep

// pacingSleep waits for the given number of microseconds. For short waits
// (below pacingSpinThresholdUS), it yields the goroutine via runtime.Gosched()
// which takes ~5-20µs — much less than time.Sleep's ~50µs minimum on macOS.
// For longer waits, it uses time.Sleep which is more CPU-efficient.
func pacingSleep(us int64) {
	if us <= 0 {
		return
	}
	if us < pacingSpinThresholdUS {
		runtime.Gosched()
		return
	}
	time.Sleep(time.Duration(us) * time.Microsecond)
}
