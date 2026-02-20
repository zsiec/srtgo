//go:build js

package srt

import "runtime"

// pacingSleep yields the goroutine without sleeping. In Go WASM, time.Sleep
// maps to setTimeout which browsers clamp to a ~4ms minimum, making
// fine-grained per-packet pacing impossible — a 50-packet chunk would take
// 200ms of pure pacing delay. Instead, we yield via Gosched (allows other
// goroutines to run) and rely on the congestion window to control send rate.
func pacingSleep(_ int64) {
	runtime.Gosched()
}
