// Package core holds the pure, Sans-I/O state machines for SRT.
//
// The types in this package are a deterministic function of their inputs. They
// never read a clock, open a socket, or spawn a goroutine. Time enters
// exclusively as explicit clock.Timestamp arguments on the entry points
// (HandlePacket, HandleTimer, Write, ...). Side effects leave exclusively
// through pulled queues:
//
//	PollOutput() -> SendPacket | SetTimer | ClearTimer   (wire/timer effects)
//	PollEvent()  -> Connected | DataReceived | Failed | Closed | KeyRefreshNeeded
//
// A host layer (internal/session) owns the UDP socket, the real clock, and the
// timer wheel; it feeds packets and timer fires into the core and executes the
// effects the core returns. This mirrors the sibling implementations
// (~/dev/srtrust crates/srt-protocol and ~/dev/ristgo internal/flow).
//
// Invariant: no file in this package (except _test.go) may directly import
// "net" or "time". Durations use clock.Microseconds; destination addresses are
// attached by the host. Enforced by gate_test.go and scripts/check-sansio.sh.
package core
