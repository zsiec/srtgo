package core

import "github.com/zsiec/srtgo/internal/packet"

// payloadClass is the capacity class for pooled single-packet delivery payloads.
// One delivered packet payload is always <= MaxPayloadSize.
const payloadClass = packet.MaxPayloadSize

// payloadPoolMaxRetained bounds process-wide retained receive payload storage.
// Each entry is payloadClass bytes, so this caps retention at about 6 MiB while
// still covering normal SRT read bursts without turning the pool into an
// unbounded RSS ratchet.
const payloadPoolMaxRetained = 4096

// payloadPool recycles the owned payload copies that emitData hands to the
// application as DataReceived events. A delivered slice crosses a goroutine
// boundary (the session loop allocates it; the application Read goroutine copies
// it out), so it is returned to the pool only at the reader's copy-out site —
// the single point at which it is provably dead. See emitData and the session
// ReadMsg copy-out sites; releasing earlier (while the delivery still sits in
// readC or the loop backlog) would recycle a buffer that is still queued unread
// and corrupt it.
var payloadPool = make(chan []byte, payloadPoolMaxRetained)

// getPayload returns a slice of length n backed by a pooled cap-payloadClass
// array, or a fresh allocation if n exceeds the class (e.g. a reassembled
// message). Callers overwrite all n bytes immediately, so recycled contents
// never leak.
func getPayload(n int) []byte {
	if n > payloadClass {
		return make([]byte, n)
	}
	select {
	case b := <-payloadPool:
		return b[:n]
	default:
	}
	return make([]byte, n, payloadClass)
}

// PutPayload returns a delivered payload slice to the pool. It accepts only
// exact class-sized buffers, so reassembled-message slices (emitMessage, which
// stays unpooled) and slices of other capacities are silently dropped rather than
// polluting the pool — making PutPayload safe to call unconditionally on any
// delivered payload. It MUST be called only after the reader has copied the
// bytes out.
func PutPayload(b []byte) {
	if cap(b) != payloadClass {
		return
	}
	b = b[:0]
	select {
	case payloadPool <- b:
	default:
	}
}
