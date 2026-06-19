package core

import (
	"sync"

	"github.com/zsiec/srtgo/internal/packet"
)

// payloadClass is the capacity class for pooled single-packet delivery payloads.
// One delivered packet payload is always <= MaxPayloadSize.
const payloadClass = packet.MaxPayloadSize

// payloadPool recycles the owned payload copies that emitData hands to the
// application as DataReceived events. A delivered slice crosses a goroutine
// boundary (the session loop allocates it; the application Read goroutine copies
// it out), so it is returned to the pool only at the reader's copy-out site —
// the single point at which it is provably dead. See emitData and the session
// ReadMsg copy-out sites; releasing earlier (while the delivery still sits in
// readC or the loop backlog) would recycle a buffer that is still queued unread
// and corrupt it.
var payloadPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, payloadClass)
		return &b
	},
}

// getPayload returns a slice of length n backed by a pooled cap-payloadClass
// array, or a fresh allocation if n exceeds the class (e.g. a reassembled
// message). Callers overwrite all n bytes immediately, so recycled contents
// never leak.
func getPayload(n int) []byte {
	if n > payloadClass {
		return make([]byte, n)
	}
	bp := payloadPool.Get().(*[]byte)
	return (*bp)[:n]
}

// PutPayload returns a delivered payload slice to the pool. It accepts only
// exact class-sized buffers, so reassembled-message slices (emitMessage, which
// stays unpooled) and any foreign slice are silently dropped rather than
// polluting the pool — making PutPayload safe to call unconditionally on any
// delivered payload. It MUST be called only after the reader has copied the
// bytes out.
func PutPayload(b []byte) {
	if cap(b) != payloadClass {
		return
	}
	b = b[:0]
	payloadPool.Put(&b)
}
