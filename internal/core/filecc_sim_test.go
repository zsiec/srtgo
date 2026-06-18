package core_test

import (
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
)

// TestSimFileModeCongestion proves the connection uses the window-based AIMD
// controller (FileCC) in file mode, not the fixed-rate live pacer. FileCC starts
// in slow start with a small congestion window (16) and grows it as ACKs arrive;
// LiveCC imposes no congestion window (the flow window governs). So a file-mode
// connection reports a small initial congestion window that then grows over a
// lossy transfer that still completes in order.
func TestSimFileModeCongestion(t *testing.T) {
	const (
		sndISN      = 100
		rcvISN      = 5000
		numPayloads = 300
	)
	base := clock.Timestamp(1_000_000)

	sender := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: 2, PayloadSize: simPayload, SendISN: sndISN, RecvISN: rcvISN,
		MaxBW: 1 << 34, Congestion: "file",
	}, base))
	receiver := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: 1, PayloadSize: simPayload, SendISN: rcvISN, RecvISN: sndISN,
		MaxBW: 1 << 34, Congestion: "file",
	}, base))

	// Before any send, the congestion window is FileCC's slow-start initial value
	// (16) — proof the file-mode controller is FileCC, not LiveCC (LiveCC imposes
	// no congestion window, so window() would report the full flow window here).
	if cw := sender.c.Stats().CongestionWindow; cw != 16 {
		t.Fatalf("initial CongestionWindow = %d, want 16 (FileCC slow start) — wrong controller?", cw)
	}

	// A lossy transfer completes in order even while the window-based controller
	// gates the in-flight count (ARQ recovers the drops).
	drop := map[uint32]bool{150: true, 151: true, 207: true, 333: true}
	runStream(t, sender, receiver, base, numPayloads, drop)

	// FileCC's rate-control gate runs on the injected clock (OnACKAt), so slow
	// start advances deterministically under virtual time — the congestion window
	// must have grown well past its initial value over the transfer.
	if cw := sender.c.Stats().CongestionWindow; cw <= 16 {
		t.Fatalf("final CongestionWindow = %d, want > 16 (FileCC slow start should grow under virtual time)", cw)
	}
}
