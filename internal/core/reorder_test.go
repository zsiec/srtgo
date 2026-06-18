package core_test

import (
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/packet"
)

// countNAKs drains the connection's outputs and returns how many NAK control
// packets it emitted (releasing owned packets).
func countNAKs(c *core.Conn) int {
	n := 0
	for {
		o, ok := c.PollOutput()
		if !ok {
			return n
		}
		if sp, ok := o.(core.SendPacket); ok {
			if sp.Packet.Header.IsControl && sp.Packet.Header.ControlType == packet.CtrlTypeNAK {
				n++
			}
			if sp.Owned {
				sp.Packet.Release()
			}
		}
	}
}

// feed delivers one in-order/at-seq data packet to the receiver.
func feed(c *core.Conn, base clock.Timestamp, seqNo uint32) {
	c.HandlePacket(base, packet.NewData(nil, seqNo, 0, 1, make([]byte, 64)))
}

func newReorderReceiver(t *testing.T, base clock.Timestamp, lossMaxTTL int) *core.Conn {
	t.Helper()
	c := core.NewEstablished(core.Config{
		PeerSocketID: 1, PayloadSize: 1200, SendISN: 100, RecvISN: 100,
		MaxBW: 1 << 34, Live: true, LossMaxTTL: lossMaxTTL, BufferCapacity: 4096,
	}, base)
	drainOutputs(c)
	return c
}

// TestReorderTolerance proves SRTO_LOSSMAXTTL: a sequence gap within the reorder
// window is not NAKed immediately, so a merely-reordered packet that arrives
// shortly after is not falsely reported lost; with tolerance 0 the same gap is
// NAKed at once; and a genuine loss is still reported once the frontier moves
// beyond the reorder window.
func TestReorderTolerance(t *testing.T) {
	base := clock.Timestamp(1_000_000)

	// (1) Reordering tolerated: 149 arrives right after 150; with tolerance it is
	// never NAKed.
	t.Run("tolerated", func(t *testing.T) {
		c := newReorderReceiver(t, base, 3)
		for s := uint32(100); s <= 148; s++ {
			feed(c, base, s)
		}
		feed(c, base, 150) // gap at 149 (within tolerance -> deferred)
		feed(c, base, 149) // the reordered packet arrives -> deferral cancelled
		for s := uint32(151); s <= 155; s++ {
			feed(c, base, s)
		}
		if n := countNAKs(c); n != 0 {
			t.Fatalf("reordered packet produced %d NAK(s), want 0 (tolerance should absorb it)", n)
		}
	})

	// (2) No tolerance: the same gap is NAKed immediately.
	t.Run("no-tolerance", func(t *testing.T) {
		c := newReorderReceiver(t, base, 0)
		for s := uint32(100); s <= 148; s++ {
			feed(c, base, s)
		}
		feed(c, base, 150) // gap at 149 -> immediate NAK
		if n := countNAKs(c); n == 0 {
			t.Fatal("with tolerance 0 a gap must be NAKed immediately, got 0 NAKs")
		}
	})

	// (3) Genuine loss: 149 never arrives; once the frontier passes 149+tolerance
	// it is reported.
	t.Run("genuine-loss", func(t *testing.T) {
		c := newReorderReceiver(t, base, 3)
		for s := uint32(100); s <= 148; s++ {
			feed(c, base, s)
		}
		feed(c, base, 150) // gap at 149 deferred
		feed(c, base, 151) // 149 is 2 behind frontier -> still deferred
		feed(c, base, 152) // 149 is 3 behind -> still within tolerance
		if n := countNAKs(c); n != 0 {
			t.Fatalf("loss within reorder window NAKed too early: %d NAK(s)", n)
		}
		feed(c, base, 153) // 149 now 4 behind (> tolerance) -> reported
		if n := countNAKs(c); n == 0 {
			t.Fatal("genuine loss past the reorder window was never NAKed")
		}
	})
}
