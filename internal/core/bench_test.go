package core

import (
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/packet"
)

// BenchmarkCoreSendPath measures the per-packet cost of the Sans-I/O send path:
// build a data packet, buffer it for retransmission, and box the SendPacket
// effect onto the output queue. The reported allocs/op is the headline number
// for "does Sans-I/O cost us on the hot path?". The conn is rebuilt per batch
// so the send buffer never fills (no ACK feedback in this micro-driver).
func BenchmarkCoreSendPath(b *testing.B) {
	payload := make([]byte, 1316)
	const batch = 8000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; {
		b.StopTimer()
		now := clock.Timestamp(1_000_000)
		c := NewEstablished(Config{
			PeerSocketID:   2,
			PayloadSize:    1316,
			SendISN:        100,
			RecvISN:        5000,
			MaxBW:          1 << 40, // pacing interval ~0 so every Write sends now
			BufferCapacity: 16384,
			FlowWindow:     16384,
		}, now)
		drainCore(c)
		b.StartTimer()

		n := batch
		if rem := b.N - i; rem < n {
			n = rem
		}
		for j := 0; j < n; j++ {
			now = now.Add(2 * clock.Millisecond) // exceed pacing interval -> immediate send
			c.Write(now, payload)
			for {
				o, ok := c.PollOutput()
				if !ok {
					break
				}
				if sp, ok := o.(SendPacket); ok && sp.Owned {
					sp.Packet.Release()
				}
			}
		}
		i += n
	}
}

func drainCore(c *Conn) {
	for {
		if _, ok := c.PollOutput(); !ok {
			break
		}
	}
}

// The two benchmarks below isolate the one real cost the Sans-I/O boundary adds
// per outgoing packet: boxing an effect into the sealed Output interface
// (BenchmarkOutputBoxingInterface) versus a tagged-struct union with no boxing
// (BenchmarkOutputUnion). The delta is exactly the "de-interface the hot path"
// lever discussed in the migration plan.

type outUnion struct {
	kind     uint8
	pkt      packet.Packet
	id       TimerID
	deadline clock.Timestamp
}

func BenchmarkOutputBoxingInterface(b *testing.B) {
	q := make([]Output, 0, 4096)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if len(q) == cap(q) {
			q = q[:0]
		}
		q = append(q, SendPacket{Owned: i&1 == 0}) // vary to defeat hoisting
	}
	_ = q
}

func BenchmarkOutputUnion(b *testing.B) {
	q := make([]outUnion, 0, 4096)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if len(q) == cap(q) {
			q = q[:0]
		}
		q = append(q, outUnion{kind: uint8(i & 1)})
	}
	_ = q
}
