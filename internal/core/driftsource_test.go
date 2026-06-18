package core_test

import (
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/packet"
)

// TestDriftNotSampledFromData proves TSBPD clock-drift samples are no longer
// taken from data packets. A data packet's timestamp is the application's source
// time (subject to pacing/buffering jitter), so it is a poor drift signal; drift
// is sampled from ACKACK/keepalive timestamps instead. Here we feed well over a
// full drift epoch (driftMaxSamples = 1000) of in-order data packets whose
// arrival is deliberately skewed from their timestamps — if data still fed the
// estimator the drift offset would be large; it must stay 0.
func TestDriftNotSampledFromData(t *testing.T) {
	base := clock.Timestamp(10_000_000)
	const rcvISN = 5000
	c := core.NewEstablished(core.Config{
		PeerSocketID: 1, PayloadSize: 1200, SendISN: 100, RecvISN: rcvISN,
		MaxBW: 1 << 34, Live: true, TsbpdDelay: 120_000, BufferCapacity: 4096,
	}, base)
	drainOutputs(c)

	const n = 1200 // > driftMaxSamples
	for i := 0; i < n; i++ {
		ts := uint32(i * 20_000)                             // 20ms apart (source time)
		now := base.Add(clock.Microseconds(i*20_000 + i*50)) // +50us/pkt clock skew
		p := packet.NewData(nil, uint32(rcvISN+i), ts, 1, make([]byte, 100))
		c.HandlePacket(now, p)
		drainOutputs(c)
	}

	if d := c.Stats().DriftMicros; d != 0 {
		t.Fatalf("DriftMicros = %d, want 0 — data packets must not feed the drift estimator", d)
	}
}
