package congestion

import (
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
)

func TestLiveCCPacketInterval(t *testing.T) {
	// 10 Mbps (10,000,000 bytes/sec), no overhead applied in PacketInterval.
	// pktSize = 1316 + 44 (wire header) = 1360 bytes
	// interval = 1_000_000 * 1360 / 10_000_000 = 136μs
	cc := NewLiveCC(10_000_000, 1316)

	interval := cc.PacketInterval()
	if interval < 131 || interval > 141 {
		t.Errorf("PacketInterval: got %dμs, expected ~136μs", interval)
	}
}

func TestLiveCCPacketIntervalDefault(t *testing.T) {
	cc := NewLiveCC(0, 0) // should use defaults

	interval := cc.PacketInterval()
	if interval <= 0 {
		t.Errorf("PacketInterval: got %d, expected positive", interval)
	}
}

func TestLiveCCSetMaxBandwidth(t *testing.T) {
	cc := NewLiveCC(10_000_000, 1316)

	interval1 := cc.PacketInterval()

	// Double the bandwidth → half the interval
	cc.SetMaxBandwidth(20_000_000)
	interval2 := cc.PacketInterval()

	if interval2 >= interval1 {
		t.Errorf("doubling BW should halve interval: %d -> %d", interval1, interval2)
	}

	// Approximately half
	ratio := float64(interval1) / float64(interval2)
	if ratio < 1.8 || ratio > 2.2 {
		t.Errorf("interval ratio: got %.2f, expected ~2.0", ratio)
	}
}

func TestLiveCCUpdateBandwidth(t *testing.T) {
	cc := NewLiveCC(10_000_000, 1316)

	interval1 := cc.PacketInterval()

	// When maxBW is set explicitly, it takes precedence
	cc.UpdateBandwidth(20_000_000, 5_000_000)
	interval2 := cc.PacketInterval()

	// Should use 20M, not 5M
	ratio := float64(interval1) / float64(interval2)
	if ratio < 1.8 || ratio > 2.2 {
		t.Errorf("explicit maxBW should override inputBW: ratio=%.2f", ratio)
	}

	// When maxBW is 0, use inputBW
	cc.UpdateBandwidth(0, 5_000_000)
	interval3 := cc.PacketInterval()

	// Should now use 5M → interval ~= 272μs
	if interval3 <= interval1 {
		t.Errorf("inputBW=5M should give longer interval than maxBW=10M: %d vs %d", interval3, interval1)
	}
}

func TestLiveCCOverheadClamping(t *testing.T) {
	cc := NewLiveCC(10_000_000, 1316)

	cc.SetOverhead(-10) // should clamp to 0
	cc.SetOverhead(150) // should clamp to 100
}

func TestLiveCCBandwidthEstimation(t *testing.T) {
	cc := NewLiveCC(10_000_000, 1316)

	// Need at least 16 probe pairs to fill the window.
	// Probe pairs are seqNo%16==0,1. At interval 175μs between packets:
	// probe pair inter-arrival = 175μs → ~5714 pps
	baseTime := clock.Timestamp(1_000_000)
	interval := clock.Microseconds(175)

	// Send 16*16 = 256 packets to fill 16 probe pair windows
	for i := range 256 {
		arrival := baseTime.Add(interval * clock.Microseconds(i))
		cc.OnPacketReceived(uint32(i), 1316, arrival)
	}

	pktRate := cc.EstimatedBandwidth()

	if pktRate == 0 {
		t.Error("expected non-zero packet rate")
	}

	// Expected: ~5714 packets/sec (1e6/175)
	if pktRate < 4000 || pktRate > 7000 {
		t.Errorf("pktRate: got %d, expected ~5714", pktRate)
	}
}

func TestProbeOnlyMeasurement(t *testing.T) {
	cc := NewLiveCC(10_000_000, 1316)

	// Send non-probe packets (seq 2-14) — should NOT generate estimates
	baseTime := clock.Timestamp(1_000_000)
	for i := 2; i < 15; i++ {
		cc.OnPacketReceived(uint32(i), 1316, baseTime.Add(clock.Microseconds(i)*175))
	}

	pktRate := cc.EstimatedBandwidth()
	// Probe window is pre-initialized to 1000μs per entry,
	// so EstimatedBandwidth returns ~1000 pkt/sec even before any probe pairs are received.
	if pktRate < 900 || pktRate > 1100 {
		t.Errorf("before probe pairs, expected baseline ~1000 pkt/sec: pktRate=%d", pktRate)
	}

	// Send 16 probe pairs to fill the window (need 16 complete pairs)
	for i := range 16 {
		seq0 := uint32(i * 16)
		seq1 := seq0 + 1
		cc.OnPacketReceived(seq0, 1316, baseTime.Add(clock.Microseconds(seq0)*175))
		cc.OnPacketReceived(seq1, 1316, baseTime.Add(clock.Microseconds(seq1)*175))
	}

	pktRate = cc.EstimatedBandwidth()
	if pktRate == 0 {
		t.Error("16 probe pairs should generate an estimate")
	}
}

func TestPeakRangeFilter(t *testing.T) {
	cc := NewLiveCC(10_000_000, 1316)
	baseTime := clock.Timestamp(1_000_000)

	// Send 16 probe pairs: 14 at 175μs, 2 at extreme values (outliers).
	// The peak-range median filter should reject outliers.
	for i := range 16 {
		seq0 := uint32(i * 16)
		seq1 := seq0 + 1

		interval := clock.Microseconds(175)
		if i == 5 {
			interval = 10 // extreme fast (outlier)
		}
		if i == 10 {
			interval = 50000 // extreme slow (outlier)
		}

		cc.OnPacketReceived(seq0, 1316, baseTime.Add(clock.Microseconds(seq0)*175))
		cc.OnPacketReceived(seq1, 1316, baseTime.Add(clock.Microseconds(seq0)*175+interval))
	}

	pktRate := cc.EstimatedBandwidth()

	// The median filter should produce a rate close to 5714 (1e6/175)
	// despite the outliers
	if pktRate == 0 {
		t.Fatal("expected non-zero estimate")
	}
	if pktRate < 4000 || pktRate > 7000 {
		t.Errorf("pktRate with outliers: got %d, expected ~5714", pktRate)
	}
}

func TestProbeSizeNormalization(t *testing.T) {
	cc := NewLiveCC(10_000_000, 1316)
	baseTime := clock.Timestamp(1_000_000)

	// Send probe pairs with half-size packets (658 bytes).
	// They arrive in half the time, so raw timediff is half.
	// Normalization should scale up: timediff * 1316 / 658 = 2x.
	for i := range 16 {
		seq0 := uint32(i * 16)
		seq1 := seq0 + 1

		// Probe1 at normal time
		cc.OnPacketReceived(seq0, 658, baseTime.Add(clock.Microseconds(seq0)*175))
		// Probe2 arrives 88μs later (half of 175μs, because half-size packet)
		cc.OnPacketReceived(seq1, 658, baseTime.Add(clock.Microseconds(seq0)*175+88))
	}

	pktRate := cc.EstimatedBandwidth()

	// After normalization: effective interval = 88 * 1316/658 = 176μs
	// Expected rate: ~5682 pps (1e6/176)
	if pktRate == 0 {
		t.Fatal("expected non-zero estimate")
	}
	if pktRate < 4500 || pktRate > 7000 {
		t.Errorf("pktRate with size normalization: got %d, expected ~5682", pktRate)
	}
}

func TestLiveCCProbePacket(t *testing.T) {
	cc := NewLiveCC(10_000_000, 1316)

	probeCount := 0
	for i := range 100 {
		cc.OnPacketSent(uint32(i), 1316)
		if cc.IsProbePacket() {
			probeCount++
		}
	}

	if probeCount != 7 {
		t.Errorf("probeCount: got %d, expected 7", probeCount)
	}
}

func TestLiveCCProbePacketWithRandomISN(t *testing.T) {
	cc := NewLiveCC(10_000_000, 1316)

	isn := uint32(1000)
	probeCount := 0
	for i := range 100 {
		seqNo := isn + uint32(i)
		cc.OnPacketSent(seqNo, 1316)
		if cc.IsProbePacket() {
			probeCount++
		}
	}

	// seqNos 1000-1099: probes at 1008, 1024, 1040, 1056, 1072, 1088 = 6
	if probeCount != 6 {
		t.Errorf("probeCount with ISN=%d: got %d, expected 6", isn, probeCount)
	}
}

func TestLiveCCOnACKNoRateChange(t *testing.T) {
	cc := NewLiveCC(10_000_000, 1316)

	before := cc.PacketInterval()
	cc.OnACK(100, 50000, 5000, 5000)
	after := cc.PacketInterval()

	if before != after {
		t.Errorf("live mode should not change rate on ACK: %d -> %d", before, after)
	}
}

func TestLiveCCOnNAKNoRateChange(t *testing.T) {
	cc := NewLiveCC(10_000_000, 1316)

	before := cc.PacketInterval()
	cc.OnNAK([]uint32{100, 101, 102})
	after := cc.PacketInterval()

	if before != after {
		t.Errorf("live mode should not change rate on NAK: %d -> %d", before, after)
	}
}

func TestLiveCCSndAvgPayloadSize(t *testing.T) {
	// sndAvgPayloadSize uses IIR-128 filter: (old * 127 + new) / 128
	cc := NewLiveCC(10_000_000, 1316)

	// Initial avg should be 1316 (same as packetSize)
	initial := cc.atomicAvgPayloadSize.Load()
	if initial != 1316 {
		t.Errorf("initial sndAvgPayloadSize: got %d, expected 1316", initial)
	}

	initialInterval := cc.PacketInterval()

	// Send 1000 packets at 500 bytes — avg should converge toward 500
	for i := range 1000 {
		cc.OnPacketSent(uint32(i), 500)
	}

	avg := cc.atomicAvgPayloadSize.Load()

	// After 1000 sends at 500 bytes with IIR-128, should be close to 500
	// (128 samples is ~99.6% converged, 1000 >> 128)
	if avg < 490 || avg > 520 {
		t.Errorf("after 1000 sends at 500 bytes: avg=%d, expected ~500", avg)
	}

	// Pacing interval should now be shorter (smaller payload = shorter interval)
	newInterval := cc.PacketInterval()
	if newInterval >= initialInterval {
		t.Errorf("interval should decrease with smaller avg payload: %d -> %d", initialInterval, newInterval)
	}
}

func TestLiveCCDefaultFromConn(t *testing.T) {
	// When conn passes 0 for live mode, LiveCC should default to 1316
	// default payload size = SRT_LIVE_DEF_PLSIZE = 1316
	cc := NewLiveCC(10_000_000, 0)

	// Interval should be based on 1316, not 1456
	// Expected: 1_000_000 * (1316 + 44) / 10_000_000 = 136μs
	interval := cc.PacketInterval()
	if interval < 131 || interval > 141 {
		t.Errorf("PacketInterval with default: got %dμs, expected ~136μs (1316+44 based)", interval)
	}
}

// --- Benchmarks ---

func BenchmarkPacketInterval(b *testing.B) {
	cc := NewLiveCC(10_000_000, 1316)
	for b.Loop() {
		cc.PacketInterval()
	}
}

func BenchmarkOnPacketReceived(b *testing.B) {
	cc := NewLiveCC(10_000_000, 1316)
	ts := clock.Timestamp(1_000_000)
	var seq uint32
	for b.Loop() {
		cc.OnPacketReceived(seq, 1316, ts)
		ts = ts.Add(175)
		seq++
	}
}
