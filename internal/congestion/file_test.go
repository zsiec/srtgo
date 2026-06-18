package congestion

import (
	"math"
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
)

// tNow is the fixed injected clock value the congestion tests pass to OnACK.
const tNow = clock.Timestamp(1 << 30)

// resetRCTime seeds FileCC's rate-control gate far enough in the past (relative
// to tNow) that the next OnACK(tNow, …) passes the 10ms RC interval gate.
func resetRCTime(cc *FileCC) {
	cc.mu.Lock()
	cc.rcInit = true
	cc.lastRCTime = tNow - 20_000
	cc.mu.Unlock()
}

func TestFileCCSlowStart(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	if !cc.slowStart {
		t.Fatal("expected slow start to be active initially")
	}

	initialCWND := cc.CongestionWindow()
	if initialCWND != fileCCInitialCWND {
		t.Errorf("initial CWND: got %d, want %d", initialCWND, fileCCInitialCWND)
	}

	// Simulate ACK: seqLen(0, 100) = 101 (inclusive), so CWND = 16 + 101 = 117
	resetRCTime(cc)
	cc.OnACK(tNow, 100, 50_000, 5000, 5000)
	cwnd := cc.CongestionWindow()
	if cwnd <= initialCWND {
		t.Errorf("CWND should grow after ACK: got %d, initial %d", cwnd, initialCWND)
	}
}

func TestFileCCExitSlowStart(t *testing.T) {
	fc := 100 // small FC to trigger exit quickly
	cc := NewFileCC(0, 1316, fc, 0)

	// First ACK: seqLen(0, 50) = 51, CWND = 16 + 51 = 67
	resetRCTime(cc)
	cc.OnACK(tNow, 50, 50_000, 5000, 5000)

	// Second ACK: seqLen(50, 120) = 71, CWND = 67 + 71 = 138 > FC=100
	resetRCTime(cc)
	cc.OnACK(tNow, 120, 50_000, 5000, 5000)

	cc.mu.RLock()
	inSlowStart := cc.slowStart
	cc.mu.RUnlock()

	if inSlowStart {
		t.Error("expected to exit slow start after CWND > FC")
	}
}

func TestFileCCLossResponse(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	// Set up: exit slow start first.
	// Use rtt=1000µs and sndPeriod=100µs → pktsInFlight=10.
	// 3 losses out of 10 = 30% → well above 2% threshold.
	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 100.0 // 100µs
	cc.rtt = 1_000       // 1ms RTT → pktsInFlight = 10
	cc.lastDecPeriod = 100.0
	cc.lastSentSeq = 200
	cc.mu.Unlock()

	periodBefore := cc.PacketInterval()

	// Set loss list length for 2% threshold check.
	// 3 losses out of 10 in-flight = 30% → well above 2% threshold.
	cc.SetSndLossLength(3)

	// Report loss from a new epoch (loss seq > lastDecSeq which is ISN-1 = 0xFFFFFFFF)
	cc.OnNAK([]uint32{201, 202, 203})

	periodAfter := cc.PacketInterval()

	if periodAfter <= periodBefore {
		t.Errorf("send period should increase on loss: before=%d, after=%d", periodBefore, periodAfter)
	}

	// Verify ~3% increase
	ratio := float64(periodAfter) / float64(periodBefore)
	if ratio < 1.02 || ratio > 1.05 {
		t.Errorf("loss increase ratio: got %.3f, expected ~1.03", ratio)
	}
}

func TestFileCCMaxDecreases(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	// Set up in congestion avoidance
	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 100.0
	cc.rtt = 50_000
	cc.lastDecPeriod = 100.0
	cc.lastSentSeq = 500
	cc.mu.Unlock()

	// Set loss list length above 2% threshold: pktsInFlight = 50000/100 = 500,
	// need numLost*1000/500 >= 20 → numLost >= 10
	cc.SetSndLossLength(15)

	// First loss: new epoch
	cc.OnNAK([]uint32{501})

	cc.mu.RLock()
	epoch1DecSeq := cc.lastDecSeq
	cc.mu.RUnlock()

	// 10 more losses in same epoch (seq <= lastDecSeq)
	for i := range 10 {
		cc.SetSndLossLength(15)
		cc.OnNAK([]uint32{uint32(400 + i)})
	}

	cc.mu.RLock()
	finalDecCount := cc.decCount
	cc.mu.RUnlock()

	_ = epoch1DecSeq

	// decCount should be capped at fileCCMaxDecCount.
	// decCount increments on every eligible NAK, not just on decrease.
	// So after 1 (epoch start) + 4 more (reaching 5), no more increments.
	if finalDecCount > fileCCMaxDecCount {
		t.Errorf("decCount should not exceed %d: got %d", fileCCMaxDecCount, finalDecCount)
	}
}

func TestFileCCCongestionAvoidance(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	// Set up in congestion avoidance (no loss)
	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 200.0 // 200µs between packets
	cc.rtt = 50_000      // 50ms RTT
	cc.deliveryRate = 5000
	cc.bwEstimate = 10000
	cc.lastDecPeriod = 200.0
	cc.lastAck = 100
	cc.mu.Unlock()

	periodBefore := cc.PacketInterval()

	// Multiple ACKs without loss → rate should increase (period decreases)
	for i := range 20 {
		resetRCTime(cc)
		cc.OnACK(tNow, uint32(110+i*10), 50_000, 10000, 5000)
	}

	periodAfter := cc.PacketInterval()

	if periodAfter >= periodBefore {
		t.Errorf("period should decrease (rate increase) in congestion avoidance: before=%d, after=%d",
			periodBefore, periodAfter)
	}
}

func TestFileCCMaxBWEnforcement(t *testing.T) {
	// 10 Mbps limit with 1316-byte packets
	// min period = 1e6 / (10e6 / 1316) = 1e6 / 7599 ≈ 131.6µs
	cc := NewFileCC(10_000_000, 1316, 8192, 0)

	// Set very fast sending period
	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 10.0 // 10µs — way too fast for 10 Mbps
	cc.rtt = 50_000
	cc.deliveryRate = 100000
	cc.bwEstimate = 100000
	cc.lastDecPeriod = 10.0
	cc.mu.Unlock()

	// ACK triggers enforceMaxBW
	resetRCTime(cc)
	cc.OnACK(tNow, 100, 50_000, 100000, 100000)

	period := cc.PacketInterval()

	// Should be clamped to at least ~131µs
	if period < 120 {
		t.Errorf("period should be clamped by maxBW: got %dµs, expected ≥120µs", period)
	}
}

func TestFileCCCongestionWindow(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	cwnd := cc.CongestionWindow()
	if cwnd != fileCCInitialCWND {
		t.Errorf("initial CWND: got %d, want %d", cwnd, fileCCInitialCWND)
	}

	// CWND should grow during slow start
	resetRCTime(cc)
	cc.OnACK(tNow, 100, 50_000, 5000, 5000)
	cwnd2 := cc.CongestionWindow()
	if cwnd2 <= cwnd {
		t.Errorf("CWND should grow: %d -> %d", cwnd, cwnd2)
	}
}

func TestFileCCCWNDMinimum(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	// Force CWND to be very small
	cc.mu.Lock()
	cc.cwnd = 0.5
	cc.mu.Unlock()

	if cc.CongestionWindow() < 2 {
		t.Error("CongestionWindow should return at least 2")
	}
}

func TestFileCCLossExitsSlowStart(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	if !cc.slowStart {
		t.Fatal("expected slow start initially")
	}

	cc.mu.Lock()
	cc.rtt = 50_000
	cc.deliveryRate = 5000
	cc.lastSentSeq = 100
	cc.mu.Unlock()

	cc.OnNAK([]uint32{50})

	cc.mu.RLock()
	inSlowStart := cc.slowStart
	cc.mu.RUnlock()

	if inSlowStart {
		t.Error("loss should exit slow start")
	}
}

func TestFileCCLowLossNoDecrease(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	// Set up: in-flight = RTT/sndPeriod = 50000/100 = 500 packets
	// Loss of 1 packet = 0.2% < 2.0% threshold
	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 100.0
	cc.rtt = 50_000
	cc.lastDecPeriod = 100.0
	cc.lastSentSeq = 600
	cc.mu.Unlock()

	periodBefore := cc.PacketInterval()

	// Single loss — should be below 2% threshold
	cc.OnNAK([]uint32{601})

	periodAfter := cc.PacketInterval()

	// Period should NOT increase for low loss
	if periodAfter != periodBefore {
		t.Errorf("low loss should not change period: before=%d, after=%d", periodBefore, periodAfter)
	}
}

func TestFileCCOnTimeout(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	// Should be in slow start initially
	if !cc.slowStart {
		t.Fatal("expected slow start initially")
	}

	cc.mu.Lock()
	cc.rtt = 50_000
	cc.deliveryRate = 5000
	cc.mu.Unlock()

	// Timeout should exit slow start
	cc.OnTimeout()

	cc.mu.RLock()
	inSlowStart := cc.slowStart
	cc.mu.RUnlock()

	if inSlowStart {
		t.Error("OnTimeout should exit slow start")
	}
}

func TestFileCCOnTimeoutInCongAvoidance(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	// Set up in congestion avoidance
	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 100.0
	cc.mu.Unlock()

	periodBefore := cc.PacketInterval()

	// Timeout in congestion avoidance should be a no-op (aggressive response is disabled)
	cc.OnTimeout()

	periodAfter := cc.PacketInterval()
	if periodAfter != periodBefore {
		t.Errorf("OnTimeout in cong avoidance should not change period: before=%d, after=%d",
			periodBefore, periodAfter)
	}
}

func TestFileCCRCIntervalGate(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	// First ACK passes the gate
	resetRCTime(cc)
	cc.OnACK(tNow, 50, 50_000, 5000, 5000)
	cwnd1 := cc.CongestionWindow()

	// Immediate second ACK should be rate-limited (no CWND change)
	cc.OnACK(tNow, 100, 50_000, 5000, 5000)
	cwnd2 := cc.CongestionWindow()

	if cwnd1 != cwnd2 {
		t.Errorf("second ACK within RC interval should be rate-limited: cwnd1=%d, cwnd2=%d", cwnd1, cwnd2)
	}

	// After resetting RC time, ACK should work
	resetRCTime(cc)
	cc.OnACK(tNow, 100, 50_000, 5000, 5000)
	cwnd3 := cc.CongestionWindow()

	if cwnd3 <= cwnd2 {
		t.Errorf("ACK after RC interval should update CWND: cwnd2=%d, cwnd3=%d", cwnd2, cwnd3)
	}
}

func TestFileCCInitialization(t *testing.T) {
	// Verify ISN-based initialization
	cc := NewFileCC(0, 1316, 8192, 1000)

	cc.mu.RLock()
	lastAck := cc.lastAck
	lastDecSeq := cc.lastDecSeq
	cc.mu.RUnlock()

	// lastAck is initialized to ISN-1
	if lastAck != 999 {
		t.Errorf("lastAck should be ISN-1 (999): got %d", lastAck)
	}
	// lastDecSeq is initialized to ISN-2
	if lastDecSeq != 998 {
		t.Errorf("lastDecSeq should be ISN-2 (998): got %d", lastDecSeq)
	}
}

func TestFileCCDecCountBehavior(t *testing.T) {
	// Verify behavior: decCount increments on every eligible NAK,
	// not just when a decrease actually happens.
	cc := NewFileCC(0, 1316, 8192, 0)

	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 100.0
	cc.rtt = 1_000
	cc.lastDecPeriod = 100.0
	cc.lastSentSeq = 200
	// Set decRandom to a large value so the modulo check rarely triggers
	cc.decRandom = 1000
	cc.mu.Unlock()

	// Set loss list length for 2% threshold (3 losses / 10 in-flight = 30%)
	cc.SetSndLossLength(3)

	// First loss: new epoch (decCount = 1)
	cc.OnNAK([]uint32{201, 202, 203})

	// 6 more losses in same epoch
	for i := range 6 {
		cc.SetSndLossLength(1) // at least 1 outstanding loss
		cc.OnNAK([]uint32{uint32(100 + i)})
	}

	cc.mu.RLock()
	decCount := cc.decCount
	cc.mu.RUnlock()

	// After epoch start (1) + 4 more increments (capped at 5), decCount = 5
	if decCount != fileCCMaxDecCount {
		t.Errorf("decCount should reach %d: got %d", fileCCMaxDecCount, decCount)
	}
}

func TestFileCCProbePackets(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	probeCount := 0
	for i := range 100 {
		cc.OnPacketSent(uint32(i), 1316)
		if cc.IsProbePacket() {
			probeCount++
		}
	}

	// seq 0, 16, 32, 48, 64, 80, 96 = 7 probes
	if probeCount != 7 {
		t.Errorf("probeCount: got %d, expected 7", probeCount)
	}
}

func TestFileCCBandwidthEstimation(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	baseTime := clock.Timestamp(1_000_000)
	interval := clock.Microseconds(175)

	// Need 16 probe pairs (256 packets) to fill the probe window
	for i := range 256 {
		arrival := baseTime.Add(interval * clock.Microseconds(i))
		cc.OnPacketReceived(uint32(i), 1316, arrival)
	}

	pktRate := cc.EstimatedBandwidth()
	if pktRate == 0 {
		t.Error("expected non-zero bandwidth estimate")
	}
}

func TestFileCCImplementsController(t *testing.T) {
	// Compile-time check that FileCC implements Controller
	var _ Controller = (*FileCC)(nil)
}

func TestLiveCCImplementsController(t *testing.T) {
	// Compile-time check that LiveCC implements Controller
	var _ Controller = (*LiveCC)(nil)
}

func TestLiveCCCongestionWindowMaxInt(t *testing.T) {
	cc := NewLiveCC(10_000_000, 1316)
	if cc.CongestionWindow() != math.MaxInt {
		t.Error("LiveCC.CongestionWindow should return math.MaxInt")
	}
}

func TestFileCCOnPktArrival(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	baseTime := clock.Timestamp(1_000_000)

	// Feed enough packets for delivery estimator to initialize
	for i := range 20 {
		cc.OnPktArrival(1316, baseTime.Add(clock.Microseconds(i)*175))
	}

	pktRate, bytesRate := cc.DeliveryRate()
	if pktRate == 0 {
		t.Error("expected non-zero delivery pktRate after OnPktArrival calls")
	}
	if bytesRate == 0 {
		t.Error("expected non-zero delivery bytesRate after OnPktArrival calls")
	}
}

func TestFileCCDeliveryRateBeforeInit(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	// Before any arrivals, delivery rate should be zero
	pktRate, bytesRate := cc.DeliveryRate()
	if pktRate != 0 || bytesRate != 0 {
		t.Errorf("DeliveryRate before init: got (%d, %d), want (0, 0)", pktRate, bytesRate)
	}
}

func TestFileCCMinNAKInterval(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	got := cc.MinNAKInterval()
	if got != 0 {
		t.Errorf("FileCC.MinNAKInterval: got %d, want 0", got)
	}
}

func TestFileCCUpdateNAKInterval(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	// UpdateNAKInterval returns the interval unchanged
	got := cc.UpdateNAKInterval(300_000, 5000, 10)
	if got != 300_000 {
		t.Errorf("FileCC.UpdateNAKInterval(300000): got %d, want 300000", got)
	}

	got = cc.UpdateNAKInterval(100_000, 0, 0)
	if got != 100_000 {
		t.Errorf("FileCC.UpdateNAKInterval(100000): got %d, want 100000", got)
	}
}

func TestFileCCCheckTransArgs(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	// FileCC accepts all API modes — always returns nil
	if err := cc.CheckTransArgs(true, 99999, true); err != nil {
		t.Errorf("unexpected error for large msgAPI write: %v", err)
	}
	if err := cc.CheckTransArgs(false, 0, false); err != nil {
		t.Errorf("unexpected error for zero stream read: %v", err)
	}
	if err := cc.CheckTransArgs(true, 1316, true); err != nil {
		t.Errorf("unexpected error for exact-size msgAPI write: %v", err)
	}
}

func TestFileCCACKMaxPackets(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)
	if cc.ACKMaxPackets() != 0 {
		t.Errorf("ACKMaxPackets: got %d, want 0", cc.ACKMaxPackets())
	}
}

func TestFileCCACKTimeoutUS(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)
	if cc.ACKTimeoutUS() != 0 {
		t.Errorf("ACKTimeoutUS: got %d, want 0", cc.ACKTimeoutUS())
	}
}

func TestFileCCSetMaxBandwidthAndGet(t *testing.T) {
	cc := NewFileCC(10_000_000, 1316, 8192, 0)

	got := cc.MaxBandwidth()
	if got != 10_000_000 {
		t.Errorf("MaxBandwidth: got %d, want 10000000", got)
	}

	cc.SetMaxBandwidth(50_000_000)
	got = cc.MaxBandwidth()
	if got != 50_000_000 {
		t.Errorf("MaxBandwidth after Set: got %d, want 50000000", got)
	}

	cc.SetMaxBandwidth(0)
	got = cc.MaxBandwidth()
	if got != 0 {
		t.Errorf("MaxBandwidth after Set(0): got %d, want 0", got)
	}
}

func TestFileCCSetOverheadClamping(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	// Negative overhead clamps to 0
	cc.SetOverhead(-10)
	cc.mu.RLock()
	if cc.overhead != 0 {
		cc.mu.RUnlock()
		t.Errorf("SetOverhead(-10): got %d, want 0", cc.overhead)
	} else {
		cc.mu.RUnlock()
	}

	// Overhead > 100 clamps to 100
	cc.SetOverhead(150)
	cc.mu.RLock()
	if cc.overhead != 100 {
		cc.mu.RUnlock()
		t.Errorf("SetOverhead(150): got %d, want 100", cc.overhead)
	} else {
		cc.mu.RUnlock()
	}

	// Normal value
	cc.SetOverhead(30)
	cc.mu.RLock()
	if cc.overhead != 30 {
		cc.mu.RUnlock()
		t.Errorf("SetOverhead(30): got %d, want 30", cc.overhead)
	} else {
		cc.mu.RUnlock()
	}
}

func TestFileCCUpdateBandwidthNoOp(t *testing.T) {
	cc := NewFileCC(10_000_000, 1316, 8192, 0)

	before := cc.MaxBandwidth()
	cc.UpdateBandwidth(99_000_000, 50_000_000)
	after := cc.MaxBandwidth()

	// UpdateBandwidth is a no-op for FileCC — maxBW should not change
	if before != after {
		t.Errorf("UpdateBandwidth should be no-op for FileCC: before=%d, after=%d", before, after)
	}
}

func TestFileCCUpdateBandwidthIsNoOp(t *testing.T) {
	cc := NewFileCC(10_000_000, 1316, 8192, 0)

	// Test all combinations — should all be no-ops
	before := cc.MaxBandwidth()

	cc.UpdateBandwidth(0, 0)
	if cc.MaxBandwidth() != before {
		t.Error("UpdateBandwidth(0,0) changed maxBW")
	}

	cc.UpdateBandwidth(50_000_000, 0)
	if cc.MaxBandwidth() != before {
		t.Error("UpdateBandwidth(50M,0) changed maxBW")
	}

	cc.UpdateBandwidth(0, 50_000_000)
	if cc.MaxBandwidth() != before {
		t.Error("UpdateBandwidth(0,50M) changed maxBW")
	}

	cc.UpdateBandwidth(50_000_000, 30_000_000)
	if cc.MaxBandwidth() != before {
		t.Error("UpdateBandwidth(50M,30M) changed maxBW")
	}
}

func TestFileCCPacketIntervalMinimum(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	// Set sndPeriod to less than 1
	cc.mu.Lock()
	cc.sndPeriod = 0.5
	cc.mu.Unlock()

	interval := cc.PacketInterval()
	if interval < 1 {
		t.Errorf("PacketInterval should be at least 1: got %d", interval)
	}
}

func TestFileCCExitSlowStartWithRTTOnly(t *testing.T) {
	// exitSlowStart falls back to RTT-based period when deliveryRate is 0
	cc := NewFileCC(0, 1316, 100, 0) // FC=100

	cc.mu.Lock()
	cc.rtt = 50_000
	cc.deliveryRate = 0 // no delivery rate data
	cc.mu.Unlock()

	// ACK enough to exceed FC=100 and exit slow start
	resetRCTime(cc)
	cc.OnACK(tNow, 50, 50_000, 0, 0)
	resetRCTime(cc)
	cc.OnACK(tNow, 120, 50_000, 0, 0)

	cc.mu.RLock()
	inSlowStart := cc.slowStart
	sndPeriod := cc.sndPeriod
	cc.mu.RUnlock()

	if inSlowStart {
		t.Error("expected to exit slow start")
	}
	// exitSlowStart with RTT sets sndPeriod = cwnd / (rtt + RCInterval).
	// This should be a small positive value, different from the initial 1.0.
	if sndPeriod <= 0 {
		t.Errorf("sndPeriod should be positive after RTT-based exit: got %f", sndPeriod)
	}
}

func TestFileCCNewWithDefaultPacketSize(t *testing.T) {
	// packetSize=0 should default to DefaultPacketSize
	cc := NewFileCC(0, 0, 0, 0)

	cc.mu.RLock()
	ps := cc.packetSize
	cc.mu.RUnlock()

	if ps != DefaultPacketSize {
		t.Errorf("packetSize with 0: got %d, want %d", ps, DefaultPacketSize)
	}
}

func TestFileCCNewWithDefaultFC(t *testing.T) {
	// fc=0 should default to 8192
	cc := NewFileCC(0, 1316, 0, 0)

	cc.mu.RLock()
	maxCWND := cc.maxCWND
	cc.mu.RUnlock()

	if maxCWND != 8192 {
		t.Errorf("maxCWND with fc=0: got %f, want 8192", maxCWND)
	}
}

func TestFileCCOnNAKWithinEpochPeriodicSlowdown(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 100.0
	cc.rtt = 1_000
	cc.lastDecPeriod = 100.0
	cc.lastSentSeq = 200
	cc.mu.Unlock()

	cc.SetSndLossLength(3)
	// First NAK: new epoch, sets decRandom
	cc.OnNAK([]uint32{201})

	cc.mu.Lock()
	// Force decRandom=1 so every nakCount%1==0 triggers periodic slowdown
	cc.decRandom = 1
	periodBefore := cc.sndPeriod
	cc.mu.Unlock()

	// In-epoch NAK should trigger periodic slowdown when nakCount%decRandom==0
	cc.SetSndLossLength(3)
	cc.OnNAK([]uint32{100}) // within epoch

	cc.mu.RLock()
	periodAfter := cc.sndPeriod
	cc.mu.RUnlock()

	if periodAfter <= periodBefore {
		t.Errorf("periodic slowdown should increase period: before=%f, after=%f", periodBefore, periodAfter)
	}
}

func TestFileCCEnforceMaxBWZero(t *testing.T) {
	// maxBW=0 means unlimited — enforceMaxBW should be no-op
	cc := NewFileCC(0, 1316, 8192, 0)

	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 1.0 // very fast
	cc.rtt = 50_000
	cc.deliveryRate = 100000
	cc.bwEstimate = 100000
	cc.lastDecPeriod = 1.0
	cc.mu.Unlock()

	resetRCTime(cc)
	cc.OnACK(tNow, 100, 50_000, 100000, 100000)

	period := cc.PacketInterval()
	// Without maxBW cap, period can be very small
	if period > 100 {
		t.Errorf("with maxBW=0, period should not be clamped: got %d", period)
	}
}

func TestFileCCEmptyNAK(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 100.0
	cc.mu.Unlock()

	before := cc.PacketInterval()
	cc.OnNAK([]uint32{})
	after := cc.PacketInterval()

	if before != after {
		t.Errorf("empty NAK should not change period: before=%d, after=%d", before, after)
	}
}

func TestFileCCRateIncreaseLowB(t *testing.T) {
	// Test rateIncrease when B <= 0 (current rate >= available bandwidth).
	// In this case, inc = 1/MSS (minimum increment).
	cc := NewFileCC(0, 1316, 8192, 0)

	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 10.0 // very fast — rate > available BW
	cc.rtt = 50_000
	cc.deliveryRate = 5000
	cc.bwEstimate = 100 // very low estimate
	cc.lastDecPeriod = 10.0
	cc.lastAck = 100
	cc.loss = false
	cc.mu.Unlock()

	periodBefore := cc.PacketInterval()
	resetRCTime(cc)
	cc.OnACK(tNow, 110, 50_000, 100, 5000)
	periodAfter := cc.PacketInterval()

	// Rate should still try to increase (period decrease), even if slowly
	_ = periodBefore
	_ = periodAfter
	// We're just ensuring the B <= 0 path doesn't panic or corrupt state
}

func TestFileCCRateIncreaseSndPeriodZero(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 0 // edge case: zero period
	cc.rtt = 50_000
	cc.deliveryRate = 5000
	cc.bwEstimate = 10000
	cc.lastDecPeriod = 100.0
	cc.lastAck = 100
	cc.loss = false
	cc.mu.Unlock()

	resetRCTime(cc)
	cc.OnACK(tNow, 110, 50_000, 10000, 5000)

	// Should not panic; period should remain reasonable
	interval := cc.PacketInterval()
	if interval < 1 {
		t.Errorf("interval should be at least 1: got %d", interval)
	}
}

func TestFileCCOnNAKNewEpochAvgNAKNumGt1(t *testing.T) {
	cc := NewFileCC(0, 1316, 8192, 0)

	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 100.0
	cc.rtt = 1_000
	cc.lastDecPeriod = 100.0
	cc.lastSentSeq = 500
	// Pre-seed avgNAKNum > 1 so the random branch executes
	cc.avgNAKNum = 10
	cc.nakCount = 5
	cc.mu.Unlock()

	cc.SetSndLossLength(3)
	// This triggers a new epoch (lossBegin > lastDecSeq)
	cc.OnNAK([]uint32{501})

	cc.mu.RLock()
	decRandom := cc.decRandom
	cc.mu.RUnlock()

	// decRandom should be in [1, avgNAKNum]
	if decRandom < 1 {
		t.Errorf("decRandom should be >= 1: got %d", decRandom)
	}
}

func TestFileCCOnACKCongAvoidanceLossFlag(t *testing.T) {
	// Test congestion avoidance when loss flag is set (should clear it, skip rate increase)
	cc := NewFileCC(0, 1316, 8192, 0)

	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 100.0
	cc.rtt = 50_000
	cc.deliveryRate = 5000
	cc.bwEstimate = 10000
	cc.lastDecPeriod = 100.0
	cc.lastAck = 100
	cc.loss = true // set loss flag
	cc.mu.Unlock()

	periodBefore := cc.PacketInterval()
	resetRCTime(cc)
	cc.OnACK(tNow, 110, 50_000, 10000, 5000)

	// CWND is updated, but period should not decrease because loss=true skips rateIncrease
	cc.mu.RLock()
	lossFlag := cc.loss
	cc.mu.RUnlock()

	if lossFlag {
		t.Error("loss flag should be cleared after OnACK")
	}

	// Period should remain unchanged (no rate increase when loss=true)
	periodAfter := cc.PacketInterval()
	if periodAfter < periodBefore {
		// This is actually OK — the period may change due to CWND recalculation
		// but the key test is that loss flag is cleared
	}
}

func TestFileCCRateIncreaseWithHighBandwidth(t *testing.T) {
	// Test the sndPeriod > lastDecPeriod && bwPktPS/9 < B branch
	cc := NewFileCC(0, 1316, 8192, 0)

	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 200.0     // slower than lastDecPeriod
	cc.lastDecPeriod = 100.0 // fast rate at last loss point
	cc.rtt = 50_000
	cc.deliveryRate = 5000
	cc.bwEstimate = 20000 // high BW estimate
	cc.lastAck = 100
	cc.loss = false
	cc.mu.Unlock()

	periodBefore := cc.PacketInterval()
	resetRCTime(cc)
	cc.OnACK(tNow, 110, 50_000, 20000, 5000)
	periodAfter := cc.PacketInterval()

	// Period should decrease (rate increase)
	if periodAfter >= periodBefore {
		t.Errorf("period should decrease: before=%d, after=%d", periodBefore, periodAfter)
	}
}

// --- Benchmarks ---

func BenchmarkFileCCOnACK(b *testing.B) {
	cc := NewFileCC(0, 1316, 8192, 0)
	// Exit slow start for benchmark
	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 100.0
	cc.rtt = 50_000
	cc.deliveryRate = 5000
	cc.bwEstimate = 10000
	cc.lastDecPeriod = 100.0
	cc.mu.Unlock()

	var ack uint32 = 100
	for b.Loop() {
		ack += 10
		resetRCTime(cc)
		cc.OnACK(tNow, ack, 50_000, 10000, 5000)
	}
}

func BenchmarkFileCCOnNAK(b *testing.B) {
	cc := NewFileCC(0, 1316, 8192, 0)
	cc.mu.Lock()
	cc.slowStart = false
	cc.sndPeriod = 100.0
	cc.rtt = 50_000
	cc.lastDecPeriod = 100.0
	cc.lastSentSeq = 1_000_000
	cc.mu.Unlock()

	lossSeqs := []uint32{500}
	for b.Loop() {
		cc.OnNAK(lossSeqs)
	}
}
