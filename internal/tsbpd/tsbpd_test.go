package tsbpd

import (
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
)

func TestDeliveryTimeBasic(t *testing.T) {
	delay := 120 * clock.Millisecond       // 120ms latency
	timeBase := clock.Timestamp(1_000_000) // t=1.0s

	timer := New(delay, timeBase)

	// Packet with timestamp 500000 (0.5s)
	delivery := timer.DeliveryTime(500_000)

	// Expected: timeBase(1.0s) + pktTS(0.5s) + delay(0.12s) = 1.62s
	expected := clock.Timestamp(1_620_000)
	if delivery != expected {
		t.Errorf("DeliveryTime: got %d, want %d", delivery, expected)
	}
}

func TestIsReady(t *testing.T) {
	delay := 100 * clock.Millisecond
	timeBase := clock.Timestamp(0)

	timer := New(delay, timeBase)
	pktTS := uint32(1_000_000) // 1.0s

	// Delivery time = 0 + 1.0s + 0.1s = 1.1s
	if timer.IsReady(pktTS, clock.Timestamp(1_000_000)) {
		t.Error("should not be ready before delay")
	}

	if !timer.IsReady(pktTS, clock.Timestamp(1_100_001)) {
		t.Error("should be ready after delay")
	}

	if !timer.IsReady(pktTS, clock.Timestamp(1_200_000)) {
		t.Error("should be ready well after delay")
	}
}

func TestTimestampWrap(t *testing.T) {
	delay := 100 * clock.Millisecond
	timeBase := clock.Timestamp(0)

	timer := New(delay, timeBase)

	// Simulate timestamps approaching wrap: enter wrap period
	preWrapTS := uint32(0xFFFFFFF0)
	timer.UpdateWrap(preWrapTS)

	// Now a small timestamp (post-wrap) — still in wrap period, gets per-packet carryover
	postWrapTS := uint32(100)
	timer.UpdateWrap(postWrapTS)

	// Delivery time for pre-wrap: timeBase + 0xFFFFFFF0 + delay (no carryover: ts > 60s)
	deliveryPre := timer.DeliveryTime(preWrapTS)

	// Delivery time for post-wrap: timeBase + wrapOffset(0) + timestampWrap + 100 + delay
	// (wrapPeriod is true, ts <= 60s → per-packet carryover)
	deliveryPost := timer.DeliveryTime(postWrapTS)

	if deliveryPost <= deliveryPre {
		t.Errorf("delivery should increase across wrap: pre=%d, post=%d", deliveryPre, deliveryPost)
	}

	// The difference should be approximately 0xFFFFFFFF - 0xFFFFFFF0 + 100 + 1 = 116μs
	diff := deliveryPost.Sub(deliveryPre)
	expectedDiff := clock.Microseconds(0xFFFFFFFF - preWrapTS + postWrapTS + 1)
	if diff < expectedDiff-10 || diff > expectedDiff+10 {
		t.Errorf("delivery diff: got %dμs, expected ~%dμs", diff, expectedDiff)
	}
}

func TestNoSpuriousWrap(t *testing.T) {
	delay := 100 * clock.Millisecond
	timeBase := clock.Timestamp(0)

	timer := New(delay, timeBase)

	// Normal sequential timestamps should not trigger wrap period
	timer.UpdateWrap(1000)
	timer.UpdateWrap(2000)
	timer.UpdateWrap(3000)

	delivery := timer.DeliveryTime(3000)
	expected := clock.Timestamp(3000 + int64(delay))
	if delivery != expected {
		t.Errorf("DeliveryTime: got %d, want %d (no spurious wrap)", delivery, expected)
	}
}

func TestWrapStateMachineExitCondition(t *testing.T) {
	delay := 100 * clock.Millisecond
	timer := New(delay, clock.Timestamp(0))

	// Enter wrap period (ts > MAX - 30s)
	timer.UpdateWrap(0xFFFFFFF0)

	// Small timestamps during wrap get carryover
	timer.UpdateWrap(100)
	d1 := timer.DeliveryTime(100)

	// Exit wrap period (ts in [30s, 60s])
	timer.UpdateWrap(35_000_000) // 35 seconds

	// After exit, wrapOffset has been permanently advanced by 2^32.
	// Timestamps no longer get per-packet carryover.
	d2 := timer.DeliveryTime(35_000_000)

	// d2 should be well after d1 (35s vs 0.1ms + carryover)
	if d2 <= d1 {
		t.Errorf("post-exit delivery should be after in-wrap delivery: d1=%d, d2=%d", d1, d2)
	}

	// The wrapOffset should now be 2^32
	expected := clock.Timestamp(int64(1<<32) + 35_000_000 + int64(delay))
	if d2 != expected {
		t.Errorf("post-exit delivery: got %d, want %d", d2, expected)
	}
}

func TestDriftCorrection(t *testing.T) {
	delay := 100 * clock.Millisecond
	timeBase := clock.Timestamp(0)

	timer := New(delay, timeBase)

	// Simulate drift: packets arrive 50μs later than expected.
	// Need 1000 samples to trigger drift correction (driftMaxSamples=1000).
	for i := range driftMaxSamples {
		pktTS := uint32(i * 10000) // every 10ms
		localRecv := clock.Timestamp(int64(i*10000) + 50)
		timer.OnACK(pktTS, localRecv, 100000) // 100ms RTT (constant, so delta=0)
	}

	drift := timer.DriftOffset()
	if drift != 50 {
		t.Errorf("DriftOffset: got %d, want 50", drift)
	}

	// Delivery time should include drift
	delivery := timer.DeliveryTime(1_000_000)
	expected := clock.Timestamp(1_000_000 + int64(delay) + 50)
	if delivery != expected {
		t.Errorf("DeliveryTime with drift: got %d, want %d", delivery, expected)
	}
}

func TestDriftCorrectionAverage(t *testing.T) {
	delay := 100 * clock.Millisecond
	timer := New(delay, clock.Timestamp(0))

	// 1000 samples: 950 with drift=100, 50 with drift=200
	// Average: (950*100 + 50*200) / 1000 = 105
	for i := range driftMaxSamples {
		pktTS := uint32(i * 10000)
		d := int64(100)
		if i%20 == 0 {
			d = 200
		}
		localRecv := clock.Timestamp(int64(i*10000) + d)
		timer.OnACK(pktTS, localRecv, -1) // no RTT
	}

	drift := timer.DriftOffset()
	if drift != 105 {
		t.Errorf("DriftOffset: got %d, want 105", drift)
	}
}

func TestDriftRTTDeltaCompensation(t *testing.T) {
	delay := 100 * clock.Millisecond
	timer := New(delay, clock.Timestamp(0))

	// First sample: RTT=100ms (sets firstRTT, rttDelta=0, raw drift=50).
	// All subsequent: RTT=200ms, rttDelta=(200000-100000)/2=50000.
	// Packets arrive 50050μs late (raw drift).
	// For i=0: compensated drift = 50 (no delta, raw=50).
	// For i>0: compensated drift = 50050 - 50000 = 50.
	// Average over 1000 samples = 50.
	for i := range driftMaxSamples {
		pktTS := uint32(i * 10000)
		rtt := int64(200000) // 200ms
		rawDrift := int64(50050)
		if i == 0 {
			rtt = 100000  // 100ms for first sample (sets firstRTT)
			rawDrift = 50 // first sample: no RTT delta, so use plain drift
		}
		localRecv := clock.Timestamp(int64(i*10000) + rawDrift)
		timer.OnACK(pktTS, localRecv, rtt)
	}

	drift := timer.DriftOffset()
	if drift != 50 {
		t.Errorf("DriftOffset with RTT delta: got %d, want 50", drift)
	}
}

func TestDriftOverdrift(t *testing.T) {
	delay := 100 * clock.Millisecond
	timer := New(delay, clock.Timestamp(0))

	// Large drift: 10ms per sample. After 1000 samples, avg=10000μs.
	// Overdrift: absorb 5000μs into timeBase, residual = 5000μs.
	for i := range driftMaxSamples {
		pktTS := uint32(i * 10000)
		localRecv := clock.Timestamp(int64(i*10000) + 10000)
		timer.OnACK(pktTS, localRecv, -1)
	}

	drift := timer.DriftOffset()
	if drift != 5000 {
		t.Errorf("DriftOffset after overdrift: got %d, want 5000", drift)
	}

	// The timeBase should have been adjusted by 5ms
	timer.mu.Lock()
	tb := timer.timeBase
	timer.mu.Unlock()
	if tb != clock.Timestamp(5000) {
		t.Errorf("timeBase after overdrift: got %d, want 5000", tb)
	}
}

func TestSetTimeBase(t *testing.T) {
	timer := New(100*clock.Millisecond, clock.Timestamp(0))

	timer.SetTimeBase(clock.Timestamp(5_000_000))

	delivery := timer.DeliveryTime(1000)
	expected := clock.Timestamp(5_000_000 + 1000 + 100_000)
	if delivery != expected {
		t.Errorf("DeliveryTime: got %d, want %d", delivery, expected)
	}
}

func TestSetDelay(t *testing.T) {
	timer := New(100*clock.Millisecond, clock.Timestamp(0))

	timer.SetDelay(200 * clock.Millisecond)

	delivery := timer.DeliveryTime(0)
	expected := clock.Timestamp(200_000) // 200ms delay
	if delivery != expected {
		t.Errorf("DeliveryTime: got %d, want %d", delivery, expected)
	}
}

// --- Benchmarks ---

func BenchmarkDeliveryTime(b *testing.B) {
	timer := New(120*clock.Millisecond, clock.Timestamp(1_000_000))
	for b.Loop() {
		timer.DeliveryTime(500_000)
	}
}

// ---- DriftTracer toggle tests ----

func TestDriftTracerDisabled(t *testing.T) {
	delay := 100 * clock.Millisecond
	timer := New(delay, clock.Timestamp(0))

	// Disable drift correction (SRTO_DRIFTTRACER=false)
	timer.SetDriftEnabled(false)

	// Feed 1000+ samples that would normally cause drift correction.
	// With drift disabled, OnACK should be a no-op.
	for i := range driftMaxSamples + 100 {
		pktTS := uint32(i * 10000)
		localRecv := clock.Timestamp(int64(i*10000) + 5000) // 5ms drift per sample
		timer.OnACK(pktTS, localRecv, 100000)
	}

	// Drift should remain zero since correction is disabled
	drift := timer.DriftOffset()
	if drift != 0 {
		t.Errorf("DriftOffset with DriftTracer disabled: got %d, want 0", drift)
	}

	// Delivery time should not be affected by drift
	delivery := timer.DeliveryTime(1_000_000)
	expected := clock.Timestamp(1_000_000 + int64(delay))
	if delivery != expected {
		t.Errorf("DeliveryTime: got %d, want %d (no drift)", delivery, expected)
	}
}

func TestDriftTracerReenabled(t *testing.T) {
	delay := 100 * clock.Millisecond
	timer := New(delay, clock.Timestamp(0))

	// Disable, add some samples (should be ignored)
	timer.SetDriftEnabled(false)
	for i := range 500 {
		pktTS := uint32(i * 10000)
		localRecv := clock.Timestamp(int64(i*10000) + 5000)
		timer.OnACK(pktTS, localRecv, -1)
	}

	// Re-enable and add enough samples to trigger drift computation
	timer.SetDriftEnabled(true)
	for i := range driftMaxSamples {
		pktTS := uint32((500 + i) * 10000)
		localRecv := clock.Timestamp(int64((500+i)*10000) + 50) // 50us drift
		timer.OnACK(pktTS, localRecv, -1)
	}

	drift := timer.DriftOffset()
	if drift != 50 {
		t.Errorf("DriftOffset after re-enable: got %d, want 50", drift)
	}
}

func BenchmarkIsReady(b *testing.B) {
	timer := New(120*clock.Millisecond, clock.Timestamp(1_000_000))
	now := clock.Timestamp(2_000_000)
	for b.Loop() {
		timer.IsReady(500_000, now)
	}
}
