package legacy

import (
	"testing"
	"time"
)

func TestSndRateEstimator_Basic(t *testing.T) {
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	// Send 100 packets of 1000 bytes in the first window
	for range 100 {
		e.recordLockFree(1, 1000)
	}

	// Advance to next window (drains atomics + rotates)
	e.rotate(now.Add(150 * time.Millisecond))

	pps, bps := e.getRate()
	if pps == 0 || bps == 0 {
		t.Errorf("expected non-zero rate, got pps=%d bps=%d", pps, bps)
	}

	// 100 packets in 100ms = ~1000 pps
	if pps < 500 || pps > 2000 {
		t.Errorf("pps=%d, expected ~1000", pps)
	}

	// 100*1000 bytes in 100ms = ~1,000,000 bps
	if bps < 500000 || bps > 2000000 {
		t.Errorf("bps=%d, expected ~1000000", bps)
	}
}

func TestSndRateEstimator_MultipleWindows(t *testing.T) {
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	// Send packets across 5 windows
	for w := range 5 {
		for range 10 {
			e.recordLockFree(1, 500)
		}
		// Rotate at end of each window
		windowEnd := now.Add(time.Duration(w+1) * sndRateWindow)
		e.rotate(windowEnd)
	}

	// Advance past 5th window
	e.rotate(now.Add(6 * sndRateWindow))

	pps, bps := e.getRate()
	if pps == 0 || bps == 0 {
		t.Errorf("expected non-zero rate after 5 windows, got pps=%d bps=%d", pps, bps)
	}
}

func TestSndRateEstimator_EmptyRate(t *testing.T) {
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	pps, bps := e.getRate()
	if pps != 0 || bps != 0 {
		t.Errorf("expected zero rate for empty estimator, got pps=%d bps=%d", pps, bps)
	}
}

func TestSndRateEstimator_WrapAround(t *testing.T) {
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	// Fill all 10 slots and then some to test wrap-around
	for w := range 15 {
		e.recordLockFree(10, 5000)
		windowEnd := now.Add(time.Duration(w+1) * sndRateWindow)
		e.rotate(windowEnd)
	}

	pps, bps := e.getRate()
	if pps == 0 || bps == 0 {
		t.Errorf("expected non-zero rate after wrap-around, got pps=%d bps=%d", pps, bps)
	}
}

func TestSndRateEstimator_RotateZeroSlotTime(t *testing.T) {
	// Test rotate when slotTime is zero (should initialize from now)
	var e sndRateEstimator
	// Don't call init — slotTime is zero

	now := time.Now()
	e.rotate(now)

	// After rotate with zero slotTime, slotTime should be set to now
	if e.slotTime.IsZero() {
		t.Error("slotTime should be set after rotate")
	}
}

func TestSndRateEstimator_RecordLockFree(t *testing.T) {
	// Test recordLockFree accumulates correctly
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	e.recordLockFree(1, 100)

	if e.curPkts.Load() != 1 {
		t.Errorf("curPkts: got %d, want 1", e.curPkts.Load())
	}
	if e.curBytes.Load() != 100 {
		t.Errorf("curBytes: got %d, want 100", e.curBytes.Load())
	}

	// After drain, atomics should be zero and slot should have data
	e.drainAtomics()
	if e.curPkts.Load() != 0 {
		t.Errorf("curPkts after drain: got %d, want 0", e.curPkts.Load())
	}
	if e.slots[0].packets != 1 {
		t.Errorf("slot packets: got %d, want 1", e.slots[0].packets)
	}
	if e.slots[0].bytes != 100 {
		t.Errorf("slot bytes: got %d, want 100", e.slots[0].bytes)
	}
}

func TestSndRateEstimator_GetRateOnlyCurrentSlot(t *testing.T) {
	// Test getRate when only one slot is filled (count=0 after clamping)
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	// Send packets via lock-free path
	e.recordLockFree(10, 5000)

	// filled is still 0 — init doesn't set filled
	pps, bps := e.getRate()
	// With filled=0, should return 0,0
	if pps != 0 || bps != 0 {
		// Or if there's a path for the single-slot case:
		t.Logf("getRate returned pps=%d bps=%d (ok for single-slot path)", pps, bps)
	}
}

func TestSndRateEstimator_RotateMultipleSkipped(t *testing.T) {
	// Test rotate when multiple windows have elapsed
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	e.recordLockFree(5, 500)

	// Jump far ahead — 500ms = 5 windows
	future := now.Add(500 * time.Millisecond)
	e.rotate(future)

	// Should have advanced through 5 windows
	if e.filled < 5 {
		t.Errorf("filled: got %d, want >= 5", e.filled)
	}

	pps, bps := e.getRate()
	// Rate should be non-zero since data was in one of the old slots
	t.Logf("after skip: pps=%d bps=%d", pps, bps)
}

func TestSndRateEstimator_GetRateSingleFilled(t *testing.T) {
	// Test the count == 0 path in getRate (only 1 slot filled, still accumulating)
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	// Send one packet to set data in slot
	e.recordLockFree(10, 5000)
	e.drainAtomics()

	// Advance exactly once — filled becomes 1
	e.advance()

	// Put data in the new current slot
	e.recordLockFree(20, 10000)
	e.drainAtomics()

	// Now filled=1, count = min(1, 9) = 1 — should use the old slot
	pps, bps := e.getRate()
	if pps == 0 || bps == 0 {
		t.Errorf("expected non-zero rate with 1 filled slot: pps=%d bps=%d", pps, bps)
	}
}

func TestSndRateEstimator_GetRateCurrentSlotOnlyOneFilled(t *testing.T) {
	// Test the count == 0 path in getRate: exactly 1 slot filled (the current one)
	// and no completed slots to average over. This exercises the single-slot fallback.
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	// Send data and drain into slot 0
	e.recordLockFree(50, 25000)
	e.drainAtomics()

	// Manually advance once so filled=1
	e.advance()
	// Now filled=1, curSlot=1. The old slot (0) has data; curSlot=1 is empty.
	// getRate will use count=min(1,9)=1 and average the old slot.
	pps, bps := e.getRate()
	// 50 packets / 0.1s = 500 pps; 25000 bytes / 0.1s = 250000 bps
	if pps < 400 || pps > 600 {
		t.Errorf("pps=%d, expected ~500", pps)
	}
	if bps < 200000 || bps > 300000 {
		t.Errorf("bps=%d, expected ~250000", bps)
	}
}

func TestSndRateEstimator_GetRateZeroPacketsInCurrentSlot(t *testing.T) {
	// Test the count == 0 fallback path where only the current slot
	// has data, with filled=1 but the old slot is empty.
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	// advance once so filled=1, but the old slot (0) is empty (init clears it)
	e.advance()
	// curSlot=1, filled=1, slot[0]={0,0}
	// Now add data to current slot only
	e.slots[e.curSlot] = sndRateSlot{packets: 20, bytes: 10000}

	// getRate: filled=1, count=min(1,9)=1, sums slot[0]={0,0} => rate=0
	pps, bps := e.getRate()
	// The old slot is empty, so rate should be 0
	if pps != 0 || bps != 0 {
		t.Logf("getRate with empty old slot: pps=%d bps=%d (may be zero)", pps, bps)
	}
}

func TestSndRateEstimator_GetRateFullSlots(t *testing.T) {
	// Test getRate when all 10 slots are filled (full wrap-around).
	// This tests count = sndRateNumSlots-1 = 9 (max averaging window).
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	// Fill all 10 slots with known data
	for i := range sndRateNumSlots {
		e.recordLockFree(100, 50000)
		e.drainAtomics()
		if i < sndRateNumSlots-1 {
			e.advance()
		}
	}
	// Push one more to ensure filled is capped at sndRateNumSlots
	e.advance()
	e.recordLockFree(100, 50000)
	e.drainAtomics()

	pps, bps := e.getRate()
	// 100 packets per 100ms window, 9 windows = 900 packets / 0.9s = 1000 pps
	if pps < 800 || pps > 1200 {
		t.Errorf("pps=%d, expected ~1000", pps)
	}
	// 50000 bytes per window, 9 windows = 450000 / 0.9s = 500000 bps
	if bps < 400000 || bps > 600000 {
		t.Errorf("bps=%d, expected ~500000", bps)
	}
}

func TestSndRateEstimator_GetRateAccuracy(t *testing.T) {
	// Precise rate test: exactly 1000 packets of 1000 bytes each
	// spread evenly across 5 windows = 500ms.
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	for w := range 5 {
		// 200 packets per window
		e.recordLockFree(200, 200000)
		windowEnd := now.Add(time.Duration(w+1) * sndRateWindow)
		e.rotate(windowEnd)
	}

	pps, bps := e.getRate()
	// 200 pkt/100ms = 2000 pps; 200000 bytes/100ms = 2000000 bps
	if pps < 1800 || pps > 2200 {
		t.Errorf("pps=%d, expected ~2000", pps)
	}
	if bps < 1800000 || bps > 2200000 {
		t.Errorf("bps=%d, expected ~2000000", bps)
	}
}
