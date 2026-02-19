// Package tsbpd implements Timestamp-Based Packet Delivery for SRT.
//
// TSBPD calculates when received packets should be delivered to the application:
//
//	DeliveryTime = TsbpdTimeBase + WrapOffset + PktTimestamp + TsbpdDelay + DriftCorrection
//
// TsbpdTimeBase is the local time when the connection started (adjusted for
// the time offset between sender and receiver). PktTimestamp is the 32-bit
// timestamp from the SRT data packet. TsbpdDelay is the configured latency.
// DriftCorrection compensates for clock drift between sender and receiver.
//
// The 32-bit SRT timestamp wraps every ~71.6 minutes (2^32 microseconds).
// This package handles the wrap-around using a two-phase state machine.
package tsbpd

import (
	"sync"

	"github.com/zsiec/srtgo/internal/clock"
)

const (
	// maxTimestamp is the maximum value of a 32-bit SRT timestamp.
	maxTimestamp = clock.Microseconds(0xFFFFFFFF)

	// timestampWrap is 2^32 microseconds — the full wrap-around period.
	timestampWrap = clock.Microseconds(1 << 32)

	// wrapThreshold is 30 seconds. Used for both entry/exit conditions
	// of the wrap period state machine.
	wrapThreshold = clock.Microseconds(30 * clock.Second)

	// driftMaxSamples is the number of samples before computing drift correction.
	driftMaxSamples = 1000

	// driftMaxValue is the maximum drift (in microseconds) before overdrift
	// adjusts the time base.
	driftMaxValue = clock.Microseconds(5000) // 5ms
)

// Timer calculates TSBPD delivery times for received packets.
type Timer struct {
	mu sync.RWMutex

	delay    clock.Microseconds // configured TSBPD latency
	timeBase clock.Timestamp    // local time base for packet timestamp decoding

	// Drift correction: accumulates samples as a running sum, computes average
	// every 1000 samples. When |avgDrift| > 5ms, overdrift adjusts timeBase
	// by +/-5ms increments.
	driftEnabled bool               // false = drift correction disabled (SRTO_DRIFTTRACER=false)
	driftSum     clock.Microseconds // running sum of drift samples
	driftCount   int                // number of samples in current epoch
	driftOffset  clock.Microseconds // current drift correction (residual after overdrift)
	firstRTT     int64              // first RTT sample in microseconds (-1 = not yet set)

	// Wrap handling — two-phase state machine:
	//   Entry: when pktTimestamp > MAX_TIMESTAMP - 30s
	//   During: packets with timestamp <= 60s get per-packet carryover
	//   Exit:  when pktTimestamp is in [30s, 60s], permanently advance offset
	wrapPeriod bool               // true when in the wrap transition period
	wrapOffset clock.Microseconds // accumulated offset from completed wraps
}

// New creates a new TSBPD Timer with the given delay (latency).
// The timeBase should be set when the connection is established,
// representing the local time corresponding to sender timestamp 0.
func New(delay clock.Microseconds, timeBase clock.Timestamp) *Timer {
	return &Timer{
		delay:        delay,
		timeBase:     timeBase,
		driftEnabled: true,
		firstRTT:     -1,
	}
}

// SetDriftEnabled enables or disables drift correction (SRTO_DRIFTTRACER).
func (t *Timer) SetDriftEnabled(enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.driftEnabled = enabled
}

// DeliveryTime calculates when a packet should be delivered to the application.
//
//	DeliveryTime = TimeBase + WrapOffset + [Carryover] + PktTimestamp + Delay + Drift
func (t *Timer) DeliveryTime(pktTimestamp uint32) clock.Timestamp {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.deliveryTimeLocked(pktTimestamp)
}

func (t *Timer) deliveryTimeLocked(pktTimestamp uint32) clock.Timestamp {
	offset := t.wrapOffset

	// During wrap period, packets with small timestamps (<= 60s) have already
	// wrapped past 0 and need per-packet carryover.
	if t.wrapPeriod && clock.Microseconds(pktTimestamp) <= 2*wrapThreshold {
		offset += timestampWrap
	}

	fullTS := offset + clock.Microseconds(pktTimestamp)
	return t.timeBase.Add(fullTS + t.delay + t.driftOffset)
}

// IsReady returns true if a packet with the given timestamp should be delivered now.
func (t *Timer) IsReady(pktTimestamp uint32, now clock.Timestamp) bool {
	delivery := t.DeliveryTime(pktTimestamp)
	return !now.Before(delivery)
}

// UpdateWrap updates the wrap state machine based on the current packet's
// timestamp. Must be called for every received data packet.
//
// State machine:
//   - Entry: when timestamp > MAX_TIMESTAMP - 30s, enter wrap period
//   - Exit:  when timestamp in [30s, 60s], leave wrap period and permanently
//     advance wrapOffset by 2^32
func (t *Timer) UpdateWrap(pktTimestamp uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	ts := clock.Microseconds(pktTimestamp)

	if !t.wrapPeriod {
		// Check if we're approaching the wrap boundary
		if ts > maxTimestamp-wrapThreshold {
			t.wrapPeriod = true
		}
	} else {
		// In wrap period — check if we've completed the transition.
		// Timestamps in [30s, 60s] indicate the wrap is done.
		if ts >= wrapThreshold && ts <= 2*wrapThreshold {
			t.wrapPeriod = false
			t.wrapOffset += timestampWrap
		}
	}
}

// OnACK processes a data packet arrival for drift correction.
// pktTimestamp is the timestamp from the packet that was received.
// localRecvTime is the local time when we received the packet.
// rttSample is the current RTT estimate in microseconds (-1 if unavailable).
//
// Drift is computed as: arrival - expected - (rtt - firstRTT)/2.
// The RTT delta compensates for one-way path delay changes.
func (t *Timer) OnACK(pktTimestamp uint32, localRecvTime clock.Timestamp, rttSample int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// SRTO_DRIFTTRACER=false: skip drift correction entirely
	if !t.driftEnabled {
		return
	}

	// Remember the first RTT sample. Any value (including negative from
	// keepalive) is accepted as the baseline; not gating on >= 0 ensures
	// RTT delta compensation is always enabled once the first sample arrives.
	if t.firstRTT == -1 {
		t.firstRTT = rttSample
	}

	// Compute full timestamp using same wrap logic as DeliveryTime
	offset := t.wrapOffset
	if t.wrapPeriod && clock.Microseconds(pktTimestamp) <= 2*wrapThreshold {
		offset += timestampWrap
	}
	fullTS := offset + clock.Microseconds(pktTimestamp)

	expectedArrival := t.timeBase.Add(fullTS)

	// RTT delta compensation: (rttSample - firstRTT) / 2
	// Assumes change in RTT is approximately 2x the change in one-way delay.
	var rttDelta clock.Microseconds
	if rttSample >= 0 && t.firstRTT >= 0 {
		rttDelta = clock.Microseconds(rttSample-t.firstRTT) / 2
	}

	// Drift = actual - expected - rttDelta
	drift := localRecvTime.Sub(clock.Timestamp(expectedArrival)) - rttDelta

	// Accumulate into running sum.
	t.driftSum += drift
	t.driftCount++

	if t.driftCount >= driftMaxSamples {
		// Compute average drift over the epoch
		avgDrift := t.driftSum / clock.Microseconds(t.driftCount)

		// Reset for next epoch
		t.driftSum = 0
		t.driftCount = 0

		// Overdrift: if |avgDrift| > 5ms, absorb +/-5ms into timeBase.
		if avgDrift > driftMaxValue {
			t.timeBase = t.timeBase.Add(driftMaxValue)
			avgDrift -= driftMaxValue
		} else if avgDrift < -driftMaxValue {
			t.timeBase = t.timeBase.Add(-driftMaxValue)
			avgDrift += driftMaxValue
		}

		t.driftOffset = avgDrift
	}
}

// SetTimeBase updates the time base. This is called during connection setup
// after handshake completes to synchronize sender and receiver clocks.
func (t *Timer) SetTimeBase(timeBase clock.Timestamp) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.timeBase = timeBase
}

// SetDelay updates the TSBPD delay.
func (t *Timer) SetDelay(delay clock.Microseconds) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.delay = delay
}

// Delay returns the configured TSBPD delay.
func (t *Timer) Delay() clock.Microseconds {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.delay
}

// DriftOffset returns the current drift correction value.
func (t *Timer) DriftOffset() clock.Microseconds {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.driftOffset
}

// GroupTimeBase holds the TSBPD internal state needed for group synchronization.
type GroupTimeBase struct {
	TimeBase   clock.Timestamp
	WrapPeriod bool
	Drift      clock.Microseconds
}

// GetInternalTimeBase extracts the current TSBPD timebase, wrap state, and drift
// for group synchronization.
func (t *Timer) GetInternalTimeBase() GroupTimeBase {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return GroupTimeBase{
		TimeBase:   t.timeBase,
		WrapPeriod: t.wrapPeriod,
		Drift:      t.driftOffset,
	}
}

// ApplyGroupDrift synchronizes this timer's timebase and drift to match another
// group member's values. Called when a member's drift is updated and needs to
// propagate to other members.
func (t *Timer) ApplyGroupDrift(tb GroupTimeBase) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.timeBase = tb.TimeBase
	t.wrapPeriod = tb.WrapPeriod
	t.driftOffset = tb.Drift
}

// ApplyGroupTime synchronizes this timer's full TSBPD state to match the group.
// Called when a new member joins and needs to adopt the group's time reference.
// Only sets the drift offset without resetting the drift accumulator.
func (t *Timer) ApplyGroupTime(tb GroupTimeBase, delay clock.Microseconds) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.timeBase = tb.TimeBase
	t.wrapPeriod = tb.WrapPeriod
	t.delay = delay
	t.driftOffset = tb.Drift
}
