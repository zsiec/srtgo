package srt

import (
	"sync/atomic"
	"time"
)

// sndRateEstimator is a circular-buffer estimator
// from buffer_tools.h. It accumulates packets and bytes in 100ms windows and
// provides a smoothed average over the last 10 periods (1 second total).
//
// The Write goroutine feeds data via lock-free atomic accumulators (curPkts,
// curBytes). The timerLoop drains these into the current slot via rotate().
// getRate() is called infrequently from Stats() under the bufStats mutex.
type sndRateEstimator struct {
	slots    [sndRateNumSlots]sndRateSlot
	curSlot  int       // index of the current accumulation slot
	filled   int       // number of slots filled (for avg before full wrap)
	slotTime time.Time // start time of current slot

	// Lock-free accumulators: Write goroutine adds here, timerLoop drains.
	curPkts  atomic.Int64
	curBytes atomic.Int64
}

const (
	sndRateNumSlots = 10                     // 10 periods = 1 second total
	sndRateWindow   = 100 * time.Millisecond // 100ms per window
)

// sndRateSlot tracks packets and bytes within a single 100ms window.
type sndRateSlot struct {
	packets int64
	bytes   int64
}

// init resets the estimator with the given start time.
func (e *sndRateEstimator) init(now time.Time) {
	e.curSlot = 0
	e.filled = 0
	e.slotTime = now
	clear(e.slots[:])
	e.curPkts.Store(0)
	e.curBytes.Store(0)
}

// recordLockFree atomically accumulates packet+byte counts from the Write goroutine.
// No mutex needed — just two atomic adds.
func (e *sndRateEstimator) recordLockFree(pkts int, bytes int) {
	e.curPkts.Add(int64(pkts))
	e.curBytes.Add(int64(bytes))
}

// drainAtomics moves accumulated atomic counts into the current slot.
// Called from rotate() under the bufStats mutex.
func (e *sndRateEstimator) drainAtomics() {
	pkts := e.curPkts.Swap(0)
	bytes := e.curBytes.Swap(0)
	e.slots[e.curSlot].packets += pkts
	e.slots[e.curSlot].bytes += bytes
}

// advance moves to the next slot, clearing it.
func (e *sndRateEstimator) advance() {
	e.curSlot = (e.curSlot + 1) % sndRateNumSlots
	e.slots[e.curSlot] = sndRateSlot{}
	if e.filled < sndRateNumSlots {
		e.filled++
	}
	e.slotTime = e.slotTime.Add(sndRateWindow)
}

// rotate is called from the timer loop every 10ms to drain atomics and advance
// slots when the current window has elapsed. Must be called under bufStats mutex.
func (e *sndRateEstimator) rotate(now time.Time) {
	// Drain atomic accumulators into the current slot first
	e.drainAtomics()

	if e.slotTime.IsZero() {
		e.slotTime = now
		return
	}
	for now.Sub(e.slotTime) >= sndRateWindow {
		e.advance()
	}
}

// getRate returns the average send rate as packets/sec and bytes/sec.
// Averages over all filled slots (up to 10). Returns (0, 0) if no data.
// Must be called under bufStats mutex.
func (e *sndRateEstimator) getRate() (pktPerSec int64, bytesPerSec int64) {
	if e.filled == 0 {
		return 0, 0
	}

	// Sum all slots except the current one (which is still accumulating)
	var totalPkts, totalBytes int64
	count := e.filled
	if count > sndRateNumSlots-1 {
		count = sndRateNumSlots - 1
	}
	if count == 0 {
		// Only one slot filled and still accumulating -- use it
		s := e.slots[e.curSlot]
		if s.packets == 0 {
			return 0, 0
		}
		// Scale to per-second
		return s.packets * int64(time.Second/sndRateWindow),
			s.bytes * int64(time.Second/sndRateWindow)
	}

	for i := 1; i <= count; i++ {
		idx := (e.curSlot - i + sndRateNumSlots) % sndRateNumSlots
		totalPkts += e.slots[idx].packets
		totalBytes += e.slots[idx].bytes
	}

	// Each slot is sndRateWindow (100ms). Scale to per-second using integer arithmetic.
	// rate = total / (count * 100ms) = total * 10 / count
	pktPerSec = totalPkts * int64(sndRateNumSlots) / int64(count)
	bytesPerSec = totalBytes * int64(sndRateNumSlots) / int64(count)
	return pktPerSec, bytesPerSec
}
