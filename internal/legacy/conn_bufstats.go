package legacy

import (
	"math"
	"sync"
	"time"
)

// bufferStatsState holds the IIR-8 moving average state for buffer occupancy
// tracking (matching C++ buffer_tools.h AvgBufSize). It also includes the
// send rate estimator for per-100ms send rate tracking.
//
// Stored directly as a field on Conn (c.bufStats) to avoid sync.Map overhead
// on the per-packet send path. All fields are protected by mu.
type bufferStatsState struct {
	mu sync.Mutex

	// IIR-8 smoothed buffer occupancy
	avgSndBufPkts  float64
	avgSndBufBytes float64
	avgRcvBufPkts  float64
	avgRcvBufBytes float64
	lastUpdate     time.Time
	initialized    bool

	// Send rate estimator
	rateEst     sndRateEstimator
	rateEstInit bool
}

// updateBufferIIR updates the IIR-8 moving averages for buffer occupancy.
// Should be called periodically (e.g., every SYN interval from the timer loop,
// or on each Stats() call). Thread-safe.
// buffer_tools.h AvgBufSize: new_avg = old * 7/8 + current * 1/8
func (c *Conn) updateBufferIIR() {
	bs := &c.bufStats
	bs.mu.Lock()
	defer bs.mu.Unlock()

	sndPkts := float64(c.sendBuf.Size())
	sndBytes := sndPkts * float64(c.payloadSize)
	rcvPkts := float64(c.recvBuf.Size())
	rcvBytes := rcvPkts * float64(c.payloadSize)

	if !bs.initialized {
		// First sample: initialize directly
		bs.avgSndBufPkts = sndPkts
		bs.avgSndBufBytes = sndBytes
		bs.avgRcvBufPkts = rcvPkts
		bs.avgRcvBufBytes = rcvBytes
		bs.lastUpdate = time.Now()
		bs.initialized = true
		return
	}

	// IIR-8: newAvg = oldAvg * 7/8 + currentValue * 1/8
	bs.avgSndBufPkts = bs.avgSndBufPkts*7.0/8.0 + sndPkts/8.0
	bs.avgSndBufBytes = bs.avgSndBufBytes*7.0/8.0 + sndBytes/8.0
	bs.avgRcvBufPkts = bs.avgRcvBufPkts*7.0/8.0 + rcvPkts/8.0
	bs.avgRcvBufBytes = bs.avgRcvBufBytes*7.0/8.0 + rcvBytes/8.0
	bs.lastUpdate = time.Now()
}

// recordSendRate feeds the send rate estimator with packet data.
// Lock-free on the hot path: just two atomic adds.
func (c *Conn) recordSendRate(pkts int, bytes int) {
	c.bufStats.rateEst.recordLockFree(pkts, bytes)
}

// rotateSendRate advances the send rate estimator's time window.
// Drains atomic accumulators and advances slots. Thread-safe.
func (c *Conn) rotateSendRate() {
	bs := &c.bufStats
	bs.mu.Lock()
	if !bs.rateEstInit {
		bs.rateEst.init(time.Now())
		bs.rateEstInit = true
	}
	bs.rateEst.rotate(time.Now())
	bs.mu.Unlock()
}

// SendRate returns the current smoothed send rate as packets/sec and bytes/sec.
// This is the circular-buffer average over the last 1 second.
func (c *Conn) SendRate() (pktPerSec int64, bytesPerSec int64) {
	bs := &c.bufStats
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if !bs.rateEstInit {
		return 0, 0
	}
	return bs.rateEst.getRate()
}

// AvgSndBufSize returns the IIR-8 smoothed send buffer occupancy in packets.
// buffer_tools.h AvgBufSize.
func (c *Conn) AvgSndBufSize() float64 {
	bs := &c.bufStats
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if !bs.initialized {
		return float64(c.sendBuf.Size())
	}
	return math.Round(bs.avgSndBufPkts*100) / 100
}

// AvgSndBufBytes returns the IIR-8 smoothed send buffer occupancy in bytes.
func (c *Conn) AvgSndBufBytes() float64 {
	bs := &c.bufStats
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if !bs.initialized {
		return float64(c.sendBuf.Size()) * float64(c.payloadSize)
	}
	return math.Round(bs.avgSndBufBytes*100) / 100
}

// AvgRcvBufSize returns the IIR-8 smoothed receive buffer occupancy in packets.
func (c *Conn) AvgRcvBufSize() float64 {
	bs := &c.bufStats
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if !bs.initialized {
		return float64(c.recvBuf.Size())
	}
	return math.Round(bs.avgRcvBufPkts*100) / 100
}

// AvgRcvBufBytes returns the IIR-8 smoothed receive buffer occupancy in bytes.
func (c *Conn) AvgRcvBufBytes() float64 {
	bs := &c.bufStats
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if !bs.initialized {
		return float64(c.recvBuf.Size()) * float64(c.payloadSize)
	}
	return math.Round(bs.avgRcvBufBytes*100) / 100
}

// ExtendedStats returns an ExtendedConnStats containing the base ConnStats plus
// additional buffer occupancy averages and send rate statistics.
// When clear is true, interval counters are reset (same as Stats).
func (c *Conn) ExtendedStats(clear bool) ExtendedConnStats {
	// Update buffer IIR averages before collecting stats
	c.updateBufferIIR()
	c.rotateSendRate()

	base := c.Stats(clear)

	sndRatePps, sndRateBps := c.SendRate()

	return ExtendedConnStats{
		ConnStats:      base,
		AvgSndBufPkts:  c.AvgSndBufSize(),
		AvgSndBufBytes: c.AvgSndBufBytes(),
		AvgRcvBufPkts:  c.AvgRcvBufSize(),
		AvgRcvBufBytes: c.AvgRcvBufBytes(),
		SendRatePps:    sndRatePps,
		SendRateBps:    sndRateBps,
	}
}

// ExtendedConnStats extends ConnStats with buffer IIR averages and send rate.
// These fields match C++ buffer_tools.h AvgBufSize and CSndRateEstimator.
type ExtendedConnStats struct {
	ConnStats

	// IIR-8 smoothed buffer occupancy
	AvgSndBufPkts  float64 // average send buffer occupancy in packets
	AvgSndBufBytes float64 // average send buffer occupancy in bytes
	AvgRcvBufPkts  float64 // average receive buffer occupancy in packets
	AvgRcvBufBytes float64 // average receive buffer occupancy in bytes

	// Send rate from circular buffer estimator
	SendRatePps int64 // smoothed send rate in packets/sec
	SendRateBps int64 // smoothed send rate in bytes/sec
}
