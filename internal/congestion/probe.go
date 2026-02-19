package congestion

import (
	"math"
	"slices"

	"github.com/zsiec/srtgo/internal/clock"
)

const (
	probeWindowSize = 16 // number of probe pair samples in the window
)

// probeEstimator implements probe-pair bandwidth estimation.
// Every ProbeInterval-th packet pair is sent back-to-back;
// the receiver measures inter-arrival time,
// normalizes by actual packet size, and stores in a 16-element circular
// window. Bandwidth is computed using a peak-range median filter.
//
// This struct has no internal synchronization — the embedding CC must
// hold its own mutex when calling these methods.
type probeEstimator struct {
	lastSentSeq    uint32
	maxPayloadSize int // reference payload size for normalization

	// Probe pair state (receiver side)
	probe1Time  clock.Timestamp
	probe1Seq   uint32
	probe1Valid bool // true if probe1 was recorded

	// Circular window of normalized inter-arrival times (microseconds).
	// Each entry represents the estimated inter-arrival for a full-size packet.
	// Initialized to 1000μs (= 1000 pkts/sec baseline).
	probeWindow [probeWindowSize]int
	probePtr    int  // next write position
	initialized bool // true once at least probeWindowSize entries have been written

	// filterBuf is reused by peakRangeFilter to avoid per-call allocation.
	filterBuf [probeWindowSize]int
}

// initProbeWindow initializes the probe window to baseline values.
// Each entry is set to 1000μs (1ms), yielding a 1000 pkts/sec baseline.
func (pe *probeEstimator) initProbeWindow(maxPayloadSize int) {
	pe.maxPayloadSize = maxPayloadSize
	for i := range pe.probeWindow {
		pe.probeWindow[i] = 1000 // 1ms baseline
	}
}

// onPacketSent records the sent sequence number for probe pair scheduling.
func (pe *probeEstimator) onPacketSent(seqNo uint32) {
	pe.lastSentSeq = seqNo
}

// isProbePacket returns true if the last sent packet was the first of a
// probe pair (seqNo%16==0).
func (pe *probeEstimator) isProbePacket() bool {
	return pe.lastSentSeq%uint32(ProbeInterval) == 0
}

// onPacketReceived processes a received data packet for bandwidth estimation.
// Only probe pairs (every 16th→17th packet) contribute to the estimate.
// The caller must NOT call this for retransmitted packets.
//
// probe1 records seqno%16==0, probe2 measures seqno%16==1.
// Sequence continuity is checked: probe2 must be exactly probe1+1.
func (pe *probeEstimator) onPacketReceived(seqNo uint32, size int, arrivalTime clock.Timestamp) {
	inorder16 := seqNo % uint32(ProbeInterval)

	// Probe1: record arrival of seqno%16==0
	if inorder16 == 0 {
		pe.probe1Time = arrivalTime
		pe.probe1Seq = seqNo
		pe.probe1Valid = true
	}

	// Probe2: measure seqno%16==1
	if inorder16 == 1 {
		if !pe.probe1Valid {
			return
		}
		// Require probe2.seqno == probe1.seqno + 1 (with wrapping)
		expectedSeq := pe.probe1Seq + 1
		if pe.probe1Seq == 0x7FFFFFFF {
			expectedSeq = 0
		}
		if seqNo != expectedSeq {
			return
		}

		pe.probe1Valid = false // consumed

		timediff := int64(arrivalTime.Sub(pe.probe1Time))
		if timediff <= 0 {
			return
		}

		// Normalize by actual packet size: if the packet is smaller than
		// full payload, scale the timediff up proportionally.
		normalized := timediff
		if pe.maxPayloadSize > 0 && size > 0 && size != pe.maxPayloadSize {
			normalized = timediff * int64(pe.maxPayloadSize) / int64(size)
		}

		pe.probeWindow[pe.probePtr] = int(normalized)
		pe.probePtr++
		if pe.probePtr >= probeWindowSize {
			pe.probePtr = 0
			pe.initialized = true
		}
	}
}

// estimatedBandwidth returns the link capacity estimate in packets/sec
// using the peak-range median filter. This is the probe-pair-based estimate.
//
// Algorithm:
// 1. Find median of the window
// 2. Filter to values in (median/8, median*8)
// 3. Average the filtered values + median
// 4. Return ceil(1_000_000 / avg) as packets/sec
func (pe *probeEstimator) estimatedBandwidth() uint32 {
	// Probe window is pre-initialized to 1000µs per entry, so
	// estimatedBandwidth returns a sensible default (~1000 pkt/sec) immediately,
	// even before any probe pairs are received. We run the filter on the
	// initialized window regardless of the initialized flag.
	avg := peakRangeFilter(pe.probeWindow[:], pe.filterBuf[:])
	if avg <= 0 {
		return 0
	}

	// packets/sec = ceil(1_000_000 / avg_inter_arrival_us)
	return uint32(math.Ceil(1_000_000 / avg))
}

// peakRangeFilter implements the peak-range median filter algorithm.
// scratch must be at least len(window) in capacity; it is used as a sort buffer
// to avoid per-call allocation.
func peakRangeFilter(window []int, scratch []int) float64 {
	n := len(window)
	if n == 0 {
		return 0
	}

	// Find median using the scratch buffer
	replica := scratch[:n]
	copy(replica, window)
	slices.Sort(replica)
	median := replica[n/2]

	if median <= 0 {
		return 0
	}

	lower := median >> 3 // median / 8
	upper := median << 3 // median * 8

	// Accumulate values within (lower, upper) — exclusive bounds
	sum := 0
	count := 0
	for _, v := range window {
		if v > lower && v < upper {
			sum += v
			count++
		}
	}

	// Add median once more to the accumulated sum
	sum += median
	count++

	return float64(sum) / float64(count)
}
