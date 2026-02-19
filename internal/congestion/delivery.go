package congestion

import (
	"math"
	"slices"

	"github.com/zsiec/srtgo/internal/clock"
)

const (
	deliveryWindowSize = 16 // number of inter-arrival samples in the window
)

// deliveryEstimator tracks inter-arrival times of ALL received data packets
// using parallel pktWindow and bytesWindow arrays. This is separate from probe
// pair estimation (probeEstimator), which only measures every 16th->17th
// packet pair for link capacity.
//
// This struct has no internal synchronization -- the embedding CC must
// hold its own mutex when calling these methods.
type deliveryEstimator struct {
	maxPayloadSize int

	lastArrivalTime clock.Timestamp
	hasLastArrival  bool

	// Circular window of inter-arrival times (microseconds).
	// Initialized to 1,000,000μs (= 1 pkt/sec baseline).
	pktWindow [deliveryWindowSize]int

	// Parallel circular window of payload bytes per packet.
	// Initialized to maxPayloadSize.
	bytesWindow [deliveryWindowSize]int

	pktPtr      int  // next write position
	initialized bool // true once at least deliveryWindowSize entries have been written
}

// initDeliveryWindow initializes the delivery window to baseline values.
// pktWindow[i]=1000000 (1 pkt/sec), bytesWindow[i]=maxPayloadSize.
func (de *deliveryEstimator) initDeliveryWindow(maxPayloadSize int) {
	de.maxPayloadSize = maxPayloadSize
	for i := range de.pktWindow {
		de.pktWindow[i] = 1_000_000 // 1 sec → 1 pkt/sec baseline
	}
	for i := range de.bytesWindow {
		de.bytesWindow[i] = maxPayloadSize
	}
}

// onPktArrival records the arrival of a data packet.
// Called for ALL received data packets (including retransmitted).
func (de *deliveryEstimator) onPktArrival(size int, arrivalTime clock.Timestamp) {
	if !de.hasLastArrival {
		de.lastArrivalTime = arrivalTime
		de.hasLastArrival = true
		return
	}

	interval := int(arrivalTime.Sub(de.lastArrivalTime))
	de.lastArrivalTime = arrivalTime

	// Record interval and bytes
	de.pktWindow[de.pktPtr] = interval
	de.bytesWindow[de.pktPtr] = size

	de.pktPtr++
	if de.pktPtr >= deliveryWindowSize {
		de.pktPtr = 0
		de.initialized = true
	}
}

// getPktRcvSpeed returns the overall packet delivery rate.
//
// Key differences from probe estimatedBandwidth():
//   - Does NOT add median to sum/count
//   - Returns 0 if fewer than half the window entries pass the filter
//   - Computes bytes/sec in parallel, adding header overhead
func (de *deliveryEstimator) getPktRcvSpeed() (pktRate uint32, bytesRate uint32) {
	if !de.initialized {
		return 0, 0
	}

	return deliveryRateFilter(de.pktWindow[:], de.bytesWindow[:], de.maxPayloadSize)
}

// deliveryRateFilter computes the packet delivery rate from the time/bytes windows.
// Unlike peakRangeFilter (used for probe bandwidth), this:
//   - Does NOT add median to sum/count
//   - Has a count > windowSize/2 minimum threshold
//   - Computes bytes/sec in parallel with header overhead
func deliveryRateFilter(timeWindow, bytesWindow []int, maxPayloadSize int) (pktRate uint32, bytesRate uint32) {
	n := len(timeWindow)
	if n == 0 {
		return 0, 0
	}

	// Find median using a sorted copy
	replica := make([]int, n)
	copy(replica, timeWindow)
	slices.Sort(replica)
	median := replica[n/2]

	if median <= 0 {
		return 0, 0
	}

	lower := median >> 3 // median / 8
	upper := median << 3 // median * 8

	// Accumulate time intervals and bytes for values within (lower, upper)
	// exclusive bounds. Unlike probe bandwidth, we do NOT add median to sum/count.
	var sum int
	var count uint32
	var totalBytes uint64
	for i, v := range timeWindow {
		if v > lower && v < upper {
			sum += v
			count++
			totalBytes += uint64(bytesWindow[i])
		}
	}

	// Return 0 if not enough valid values
	if count <= uint32(n/2) {
		return 0, 0
	}

	// Add protocol headers to bytes received
	totalBytes += uint64(WireHeaderSize) * uint64(count)

	// ceilPerMega(sum, count) = ceil(1_000_000 / (sum / count))
	//                              = ceil(1_000_000 * count / sum)
	avgInterval := float64(sum) / float64(count)
	if avgInterval <= 0 {
		return 0, 0
	}
	pkts := uint32(math.Ceil(1_000_000 / avgInterval))

	// ceilPerMega(sum, bytes) = ceil(1_000_000 * bytes / sum)
	bytesPS := uint32(math.Ceil(1_000_000 * float64(totalBytes) / float64(sum)))

	return pkts, bytesPS
}
