package congestion

import (
	"fmt"
	"math"
	"sync"
	"sync/atomic"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/packet"
)

// Default values for live congestion control.
const (
	DefaultMaxBW      int64 = 1_000_000_000 / 8 // 1 Gbps = 125 MB/s
	DefaultOverhead   int   = 25                // 25% overhead for retransmissions
	DefaultPacketSize int   = 1316              // typical video packet payload size
	ProbeInterval     int   = 16                // send probe every 16th packet
)

// LiveCC implements the SRT live mode congestion controller.
// It uses a fixed-rate pacer: packets are sent at a constant interval
// determined by maxBW / packetSize.
//
// Probe pairs are used for bandwidth estimation: every ProbeInterval-th
// packet pair is sent back-to-back, and the receiver measures the
// inter-arrival time to estimate link capacity.
type LiveCC struct {
	mu sync.Mutex // protects probe, delivery, overhead

	// Atomic fields for lock-free PacketInterval() and IsProbePacket() reads.
	// These are the hot-path fields read 2-3x per packet send.
	atomicMaxBW          atomic.Int64  // bytes per second
	atomicAvgPayloadSize atomic.Int64  // IIR-128 running average of sent payload sizes
	atomicLastSentSeq    atomic.Uint32 // last sent seqno for probe pair detection

	overhead   int // percentage (0-100), written rarely
	packetSize int // expected payload size (default 1316), immutable

	probe    probeEstimator
	delivery deliveryEstimator
}

// NewLiveCC creates a new live mode congestion controller.
func NewLiveCC(maxBW int64, packetSize int) *LiveCC {
	if maxBW <= 0 {
		maxBW = DefaultMaxBW
	}
	if packetSize <= 0 {
		packetSize = DefaultPacketSize
	}

	cc := &LiveCC{
		overhead:   DefaultOverhead,
		packetSize: packetSize,
	}
	cc.atomicMaxBW.Store(maxBW)
	cc.atomicAvgPayloadSize.Store(int64(packetSize))
	cc.probe.initProbeWindow(packetSize)
	cc.delivery.initDeliveryWindow(packetSize)
	return cc
}

// PacketInterval returns the inter-packet interval in microseconds.
// interval = 1e6 * pktsize / maxBW, where pktsize = avgPayload + headerSize
// (IP+UDP+SRT = 44 bytes). maxBW is the wire bandwidth limit -- overhead is
// NOT applied here. Overhead is applied externally (in updateCC/updateBandwidth)
// only when maxBW is derived from InputBW or auto-sampling, never to explicit
// SRTO_MAXBW.
func (cc *LiveCC) PacketInterval() clock.Microseconds {
	maxBW := cc.atomicMaxBW.Load()
	if maxBW <= 0 {
		return clock.Millisecond // fallback: 1ms
	}

	// Include wire header overhead in packet size:
	// pktsize = avgPayloadSize + headerSize
	pktSize := cc.atomicAvgPayloadSize.Load() + int64(packet.WireHeaderSize)
	interval := clock.Microseconds(int64(clock.Second) * pktSize / maxBW)
	if interval <= 0 {
		return 1
	}
	return interval
}

// OnACK processes an ACK from the receiver.
func (cc *LiveCC) OnACK(ackSeqNo uint32, rtt clock.Microseconds, bandwidth uint32, deliveryRate uint32) {
	// Live mode doesn't adjust rate based on ACK, but we could
	// use bandwidth estimation data here if needed.
}

// OnNAK processes a loss report from the receiver.
func (cc *LiveCC) OnNAK(lossSeqs []uint32) {
	// Live mode doesn't reduce rate on loss — it maintains
	// the configured fixed rate.
}

// OnTimeout is a no-op for live mode (fixed-rate pacer).
func (cc *LiveCC) OnTimeout() {}

// OnPacketSent is called when a packet is sent.
// Updates the running average payload size via IIR-128 filter.
// Lock-free: probe.lastSentSeq is redundant with atomicLastSentSeq.
func (cc *LiveCC) OnPacketSent(seqNo uint32, size int) {
	cc.atomicLastSentSeq.Store(seqNo)
	if size > 0 {
		// IIR-128 filter: avg = (old * 127 + new) / 128
		old := cc.atomicAvgPayloadSize.Load()
		cc.atomicAvgPayloadSize.Store((old*127 + int64(size)) / 128)
	}
}

// IsProbePacket returns true if the last sent packet was the first of
// a probe pair (seqNo%16==0), meaning the next packet should be sent
// immediately (back-to-back) for bandwidth measurement.
func (cc *LiveCC) IsProbePacket() bool {
	return cc.atomicLastSentSeq.Load()%uint32(ProbeInterval) == 0
}

// OnPacketReceived processes a received non-retransmitted data packet for
// probe-pair link capacity estimation. Only probe pairs (every 16th→17th
// packet) contribute to the estimate.
func (cc *LiveCC) OnPacketReceived(seqNo uint32, size int, arrivalTime clock.Timestamp) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.probe.onPacketReceived(seqNo, size, arrivalTime)
}

// OnPktArrival records the arrival of ANY data packet (including retransmitted)
// for overall delivery rate estimation.
func (cc *LiveCC) OnPktArrival(size int, arrivalTime clock.Timestamp) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.delivery.onPktArrival(size, arrivalTime)
}

// EstimatedBandwidth returns the link capacity estimate from probe pair
// measurements, in packets per second.
func (cc *LiveCC) EstimatedBandwidth() uint32 {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.probe.estimatedBandwidth()
}

// DeliveryRate returns the overall packet delivery rate from ALL received
// packets. pktRate is packets/sec, bytesRate is bytes/sec (including headers).
func (cc *LiveCC) DeliveryRate() (pktRate uint32, bytesRate uint32) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.delivery.getPktRcvSpeed()
}

// SetMaxBandwidth updates the maximum sending bandwidth (wire rate).
func (cc *LiveCC) SetMaxBandwidth(bw int64) {
	cc.atomicMaxBW.Store(bw)
}

// UpdateBandwidth updates bandwidth.
// If maxBW > 0 (explicit SRTO_MAXBW), use it directly with no overhead.
// If maxBW == 0 and inputBW > 0, use inputBW (caller should apply overhead).
// If both are 0, no change.
func (cc *LiveCC) UpdateBandwidth(maxBW, inputBW int64) {
	if maxBW > 0 {
		cc.atomicMaxBW.Store(maxBW)
		return
	}
	if inputBW > 0 {
		cc.atomicMaxBW.Store(inputBW)
	}
}

// SetOverhead sets the bandwidth overhead percentage.
func (cc *LiveCC) SetOverhead(pct int) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	cc.overhead = pct
}

// MaxBandwidth returns the configured max bandwidth.
func (cc *LiveCC) MaxBandwidth() int64 {
	return cc.atomicMaxBW.Load()
}

// CongestionWindow returns math.MaxInt for live mode. Live mode uses
// the flow control window (FC) exclusively, not CWND-based control.
func (cc *LiveCC) CongestionWindow() int {
	return math.MaxInt
}

// MinNAKInterval returns the LiveCC-specific minimum NAK interval (20ms).
func (cc *LiveCC) MinNAKInterval() clock.Microseconds {
	return 20_000 // 20ms
}

// UpdateNAKInterval applies the LiveCC NAK acceleration (divide by 2).
// rcvSpeed and lossLength are passed for future CC extensibility but
// are ignored by LiveCC.
func (cc *LiveCC) UpdateNAKInterval(nakIntUS int64, rcvSpeed int, lossLength int) int64 {
	return nakIntUS / 2
}

// CheckTransArgs validates API compatibility for live mode.
// LiveCC enforces payload size limits for writes.
func (cc *LiveCC) CheckTransArgs(msgAPI bool, size int, isWrite bool) error {
	if isWrite && msgAPI {
		// packetSize is immutable after construction — no lock needed
		if size > cc.packetSize {
			return fmt.Errorf("srt: payload size %d exceeds maximum %d for live mode", size, cc.packetSize)
		}
	}
	return nil
}

// ACKMaxPackets returns 0 — LiveCC uses timer-based ACK only.
func (cc *LiveCC) ACKMaxPackets() int { return 0 }

// ACKTimeoutUS returns 0 — LiveCC uses the default 10ms SYN interval.
func (cc *LiveCC) ACKTimeoutUS() int64 { return 0 }
