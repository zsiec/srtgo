package congestion

import (
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/seq"
)

// FileCC algorithm constants.
const (
	fileCCInitialCWND   = 16        // initial congestion window (packets)
	fileCCInitialPeriod = 1.0       // initial send period (1µs — essentially unlimited)
	fileCCRCInterval    = 10_000    // rate control interval (10ms in µs)
	fileCCLossIncrease  = 1.03      // multiplicative increase factor for sndPeriod on loss
	fileCCBeta          = 0.0000015 // logarithmic rate increase factor (1.5 × 10^-6)
	fileCCMaxDecCount   = 5         // max rate decreases per congestion epoch
	fileCCLossThreshold = 20        // loss percentage × 10 below which we skip decrease (2.0%)
	fileCCShareFactor   = 0.03      // EWMA factor for avgNAKNum update
)

// FileCC implements the SRT file mode congestion controller.
// It uses a UDT-legacy AIMD algorithm with slow start, congestion avoidance,
// and loss-reactive rate adjustment.
type FileCC struct {
	mu sync.RWMutex

	// Congestion window and rate control
	cwnd      float64 // current CWND (packets)
	maxCWND   float64 // max CWND from flow control window
	sndPeriod float64 // inter-packet interval (microseconds)
	slowStart bool    // true during slow start phase

	// ACK tracking
	lastAck    uint32    // last ACK'd sequence number (initialized to ISN)
	lastRCTime time.Time // last rate control time for 10ms gate

	// Loss handling
	loss          bool    // loss occurred since last rate increase
	lastDecSeq    uint32  // seq number at last rate decrease
	lastDecPeriod float64 // sndPeriod at last decrease
	nakCount      int     // NAK counter in current epoch
	avgNAKNum     int     // average number of NAKs per congestion epoch
	decCount      int     // number of decreases in current epoch
	decRandom     int     // random threshold for decrease

	// Bandwidth/delivery rate tracking
	deliveryRate float64 // packets/sec from receiver ACK
	bwEstimate   float64 // probe-pair bandwidth (packets/sec)
	rtt          float64 // smoothed RTT (microseconds)

	// Sender tracking
	lastSentSeq uint32 // last sent sequence number (for epoch detection)

	// Loss list length — set by conn before OnNAK for the 2% threshold check.
	sndLossLength int

	// Configuration
	maxBW      int64 // max bandwidth (bytes/sec), 0 = unlimited
	overhead   int   // overhead percentage
	packetSize int   // payload size (bytes)

	// Probe pair estimation (shared with LiveCC)
	probe    probeEstimator
	delivery deliveryEstimator
}

// NewFileCC creates a new file mode congestion controller.
// isn is the initial sequence number (first packet to be sent).
// fc is the flow control window in packets (max CWND).
func NewFileCC(maxBW int64, packetSize int, fc int, isn uint32) *FileCC {
	if packetSize <= 0 {
		packetSize = DefaultPacketSize
	}
	if fc <= 0 {
		fc = 8192
	}
	cc := &FileCC{
		cwnd:          fileCCInitialCWND,
		maxCWND:       float64(fc),
		sndPeriod:     fileCCInitialPeriod,
		slowStart:     true,
		lastAck:       seq.Number(isn).Dec().Value(),       // ISN-1 (sender's current seqno before first send)
		lastDecSeq:    seq.Number(isn).Dec().Dec().Value(), // ISN-2 (one before lastAck)
		lastDecPeriod: fileCCInitialPeriod,
		decRandom:     1,
		lastRCTime:    time.Now(),
		maxBW:         maxBW,
		overhead:      DefaultOverhead,
		packetSize:    packetSize,
	}
	cc.probe.initProbeWindow(packetSize)
	cc.delivery.initDeliveryWindow(packetSize)
	return cc
}

// PacketInterval returns the inter-packet send interval in microseconds.
func (cc *FileCC) PacketInterval() clock.Microseconds {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	period := cc.sndPeriod
	if period < 1 {
		period = 1
	}
	return clock.Microseconds(period)
}

// OnACK processes an ACK from the receiver.
// In slow start: CWND grows by acked packet count, exits when CWND > maxCWND.
// In congestion avoidance: adjusts CWND and sndPeriod based on delivery rate.
func (cc *FileCC) OnACK(ackSeqNo uint32, rtt clock.Microseconds, bandwidth uint32, deliveryRate uint32) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Update RTT and bandwidth estimates (always, even if rate-limited)
	if rtt > 0 {
		cc.rtt = float64(rtt)
	}
	if bandwidth > 0 {
		cc.bwEstimate = float64(bandwidth)
	}
	if deliveryRate > 0 {
		cc.deliveryRate = float64(deliveryRate)
	}

	// Rate control interval gate: only adjust rates every 10ms.
	now := time.Now()
	if now.Sub(cc.lastRCTime).Microseconds() < fileCCRCInterval {
		return
	}
	cc.lastRCTime = now

	if cc.slowStart {
		// CWND += number of packets ACK'd since last ACK (inclusive count)
		acked := seqLen(cc.lastAck, ackSeqNo)
		if acked > 0 {
			cc.cwnd += float64(acked)
		}
		cc.lastAck = ackSeqNo

		// Exit slow start when CWND exceeds flow control window
		if cc.cwnd > cc.maxCWND {
			cc.slowStart = false
			cc.exitSlowStart()
		}
	} else {
		// Congestion avoidance: CWND = deliveryRate * (RTT + RCInterval) + 16
		if cc.deliveryRate > 0 {
			cc.cwnd = cc.deliveryRate/1_000_000*(cc.rtt+fileCCRCInterval) + 16
		}

		if cc.loss {
			// After loss, clear the flag — no rate increase this cycle
			cc.loss = false
		} else {
			// Rate increase: UDT AIAD algorithm
			cc.rateIncrease()
		}
	}

	// Enforce max bandwidth limit
	cc.enforceMaxBW()
}

// OnTimeout exits slow start if active.
func (cc *FileCC) OnTimeout() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.slowStart {
		cc.slowStart = false
		cc.exitSlowStart()
	}
	// In congestion avoidance, nothing happens (the aggressive doubling
	// of sndPeriod from legacy UDT is disabled).
}

// exitSlowStart sets the initial sending period when leaving slow start.
func (cc *FileCC) exitSlowStart() {
	if cc.deliveryRate > 0 {
		cc.sndPeriod = 1_000_000.0 / cc.deliveryRate
	} else if cc.rtt > 0 {
		cc.sndPeriod = cc.cwnd / (cc.rtt + fileCCRCInterval)
	}
}

// rateIncrease applies the UDT AIAD rate increase.
// Called in congestion avoidance when no loss has occurred.
func (cc *FileCC) rateIncrease() {
	if cc.sndPeriod <= 0 {
		return
	}

	// Calculate available bandwidth
	lossBW := 2.0 * (1_000_000.0 / cc.lastDecPeriod) // 2× last loss point rate
	bwPktPS := math.Min(lossBW, cc.bwEstimate)
	if bwPktPS <= 0 {
		bwPktPS = lossBW
	}

	B := bwPktPS - 1_000_000.0/cc.sndPeriod
	if cc.sndPeriod > cc.lastDecPeriod && bwPktPS/9.0 < B {
		B = bwPktPS / 9.0
	}

	var inc float64
	// MSS is the full wire packet size (payload + headers).
	mss := float64(cc.packetSize) + float64(WireHeaderSize)
	if mss <= float64(WireHeaderSize) {
		mss = float64(DefaultPacketSize) + float64(WireHeaderSize)
	}

	if B <= 0 {
		inc = 1.0 / mss
	} else {
		// inc = max(10^ceil(log10(B * MSS * 8)) * Beta / MSS, 1/MSS)
		inc = math.Pow(10.0, math.Ceil(math.Log10(B*mss*8.0))) * fileCCBeta / mss
		if inc < 1.0/mss {
			inc = 1.0 / mss
		}
	}

	// Update send period: sndPeriod = (sndPeriod * RCInterval) / (sndPeriod * inc + RCInterval)
	cc.sndPeriod = (cc.sndPeriod * fileCCRCInterval) / (cc.sndPeriod*inc + fileCCRCInterval)
}

// SetSndLossLength sets the total sender loss list length for the 2% threshold check.
// This should be called by the connection before OnNAK.
func (cc *FileCC) SetSndLossLength(n int) {
	cc.mu.Lock()
	cc.sndLossLength = n
	cc.mu.Unlock()
}

// OnNAK processes a loss report from the receiver.
// Exits slow start if active. In congestion avoidance, applies multiplicative
// decrease (sndPeriod *= 1.03) up to 5 times per congestion epoch.
func (cc *FileCC) OnNAK(lossSeqs []uint32) {
	if len(lossSeqs) == 0 {
		return
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Exit slow start on first loss
	if cc.slowStart {
		cc.slowStart = false
		cc.exitSlowStart()
	}

	cc.loss = true

	// Calculate loss percentage: pktsInFlight ≈ RTT / sndPeriod
	if cc.sndPeriod > 0 && cc.rtt > 0 {
		pktsInFlight := cc.rtt / cc.sndPeriod
		if pktsInFlight > 0 {
			// Use the total sender loss list length for the threshold check
			numLost := cc.sndLossLength
			lostPctX10 := float64(numLost) * 1000.0 / pktsInFlight
			if lostPctX10 < fileCCLossThreshold {
				// Loss below 2%: record but don't decrease
				cc.lastDecPeriod = cc.sndPeriod
				return
			}
		}
	}

	lossBegin := lossSeqs[0]

	if seqCmp(lossBegin, cc.lastDecSeq) > 0 {
		// New congestion epoch
		cc.lastDecPeriod = cc.sndPeriod
		cc.sndPeriod = math.Ceil(cc.sndPeriod * fileCCLossIncrease)

		cc.avgNAKNum = int(math.Ceil(float64(cc.avgNAKNum)*(1-fileCCShareFactor) + float64(cc.nakCount)*fileCCShareFactor))
		cc.nakCount = 1
		cc.decCount = 1
		cc.lastDecSeq = cc.lastSentSeq

		if cc.avgNAKNum > 1 {
			// Random threshold in [1, avgNAKNum] inclusive
			cc.decRandom = rand.Intn(cc.avgNAKNum) + 1
		} else {
			cc.decRandom = 1
		}
	} else {
		// Within epoch: post-increment decCount, pre-increment nakCount.
		// Short-circuit: if decCount >= 5, don't evaluate or increment nakCount.
		if cc.decCount < fileCCMaxDecCount {
			cc.decCount++ // always increment (post-increment semantics)
			cc.nakCount++ // always increment when decCount check passes (pre-increment semantics)
			if cc.decRandom > 0 && cc.nakCount%cc.decRandom == 0 {
				// Periodic slowdown within congestion epoch
				cc.sndPeriod = math.Ceil(cc.sndPeriod * fileCCLossIncrease)
				cc.lastDecSeq = cc.lastSentSeq
			}
		}
	}

	cc.enforceMaxBW()
}

// enforceMaxBW clamps the sending rate to the configured maximum bandwidth.
// minSP = 1e6 / (maxBW / MSS), where MSS is the full wire packet size
// (payload + IP/UDP/SRT headers).
func (cc *FileCC) enforceMaxBW() {
	if cc.maxBW <= 0 {
		return
	}
	mss := float64(cc.packetSize) + float64(WireHeaderSize)
	if mss <= float64(WireHeaderSize) {
		mss = float64(DefaultPacketSize) + float64(WireHeaderSize)
	}
	// minSP = 1e6 / (maxBW_bytes_per_sec / MSS_bytes_per_pkt)
	minSP := 1_000_000.0 / (float64(cc.maxBW) / mss)
	if cc.sndPeriod < minSP {
		cc.sndPeriod = minSP
	}
}

// OnPacketSent is called when a data packet is sent.
func (cc *FileCC) OnPacketSent(seqNo uint32, size int) {
	cc.mu.Lock()
	cc.lastSentSeq = seqNo
	cc.probe.onPacketSent(seqNo)
	cc.mu.Unlock()
}

// OnPacketReceived processes a received non-retransmitted data packet for
// probe-pair link capacity estimation.
func (cc *FileCC) OnPacketReceived(seqNo uint32, size int, arrivalTime clock.Timestamp) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.probe.onPacketReceived(seqNo, size, arrivalTime)
}

// OnPktArrival records the arrival of ANY data packet (including retransmitted)
// for overall delivery rate estimation.
func (cc *FileCC) OnPktArrival(size int, arrivalTime clock.Timestamp) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.delivery.onPktArrival(size, arrivalTime)
}

// IsProbePacket returns true if the last sent packet was the first of a probe pair.
func (cc *FileCC) IsProbePacket() bool {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.probe.isProbePacket()
}

// EstimatedBandwidth returns the link capacity estimate from probe pair
// measurements, in packets per second.
func (cc *FileCC) EstimatedBandwidth() uint32 {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.probe.estimatedBandwidth()
}

// DeliveryRate returns the overall packet delivery rate from ALL received
// packets. pktRate is packets/sec, bytesRate is bytes/sec (including headers).
func (cc *FileCC) DeliveryRate() (pktRate uint32, bytesRate uint32) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.delivery.getPktRcvSpeed()
}

// CongestionWindow returns the current congestion window in packets.
func (cc *FileCC) CongestionWindow() int {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	cwnd := int(cc.cwnd)
	if cwnd < 2 {
		cwnd = 2
	}
	return cwnd
}

// MinNAKInterval returns 0 for FileCC — use core default 300ms.
// Periodic NAK is disabled in file mode anyway (periodicNAK=false).
func (cc *FileCC) MinNAKInterval() clock.Microseconds {
	return 0
}

// UpdateNAKInterval returns the interval unchanged for FileCC.
// File mode disables periodic NAK, so this is unused in practice.
// rcvSpeed and lossLength are passed for future CC extensibility.
func (cc *FileCC) UpdateNAKInterval(nakIntUS int64, rcvSpeed int, lossLength int) int64 {
	return nakIntUS
}

// CheckTransArgs accepts all API modes for file mode (no restrictions).
func (cc *FileCC) CheckTransArgs(msgAPI bool, size int, isWrite bool) error {
	return nil
}

// ACKMaxPackets returns 0 — FileCC uses timer-based ACK only.
func (cc *FileCC) ACKMaxPackets() int { return 0 }

// ACKTimeoutUS returns 0 — FileCC uses the default 10ms SYN interval.
func (cc *FileCC) ACKTimeoutUS() int64 { return 0 }

// SetMaxBandwidth updates the maximum sending bandwidth (bytes/sec).
func (cc *FileCC) SetMaxBandwidth(bw int64) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.maxBW = bw
}

// SetOverhead sets the bandwidth overhead percentage.
func (cc *FileCC) SetOverhead(pct int) {
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

// UpdateBandwidth is a no-op for FileCC — bandwidth is AIMD-controlled.
func (cc *FileCC) UpdateBandwidth(_, _ int64) {}

// MaxBandwidth returns the configured max bandwidth.
func (cc *FileCC) MaxBandwidth() int64 {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.maxBW
}

// seqLen returns the number of packets from seq1 to seq2 inclusive,
// with 31-bit wrapping:
//
//	(seq2 - seq1 + 0x80000000) & 0x7FFFFFFF
func seqLen(seq1, seq2 uint32) int {
	return int((seq2 - seq1 + 0x80000000) & 0x7FFFFFFF)
}

// seqCmp compares two sequence numbers with wrapping.
// Returns positive if a > b, negative if a < b, 0 if equal.
func seqCmp(a, b uint32) int {
	return int(int32(a) - int32(b))
}
