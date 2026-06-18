// Package congestion provides congestion control for SRT.
//
// SRT supports two congestion control modes:
//   - LiveCC: fixed-rate pacer for live streaming (low latency)
//   - FileCC: CUBIC-like adaptive CC for bulk file transfer (high throughput)
//
// Both use probe pairs for bandwidth estimation: every 16th packet pair
// is sent back-to-back, and the receiver measures inter-arrival time
// to estimate link capacity.
package congestion

import (
	"github.com/zsiec/srtgo/internal/clock"
)

// Controller is the interface for congestion control algorithms.
type Controller interface {
	// PacketInterval returns the inter-packet sending interval in microseconds.
	// The sender should pace packets at this rate.
	PacketInterval() clock.Microseconds

	// OnACK is called when an ACK is received. It reads the wall clock for
	// FileCC's rate-control gate; deliveryRate is the receiver's packet arrival
	// rate (packets/sec) and bandwidth the probe-estimated link capacity.
	OnACK(ackSeqNo uint32, rtt clock.Microseconds, bandwidth uint32, deliveryRate uint32)

	// OnACKAt is OnACK driven by an injected clock instead of the wall clock, so
	// the controller is a deterministic function of its inputs. The Sans-I/O core
	// calls this (passing the loop's now); the legacy path uses OnACK. After the
	// legacy cutover the two collapse into one.
	OnACKAt(now clock.Timestamp, ackSeqNo uint32, rtt clock.Microseconds, bandwidth uint32, deliveryRate uint32)

	// OnNAK is called when a loss report (NAK) is received.
	// lossSeqs contains the lost sequence numbers for epoch detection.
	OnNAK(lossSeqs []uint32)

	// OnTimeout is called when a retransmission timeout fires.
	// FileCC uses this to exit slow start. LiveCC is a no-op.
	OnTimeout()

	// OnPacketSent is called when a data packet is sent.
	OnPacketSent(seqNo uint32, size int)

	// OnPacketReceived is called when a non-retransmitted data packet is received.
	// Probe pairs (every 16th→17th packet) are used for link capacity estimation.
	OnPacketReceived(seqNo uint32, size int, arrivalTime clock.Timestamp)

	// OnPktArrival records the arrival of ANY data packet (including retransmitted)
	// for overall delivery rate estimation.
	OnPktArrival(size int, arrivalTime clock.Timestamp)

	// SetMaxBandwidth updates the maximum sending bandwidth in bytes/sec.
	SetMaxBandwidth(bw int64)

	// SetOverhead sets the bandwidth overhead percentage (0-100).
	SetOverhead(pct int)

	// IsProbePacket returns true if the last sent packet was the first of
	// a probe pair (seqNo%16==0), meaning the next packet should be sent
	// immediately (back-to-back) for bandwidth measurement.
	IsProbePacket() bool

	// EstimatedBandwidth returns the link capacity estimate from probe pair
	// measurements, in packets per second.
	EstimatedBandwidth() uint32

	// DeliveryRate returns the overall packet delivery rate from ALL received
	// packets. pktRate is packets/sec, bytesRate is bytes/sec (including headers).
	DeliveryRate() (pktRate uint32, bytesRate uint32)

	// UpdateBandwidth updates the sending bandwidth.
	// If maxBW > 0, use it directly. If maxBW == 0 and inputBW > 0, use inputBW.
	UpdateBandwidth(maxBW, inputBW int64)

	// MaxBandwidth returns the configured max bandwidth in bytes/sec.
	MaxBandwidth() int64

	// CongestionWindow returns the congestion window in packets.
	// LiveCC returns math.MaxInt (no CWND limit — FC controls flow).
	// FileCC returns the adaptive CWND.
	CongestionWindow() int

	// MinNAKInterval returns the CC-specific minimum NAK report interval
	// in microseconds.
	// LiveCC returns 20000 (20ms). FileCC returns 0 (use core default 300ms).
	// The core will override its initial 300ms minimum with this value
	// if non-zero.
	MinNAKInterval() clock.Microseconds

	// UpdateNAKInterval adjusts the NAK report interval per the CC algorithm.
	// The base interval (RTT+4*RTTVar in µs) is passed in.
	// rcvSpeed is the receiver packet delivery rate (packets/sec) and lossLength
	// is the total loss list length. Both are passed for future CC extensibility;
	// LiveCC and FileCC currently ignore them.
	// LiveCC divides by 2 (NAK report acceleration).
	// FileCC returns it unchanged (periodic NAK disabled in file mode anyway).
	UpdateNAKInterval(nakIntUS int64, rcvSpeed int, lossLength int) int64

	// CheckTransArgs validates API compatibility before every send/recv.
	// msgAPI indicates whether message API is in use (vs stream/buffer API).
	// size is the payload length for sends or the buffer length for receives.
	// isWrite is true for the send direction, false for receive.
	// Returns nil if allowed, or an error describing the incompatibility.
	CheckTransArgs(msgAPI bool, size int, isWrite bool) error

	// ACKMaxPackets returns the CC-specific maximum number of packets to receive
	// before triggering an ACK. Returns 0 to use the default (timer-based) logic.
	ACKMaxPackets() int

	// ACKTimeoutUS returns the CC-specific ACK interval in microseconds.
	// Returns 0 to use the default 10ms SYN interval.
	ACKTimeoutUS() int64
}
