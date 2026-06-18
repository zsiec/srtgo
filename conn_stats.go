package srt

import (
	"time"

	"github.com/zsiec/srtgo/internal/core"
)

// ConnStats is a snapshot of a connection's statistics. Field names and types
// mirror the legacy public API. NOTE (cutover, in progress): the fields the
// Sans-I/O core exposes today are populated; the derived/aggregated fields
// (Mbps rates, *-with-header byte totals, ms-buffer timings, reorder/belated,
// interval/clear semantics, OnStats, StartTime/Duration) are not yet wired and
// read zero. These are filled in a later cutover step.
type ConnStats struct {
	// Timing
	StartTime time.Time
	Duration  time.Duration

	// Sent packet/byte counters
	SentPackets       uint64
	SentBytes         uint64
	SentUniquePackets uint64
	SentUniqueBytes   uint64
	Retransmits       uint64
	RetransBytes      uint64

	// Received packet/byte counters
	RecvPackets       uint64
	RecvBytes         uint64
	RecvUniquePackets uint64
	RecvUniqueBytes   uint64
	RecvRetrans       uint64
	RecvRetransBytes  uint64

	// Loss
	LostPackets  uint64
	RecvLoss     uint64
	SendLossRate float64
	RecvLossRate float64

	// Total bytes including IP/UDP/SRT header overhead (44 bytes per packet)
	SentTotalBytes          uint64
	RecvTotalBytes          uint64
	SentUniqueTotalBytes    uint64
	RecvUniqueTotalBytes    uint64
	RecvLossBytes           uint64
	RetransTotalBytes       uint64
	RecvRetransTotalBytes   uint64
	SentDropTotalBytes      uint64
	RecvDropTotalBytes      uint64
	RecvBelatedTotalBytes   uint64
	RecvUndecryptTotalBytes uint64

	// Bitrates (interval mode)
	MbpsSendRate float64
	MbpsRecvRate float64

	// RTT
	RTT       time.Duration
	RTTVar    time.Duration
	RTTFactor float64

	// Flight and buffer state
	FlowWindow       int
	FlightSize       int
	SendBufSize      int
	SendBufAvailable int
	SendBufBytes     int
	RecvBufSize      int
	RecvBufAvailable int
	RecvBufBytes     int

	// Instantaneous measurements
	NegotiatedLatency  time.Duration
	PacketReceiveRate  uint32
	EstimatedBandwidth uint32
	UsPktSndPeriod     float64
	MbpsMaxBW          float64
	MsSndBuf           time.Duration
	MsRcvBuf           time.Duration

	// Control packet counters
	SentACKs    uint64
	SentNAKs    uint64
	SentACKACKs uint64
	RecvACKs    uint64
	RecvNAKs    uint64
	RecvACKACKs uint64

	// Receiver-side counters
	RecvDropped        uint64
	RecvDroppedBytes   uint64
	RecvBelated        uint64
	RecvBelatedBytes   uint64
	RecvUndecrypt      uint64
	RecvUndecryptBytes uint64

	// Sender-side counters
	SentDropped      uint64
	SentDroppedBytes uint64

	// Key management
	SentKM     uint64
	RecvKM     uint64
	SndKmState int
	RcvKmState int

	// Sender duration and congestion
	UsSndDuration    int64
	CongestionWindow int

	// Reorder tracking
	ReorderTolerance int32
	ReorderDistance  int32

	// Belated arrival timing
	RcvAvgBelatedTime time.Duration

	// FEC statistics
	SndFilterExtra  uint64
	RcvFilterExtra  uint64
	RcvFilterSupply uint64
	RcvFilterLoss   uint64

	// Negotiated parameters
	NegotiatedMSS   int
	NegotiatedFC    int
	MsSndTsbPdDelay time.Duration
	MsRcvTsbPdDelay time.Duration
}

// Stats returns a snapshot of the connection's statistics. The clear flag
// (interval-vs-total) is not yet honored — totals are always returned.
// TODO(cutover): interval/clear semantics + OnStats.
func (c *Conn) Stats(clear bool) ConnStats {
	s, err := c.s.Stats()
	if err != nil {
		return ConnStats{}
	}
	return statsFromCore(s, c.cfg)
}

func statsFromCore(s core.Stats, cfg Config) ConnStats {
	st := ConnStats{
		SentPackets:       s.SentPackets,
		SentBytes:         s.SentBytes,
		SentUniquePackets: s.SentUniquePackets,
		SentUniqueBytes:   s.SentUniqueBytes,
		Retransmits:       s.RetransPackets,
		RetransBytes:      s.RetransBytes,

		RecvPackets:       s.RecvPackets,
		RecvBytes:         s.RecvBytes,
		RecvUniquePackets: s.RecvUniquePackets,
		RecvUniqueBytes:   s.RecvUniqueBytes,
		RecvRetrans:       s.RecvRetrans,
		RecvRetransBytes:  s.RecvRetransBytes,

		LostPackets:   s.LostPackets,
		RecvLoss:      s.RecvLoss,
		RecvDropped:   s.RecvDropped,
		RecvUndecrypt: s.RecvUndecrypt,

		SentDropped:      s.SentDropped,
		SentDroppedBytes: s.SentDroppedBytes,

		SentACKs:    s.SentACKs,
		SentNAKs:    s.SentNAKs,
		SentACKACKs: s.SentACKACKs,
		RecvACKs:    s.RecvACKs,
		RecvNAKs:    s.RecvNAKs,
		RecvACKACKs: s.RecvACKACKs,

		SentKM:     s.SentKM,
		RecvKM:     s.RecvKM,
		SndKmState: int(s.SndKmState),
		RcvKmState: int(s.RcvKmState),

		RTT:    time.Duration(s.RTTMicros) * time.Microsecond,
		RTTVar: time.Duration(s.RTTVarMicros) * time.Microsecond,

		FlowWindow:       s.FlowWindow,
		FlightSize:       s.FlightSize,
		SendBufSize:      s.SendBufPackets,
		SendBufAvailable: s.SendBufAvailable,
		RecvBufSize:      s.RecvBufPackets,
		RecvBufAvailable: s.RecvBufAvailable,
		CongestionWindow: s.CongestionWindow,

		NegotiatedLatency:  time.Duration(s.NegotiatedLatency) * time.Microsecond,
		PacketReceiveRate:  s.PacketRecvRate,
		EstimatedBandwidth: s.EstimatedBandwidth,
		UsPktSndPeriod:     float64(s.PktSndPeriodMicros),

		SndFilterExtra:  s.SentFEC,
		RcvFilterSupply: s.RecvFECRecov,

		ReorderTolerance: int32(cfg.LossMaxTTL),
		NegotiatedMSS:    cfg.MSS,
		NegotiatedFC:     s.FlowWindow,
	}
	if st.NegotiatedLatency > 0 {
		st.RTTFactor = float64(st.RTT) / float64(st.NegotiatedLatency)
	}
	return st
}
