package srt

import (
	"time"

	"github.com/zsiec/srtgo/internal/core"
)

// ConnStats is a snapshot of a connection's statistics. Field names and types
// mirror the legacy public API. NOTE (cutover, in progress): the fields the
// Sans-I/O core exposes are populated, including the derived fields (header-byte
// totals, loss rates, interval Mbps, StartTime/Duration) and the belated/reorder/
// ms-buffer instrumentation.
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

// Stats returns a snapshot of the connection's statistics. Packet/byte counters
// are cumulative; the Mbps interval rates are computed over the window since the
// previous clear=true call, which also resets that window.
func (c *Conn) Stats(clear bool) ConnStats {
	s, err := c.s.Stats()
	if err != nil {
		return ConnStats{}
	}
	st := statsFromCore(s, c.cfg)
	st.StartTime = c.startTime
	st.Duration = time.Since(c.startTime)
	const hdr = 44 // IP(20) + UDP(8) + SRT(16) per packet

	// Header-inclusive byte totals.
	st.SentTotalBytes = st.SentBytes + st.SentPackets*hdr
	st.RecvTotalBytes = st.RecvBytes + st.RecvPackets*hdr
	st.SentUniqueTotalBytes = st.SentUniqueBytes + st.SentUniquePackets*hdr
	st.RecvUniqueTotalBytes = st.RecvUniqueBytes + st.RecvUniquePackets*hdr
	st.RetransTotalBytes = st.RetransBytes + st.Retransmits*hdr
	st.RecvRetransTotalBytes = st.RecvRetransBytes + st.RecvRetrans*hdr
	st.SentDropTotalBytes = st.SentDroppedBytes + st.SentDropped*hdr

	// Loss rates.
	if st.SentPackets > 0 {
		st.SendLossRate = float64(st.LostPackets) / float64(st.SentPackets) * 100
	}
	if denom := st.RecvPackets + st.RecvDropped; denom > 0 {
		st.RecvLossRate = float64(st.RecvDropped) / float64(denom) * 100
	}
	st.MbpsMaxBW = float64(c.cfg.MaxBW) * 8 / 1e6

	// Fields the core surfaces directly.
	st.RecvBelated = s.RecvBelated
	st.RecvBelatedBytes = s.RecvBelatedBytes
	st.RecvBelatedTotalBytes = s.RecvBelatedBytes + s.RecvBelated*hdr
	st.RcvAvgBelatedTime = time.Duration(s.AvgBelatedMicros) * time.Microsecond
	st.ReorderDistance = s.ReorderDistance
	st.MsSndBuf = time.Duration(s.MsSndBuf) * time.Microsecond
	st.MsRcvBuf = time.Duration(s.MsRcvBuf) * time.Microsecond

	// Interval Mbps rates over the window since the last clear=true.
	c.statsMu.Lock()
	dt := time.Since(c.clearAt).Seconds()
	if dt > 0 {
		st.MbpsSendRate = float64(st.SentBytes-c.clearSntBytes) * 8 / 1e6 / dt
		st.MbpsRecvRate = float64(st.RecvBytes-c.clearRcvBytes) * 8 / 1e6 / dt
	}
	if clear {
		c.clearAt = time.Now()
		c.clearSntBytes = st.SentBytes
		c.clearRcvBytes = st.RecvBytes
	}
	c.statsMu.Unlock()
	return st
}

// OnStats registers a callback invoked periodically (every interval, min ~10ms)
// with interval statistics (Stats(true)). Pass a nil fn to stop. The callback
// stops automatically when the connection is closed.
func (c *Conn) OnStats(interval time.Duration, fn func(ConnStats)) {
	c.statsMu.Lock()
	if c.onStatsStop != nil {
		close(c.onStatsStop)
		c.onStatsStop = nil
	}
	if fn == nil {
		c.statsMu.Unlock()
		return
	}
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	stop := make(chan struct{})
	c.onStatsStop = stop
	c.statsMu.Unlock()

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				fn(c.Stats(true))
			}
		}
	}()
}

// ExtendedConnStats is ConnStats plus smoothed buffer occupancy and send rate.
type ExtendedConnStats struct {
	ConnStats
	AvgSndBufPkts  float64
	AvgSndBufBytes float64
	AvgRcvBufPkts  float64
	AvgRcvBufBytes float64
	SendRatePps    int64
	SendRateBps    int64
}

// ExtendedStats returns Stats plus IIR-smoothed buffer occupancy and the
// measured send rate. The averages use an 8-tap IIR updated on each call
// (avg = avg*7/8 + current/8), seeded on the first call — so they smooth when
// ExtendedStats is polled periodically.
func (c *Conn) ExtendedStats(clear bool) ExtendedConnStats {
	base := c.Stats(clear)
	pps, bps := c.SendRate()

	iir := func(avg *float64, cur float64) float64 {
		*avg = *avg*7/8 + cur/8
		return *avg
	}
	c.extMu.Lock()
	if !c.extInit {
		c.extInit = true
		c.avgSndPkts, c.avgSndBytes = float64(base.SendBufSize), float64(base.SendBufBytes)
		c.avgRcvPkts, c.avgRcvBytes = float64(base.RecvBufSize), float64(base.RecvBufBytes)
	}
	ext := ExtendedConnStats{
		ConnStats:      base,
		AvgSndBufPkts:  iir(&c.avgSndPkts, float64(base.SendBufSize)),
		AvgSndBufBytes: iir(&c.avgSndBytes, float64(base.SendBufBytes)),
		AvgRcvBufPkts:  iir(&c.avgRcvPkts, float64(base.RecvBufSize)),
		AvgRcvBufBytes: iir(&c.avgRcvBytes, float64(base.RecvBufBytes)),
		SendRatePps:    pps,
		SendRateBps:    bps,
	}
	c.extMu.Unlock()
	return ext
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
