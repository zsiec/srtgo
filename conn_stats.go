package srt

import (
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/packet"
)

// headerOverhead is the combined IP + UDP + SRT header size per packet.
const headerOverhead = packet.WireHeaderSize

// Stats returns connection statistics. If clear is true, the returned stats
// represent the interval since the last clear=true call, and internal interval
// counters are reset. If clear is false, cumulative totals are returned.
// This matches the srt_bistats(sock, &perf, clear, instantaneous) API.
func (c *Conn) Stats(clear bool) ConnStats {
	stats := c.buildTotalStats()

	if clear {
		c.statsMu.Lock()
		interval := c.computeInterval(stats)
		c.updateSnapshot(stats)
		c.statsMu.Unlock()
		return interval
	}
	return stats
}

// buildTotalStats computes cumulative totals from atomic counters.
func (c *Conn) buildTotalStats() ConnStats {
	bw := c.sendCC.EstimatedBandwidth()
	pktRate, _ := c.sendCC.DeliveryRate()
	flightSize := c.flightSize()

	sentPackets := c.sentPackets.Load()
	sentBytes := c.sentBytes.Load()
	retransmits := c.retransCount.Load()
	retransBytes := c.retransBytes.Load()
	recvPackets := c.recvPackets.Load()
	recvBytes := c.recvBytes.Load()
	recvRetrans := c.recvRetrans.Load()
	recvRetransBytes := c.recvRetransBytes.Load()
	lostPackets := c.lostPackets.Load()
	recvLoss := c.recvLoss.Load()
	recvDropped := c.recvDropped.Load()
	recvDroppedBytes := c.recvDroppedBytes.Load()
	sentDropped := c.sentDropped.Load()
	sentDroppedBytes := c.sentDroppedBytes.Load()
	recvBelated := c.recvBelated.Load()
	recvBelatedBytes := c.recvBelatedBytes.Load()
	recvUndecrypt := c.recvUndecrypt.Load()
	recvUndecryptBytes := c.recvUndecryptBytes.Load()

	// Unique vs retransmit breakdown
	sentUniquePackets := sentPackets - retransmits
	sentUniqueBytes := sentBytes - retransBytes
	recvUniquePackets := recvPackets - recvRetrans
	recvUniqueBytes := recvBytes - recvRetransBytes

	// Loss rates (as percentages)
	var sendLossRate float64
	if sentPackets > 0 {
		sendLossRate = float64(lostPackets) / float64(sentPackets) * 100
	}
	var recvLossRate float64
	if total := recvPackets + recvDropped; total > 0 {
		recvLossRate = float64(recvDropped) / float64(total) * 100
	}

	// Total bytes including header overhead per packet (matches byteSentTotal semantics)
	h := uint64(headerOverhead)
	sentTotalBytes := sentBytes + sentPackets*h
	recvTotalBytes := recvBytes + recvPackets*h

	// RTT factor
	rtt := time.Duration(c.rtt.Load()) * time.Microsecond
	latency := c.tsbpdDelay.Duration()
	var rttFactor float64
	if latency > 0 {
		rttFactor = float64(rtt) / float64(latency)
	}

	// Buffer state
	sendBufSize := c.sendBuf.Size()
	recvBufSize := c.recvBuf.Size()

	// Send buffer age: time since oldest unacked packet was sent
	var msSndBuf time.Duration
	if oldest := c.sendBuf.OldestSendTime(); !oldest.IsZero() {
		msSndBuf = c.clk.Now().Sub(oldest).Duration()
	}

	// Recv buffer timespan estimate: recvBufSize packets at the negotiated pacing rate
	var msRcvBuf time.Duration
	if pktRate > 0 && recvBufSize > 0 {
		msRcvBuf = time.Duration(float64(recvBufSize)/float64(pktRate)*1e9) * time.Nanosecond
	}

	// Instantaneous congestion controller metrics
	sndPeriod := float64(c.sendCC.PacketInterval())
	maxBW := float64(c.sendCC.MaxBandwidth()) * 8 / 1_000_000 // bytes/sec → Mbps

	// Sender duration: accumulated + currently pending busy span
	sndDuration := c.sndDurationUs.Load()
	if busySince := c.sndBusySince.Load(); busySince != 0 {
		pending := c.clk.Now().Sub(clock.Timestamp(busySince))
		sndDuration += int64(pending)
	}

	// Average belated arrival time (EWMA)
	avgBelatedTime := time.Duration(c.recvBelatedTimeAvg.Load()) * time.Microsecond

	// Key management state: tracked atomically/ m_RcvKmState.
	// Values: 0=unsecured, 1=securing, 2=secured, 3=nosecret, 4=badsecret, 5=badcryptomode
	sndKmState := int(c.sndKmState.Load())
	rcvKmState := int(c.rcvKmState.Load())

	return ConnStats{
		StartTime:               c.startTime,
		Duration:                time.Since(c.startTime),
		SentPackets:             sentPackets,
		SentBytes:               sentBytes,
		SentUniquePackets:       sentUniquePackets,
		SentUniqueBytes:         sentUniqueBytes,
		Retransmits:             retransmits,
		RetransBytes:            retransBytes,
		RecvPackets:             recvPackets,
		RecvBytes:               recvBytes,
		RecvUniquePackets:       recvUniquePackets,
		RecvUniqueBytes:         recvUniqueBytes,
		RecvRetrans:             recvRetrans,
		RecvRetransBytes:        recvRetransBytes,
		LostPackets:             lostPackets,
		RecvLoss:                recvLoss,
		SendLossRate:            sendLossRate,
		RecvLossRate:            recvLossRate,
		SentTotalBytes:          sentTotalBytes,
		RecvTotalBytes:          recvTotalBytes,
		SentUniqueTotalBytes:    sentUniqueBytes + sentUniquePackets*h,
		RecvUniqueTotalBytes:    recvUniqueBytes + recvUniquePackets*h,
		RecvLossBytes:           recvLoss * (uint64(c.payloadSize) + h),
		RetransTotalBytes:       retransBytes + retransmits*h,
		RecvRetransTotalBytes:   recvRetransBytes + recvRetrans*h,
		SentDropTotalBytes:      sentDroppedBytes + sentDropped*h,
		RecvDropTotalBytes:      recvDroppedBytes + recvDropped*h,
		RecvBelatedTotalBytes:   recvBelatedBytes + recvBelated*h,
		RecvUndecryptTotalBytes: recvUndecryptBytes + recvUndecrypt*h,
		RTT:                     rtt,
		RTTVar:                  time.Duration(c.rttVar.Load()) * time.Microsecond,
		RTTFactor:               rttFactor,
		FlowWindow:              c.currentFlowWindow(),
		FlightSize:              flightSize,
		SendBufSize:             sendBufSize,
		SendBufAvailable:        c.sendBuf.Available(),
		SendBufBytes:            sendBufSize * c.payloadSize,
		RecvBufSize:             recvBufSize,
		RecvBufAvailable:        c.recvBuf.Capacity() - recvBufSize,
		RecvBufBytes:            recvBufSize * c.payloadSize,
		NegotiatedLatency:       latency,
		PacketReceiveRate:       pktRate,
		EstimatedBandwidth:      bw,
		UsPktSndPeriod:          sndPeriod,
		MbpsMaxBW:               maxBW,
		MsSndBuf:                msSndBuf,
		MsRcvBuf:                msRcvBuf,
		SentACKs:                c.sentACKs.Load(),
		SentNAKs:                c.sentNAKs.Load(),
		SentACKACKs:             c.sentACKACKs.Load(),
		RecvACKs:                c.recvACKs.Load(),
		RecvNAKs:                c.recvNAKs.Load(),
		RecvACKACKs:             c.recvACKACKs.Load(),
		RecvDropped:             recvDropped,
		RecvDroppedBytes:        recvDroppedBytes,
		RecvBelated:             recvBelated,
		RecvBelatedBytes:        recvBelatedBytes,
		RecvUndecrypt:           recvUndecrypt,
		RecvUndecryptBytes:      recvUndecryptBytes,
		SentDropped:             sentDropped,
		SentDroppedBytes:        sentDroppedBytes,
		SentKM:                  c.sentKM.Load(),
		RecvKM:                  c.recvKM.Load(),
		SndKmState:              sndKmState,
		RcvKmState:              rcvKmState,
		UsSndDuration:           sndDuration,
		CongestionWindow:        c.sendCC.CongestionWindow(),
		ReorderTolerance:        int32(c.reorderTolerance),
		ReorderDistance:         c.reorderDistance.Load(),
		RcvAvgBelatedTime:       avgBelatedTime,
		SndFilterExtra:          c.sndFilterExtra.Load(),
		RcvFilterExtra:          c.rcvFilterExtra.Load(),
		RcvFilterSupply:         c.rcvFilterSupply.Load(),
		RcvFilterLoss:           c.rcvFilterLoss.Load(),
		NegotiatedMSS:           c.payloadSize + headerOverhead,
		NegotiatedFC:            c.fc,
		MsSndTsbPdDelay:         c.peerTsbpdDelay.Duration(),
		MsRcvTsbPdDelay:         latency,
	}
}

// computeInterval returns the difference between current stats and the last snapshot.
// Cumulative counters are subtracted; instantaneous fields are copied as-is.
func (c *Conn) computeInterval(current ConnStats) ConnStats {
	last := c.lastSnapshot

	// Compute interval bitrates (Mbps) from delta bytes and elapsed time
	elapsed := current.Duration - last.Duration
	var mbpsSend, mbpsRecv float64
	if elapsed > 0 {
		sec := elapsed.Seconds()
		mbpsSend = float64(current.SentTotalBytes-last.SentTotalBytes) * 8 / 1_000_000 / sec
		mbpsRecv = float64(current.RecvTotalBytes-last.RecvTotalBytes) * 8 / 1_000_000 / sec
	}

	return ConnStats{
		StartTime: current.StartTime,
		Duration:  current.Duration,
		// Cumulative counter deltas
		SentPackets:             current.SentPackets - last.SentPackets,
		SentBytes:               current.SentBytes - last.SentBytes,
		SentUniquePackets:       current.SentUniquePackets - last.SentUniquePackets,
		SentUniqueBytes:         current.SentUniqueBytes - last.SentUniqueBytes,
		Retransmits:             current.Retransmits - last.Retransmits,
		RetransBytes:            current.RetransBytes - last.RetransBytes,
		RecvPackets:             current.RecvPackets - last.RecvPackets,
		RecvBytes:               current.RecvBytes - last.RecvBytes,
		RecvUniquePackets:       current.RecvUniquePackets - last.RecvUniquePackets,
		RecvUniqueBytes:         current.RecvUniqueBytes - last.RecvUniqueBytes,
		RecvRetrans:             current.RecvRetrans - last.RecvRetrans,
		RecvRetransBytes:        current.RecvRetransBytes - last.RecvRetransBytes,
		LostPackets:             current.LostPackets - last.LostPackets,
		RecvLoss:                current.RecvLoss - last.RecvLoss,
		SendLossRate:            current.SendLossRate, // instantaneous rate
		RecvLossRate:            current.RecvLossRate, // instantaneous rate
		SentTotalBytes:          current.SentTotalBytes - last.SentTotalBytes,
		RecvTotalBytes:          current.RecvTotalBytes - last.RecvTotalBytes,
		SentUniqueTotalBytes:    current.SentUniqueTotalBytes - last.SentUniqueTotalBytes,
		RecvUniqueTotalBytes:    current.RecvUniqueTotalBytes - last.RecvUniqueTotalBytes,
		RecvLossBytes:           current.RecvLossBytes - last.RecvLossBytes,
		RetransTotalBytes:       current.RetransTotalBytes - last.RetransTotalBytes,
		RecvRetransTotalBytes:   current.RecvRetransTotalBytes - last.RecvRetransTotalBytes,
		SentDropTotalBytes:      current.SentDropTotalBytes - last.SentDropTotalBytes,
		RecvDropTotalBytes:      current.RecvDropTotalBytes - last.RecvDropTotalBytes,
		RecvBelatedTotalBytes:   current.RecvBelatedTotalBytes - last.RecvBelatedTotalBytes,
		RecvUndecryptTotalBytes: current.RecvUndecryptTotalBytes - last.RecvUndecryptTotalBytes,
		MbpsSendRate:            mbpsSend,
		MbpsRecvRate:            mbpsRecv,
		// Instantaneous fields — copied as-is
		RTT:                current.RTT,
		RTTVar:             current.RTTVar,
		RTTFactor:          current.RTTFactor,
		FlowWindow:         current.FlowWindow,
		FlightSize:         current.FlightSize,
		SendBufSize:        current.SendBufSize,
		SendBufAvailable:   current.SendBufAvailable,
		SendBufBytes:       current.SendBufBytes,
		RecvBufSize:        current.RecvBufSize,
		RecvBufAvailable:   current.RecvBufAvailable,
		RecvBufBytes:       current.RecvBufBytes,
		NegotiatedLatency:  current.NegotiatedLatency,
		PacketReceiveRate:  current.PacketReceiveRate,
		EstimatedBandwidth: current.EstimatedBandwidth,
		UsPktSndPeriod:     current.UsPktSndPeriod,
		MbpsMaxBW:          current.MbpsMaxBW,
		MsSndBuf:           current.MsSndBuf,
		MsRcvBuf:           current.MsRcvBuf,
		// Control counter deltas
		SentACKs:           current.SentACKs - last.SentACKs,
		SentNAKs:           current.SentNAKs - last.SentNAKs,
		SentACKACKs:        current.SentACKACKs - last.SentACKACKs,
		RecvACKs:           current.RecvACKs - last.RecvACKs,
		RecvNAKs:           current.RecvNAKs - last.RecvNAKs,
		RecvACKACKs:        current.RecvACKACKs - last.RecvACKACKs,
		RecvDropped:        current.RecvDropped - last.RecvDropped,
		RecvDroppedBytes:   current.RecvDroppedBytes - last.RecvDroppedBytes,
		RecvBelated:        current.RecvBelated - last.RecvBelated,
		RecvBelatedBytes:   current.RecvBelatedBytes - last.RecvBelatedBytes,
		RecvUndecrypt:      current.RecvUndecrypt - last.RecvUndecrypt,
		RecvUndecryptBytes: current.RecvUndecryptBytes - last.RecvUndecryptBytes,
		SentDropped:        current.SentDropped - last.SentDropped,
		SentDroppedBytes:   current.SentDroppedBytes - last.SentDroppedBytes,
		SentKM:             current.SentKM - last.SentKM,
		RecvKM:             current.RecvKM - last.RecvKM,
		SndKmState:         current.SndKmState,
		RcvKmState:         current.RcvKmState,
		UsSndDuration:      current.UsSndDuration - last.UsSndDuration,
		CongestionWindow:   current.CongestionWindow,
		ReorderTolerance:   current.ReorderTolerance,
		ReorderDistance:    current.ReorderDistance,
		RcvAvgBelatedTime:  current.RcvAvgBelatedTime,
		NegotiatedMSS:      current.NegotiatedMSS,
		NegotiatedFC:       current.NegotiatedFC,
		MsSndTsbPdDelay:    current.MsSndTsbPdDelay,
		MsRcvTsbPdDelay:    current.MsRcvTsbPdDelay,
	}
}

// updateSnapshot saves the current stats as the baseline for next interval.
func (c *Conn) updateSnapshot(current ConnStats) {
	c.lastSnapshot = current
}

// statsCallbackState holds the registered stats callback and its interval.
type statsCallbackState struct {
	fn       func(ConnStats)
	interval time.Duration
}

// OnStats registers a callback invoked periodically with connection statistics.
// The callback receives interval stats (equivalent to Stats(true)).
// Pass 0 interval to use the default (1 second). Call with nil fn to unregister.
func (c *Conn) OnStats(interval time.Duration, fn func(ConnStats)) {
	if fn == nil {
		c.statsCallback.Store(nil)
		return
	}
	if interval <= 0 {
		interval = time.Second
	}
	state := &statsCallbackState{fn: fn, interval: interval}
	c.statsCallback.Store(state)
}

// ConnStats contains connection statistics
// Byte fields suffixed with "Total" include IP/UDP/SRT header overhead (44 bytes/pkt).
// Payload-only byte fields omit headers.
type ConnStats struct {
	// Timing
	StartTime time.Time     // connection creation time
	Duration  time.Duration // time since connection start

	// Sent packet/byte counters
	SentPackets       uint64 // total DATA packets sent (including retransmissions)
	SentBytes         uint64 // payload bytes sent
	SentUniquePackets uint64 // unique DATA packets sent (SentPackets - Retransmits)
	SentUniqueBytes   uint64 // payload bytes for unique sends
	Retransmits       uint64 // retransmitted packets sent
	RetransBytes      uint64 // payload bytes for retransmitted packets

	// Received packet/byte counters
	RecvPackets       uint64 // total DATA packets received (including retransmissions)
	RecvBytes         uint64 // payload bytes received
	RecvUniquePackets uint64 // unique DATA packets received (RecvPackets - RecvRetrans)
	RecvUniqueBytes   uint64 // payload bytes for unique receives
	RecvRetrans       uint64 // retransmitted packets received
	RecvRetransBytes  uint64 // payload bytes of retransmitted packets received

	// Loss
	LostPackets  uint64  // packets reported as lost at sender side (from NAKs)
	RecvLoss     uint64  // packets detected as missing at receiver side (gap detection)
	SendLossRate float64 // LostPackets / SentPackets * 100
	RecvLossRate float64 // RecvDropped / (RecvPackets + RecvDropped) * 100

	// Total bytes including IP/UDP/SRT header overhead (44 bytes per packet)
	// These match byteSentTotal/byteRecvTotal semantics.
	SentTotalBytes          uint64 // payload + headers for all sent packets
	RecvTotalBytes          uint64 // payload + headers for all received packets
	SentUniqueTotalBytes    uint64 // payload + headers for unique sent packets
	RecvUniqueTotalBytes    uint64 // payload + headers for unique received packets
	RecvLossBytes           uint64 // estimated bytes for lost packets (pkt count * avg payload + headers)
	RetransTotalBytes       uint64 // payload + headers for retransmitted packets
	RecvRetransTotalBytes   uint64 // payload + headers for received retransmissions
	SentDropTotalBytes      uint64 // payload + headers for sender-dropped packets
	RecvDropTotalBytes      uint64 // payload + headers for receiver-dropped packets
	RecvBelatedTotalBytes   uint64 // payload + headers for belated packets
	RecvUndecryptTotalBytes uint64 // payload + headers for undecrypted packets

	// Bitrates (interval mode: computed from interval bytes/duration)
	MbpsSendRate float64 // send bitrate in Mbps
	MbpsRecvRate float64 // receive bitrate in Mbps

	// RTT
	RTT       time.Duration
	RTTVar    time.Duration
	RTTFactor float64 // RTT / NegotiatedLatency

	// Flight and buffer state
	FlowWindow       int // flow window size in packets
	FlightSize       int // packets in flight (sent but not ACK'd)
	SendBufSize      int // packets in send buffer
	SendBufAvailable int // free slots in send buffer
	SendBufBytes     int // estimated payload bytes in send buffer
	RecvBufSize      int // packets in receive buffer
	RecvBufAvailable int // free slots in receive buffer
	RecvBufBytes     int // estimated payload bytes in receive buffer

	// Instantaneous measurements
	NegotiatedLatency  time.Duration // negotiated TSBPD delay
	PacketReceiveRate  uint32        // packets/sec
	EstimatedBandwidth uint32        // probe link capacity (packets/sec)
	UsPktSndPeriod     float64       // inter-packet send period in μs
	MbpsMaxBW          float64       // configured max bandwidth in Mbps
	MsSndBuf           time.Duration // age of oldest unacked packet in send buffer
	MsRcvBuf           time.Duration // timespan of data in receive buffer

	// Control packet counters
	SentACKs    uint64
	SentNAKs    uint64
	SentACKACKs uint64
	RecvACKs    uint64
	RecvNAKs    uint64
	RecvACKACKs uint64

	// Receiver-side counters
	RecvDropped        uint64 // packets dropped due to too-late arrival
	RecvDroppedBytes   uint64 // payload bytes of receiver-dropped packets
	RecvBelated        uint64 // packets arrived after already dropped/ACK'd
	RecvBelatedBytes   uint64 // payload bytes of belated packets
	RecvUndecrypt      uint64 // packets that failed decryption
	RecvUndecryptBytes uint64 // payload bytes of undecrypted packets

	// Sender-side counters
	SentDropped      uint64 // packets dropped from send buffer (too late)
	SentDroppedBytes uint64 // payload bytes of sender-dropped packets

	// Key management counters
	SentKM uint64 // KMREQ packets sent
	RecvKM uint64 // KMREQ/KMRSP packets received

	// Key management state (matches m_SndKmState / m_RcvKmState)
	// 0=unsecured, 1=securing, 2=secured, 3=nosecret, 4=badsecret, 5=badcryptomode
	SndKmState int
	RcvKmState int

	// Sender duration and congestion
	UsSndDuration    int64 // accumulated microseconds sender had data to transmit
	CongestionWindow int   // congestion window in packets (= FC for live mode)

	// Reorder tracking
	ReorderTolerance int32 // configured reorder tolerance (packets)
	ReorderDistance  int32 // maximum observed reorder distance (packets)

	// Belated arrival timing
	RcvAvgBelatedTime time.Duration // average lateness of belated packets

	// FEC statistics
	SndFilterExtra  uint64 // FEC control packets sent
	RcvFilterExtra  uint64 // FEC control packets received
	RcvFilterSupply uint64 // packets recovered by FEC
	RcvFilterLoss   uint64 // irrecoverable losses reported to ARQ

	// Negotiated parameters
	NegotiatedMSS   int           // negotiated maximum segment size
	NegotiatedFC    int           // negotiated flow control window
	MsSndTsbPdDelay time.Duration // peer's TSBPD delay (sender side)
	MsRcvTsbPdDelay time.Duration // local TSBPD delay (receiver side)
}
