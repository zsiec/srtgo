package core

import (
	"encoding/binary"

	"github.com/zsiec/srtgo/internal/buffer"
	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/congestion"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
	"github.com/zsiec/srtgo/internal/tsbpd"
)

// Data-path timing constants (microseconds), ported from the root conn.go.
const (
	ackTimeSlots = 64 // circular buffer matching ACK -> ACKACK for RTT

	synInterval    = 10 * clock.Millisecond  // Full ACK period / SYN
	liteACKPeriod  = 64                      // packets before a lite ACK
	initialRTT     = 100 * clock.Millisecond // startup RTT estimate
	minNAKInterval = 20 * clock.Millisecond  // live-CC NAK floor
	rttSanityCap   = 10 * clock.Second       // reject RTT samples >= this
	maxPacingBurst = 10 * clock.Millisecond  // cap on accumulated pacing credit

	defaultTsbpdDelay = 120 * clock.Millisecond // default playout latency
)

// Config parameters an established connection. Handshake negotiation (Phase 2)
// will produce one of these; for Phase 1 the test/host fills it directly.
type Config struct {
	PeerSocketID   uint32     // destination socket ID on outgoing packets
	PayloadSize    int        // max data payload per packet (0 -> MaxPayloadSize)
	SendISN        seq.Number // initial send sequence number
	RecvISN        seq.Number // initial receive sequence number
	FlowWindow     int        // negotiated max packets in flight (0 -> default)
	BufferCapacity int        // send/recv ring capacity in packets (0 -> default)
	MaxBW          int64      // max send bandwidth bytes/sec (0 -> LiveCC default)

	Live       bool               // true -> TSBPD playout + too-late drop (live mode)
	TsbpdDelay clock.Microseconds // playout latency when Live (0 -> default 120ms)
}

// Conn is the pure, single-threaded SRT data-path state machine for one
// established connection. It performs no I/O, reads no clock, and spawns no
// goroutines: the host feeds it packets/timers (each call carries `now`) and
// drains its outputs and events.
//
// Scope (Phase 1 vertical slice): steady-state live data transfer with ACK,
// NAK (immediate + periodic), retransmission, flow control, pacing, and
// ACKACK-based RTT. Handshake, encryption, FEC, TSBPD playout scheduling,
// reorder tolerance, sender-drop, and groups are deferred to later phases. In
// this slice received data is delivered in sequence order as soon as it is
// contiguous (no TSBPD hold).
type Conn struct {
	peerSocketID uint32
	payloadSize  int
	sndTSBase    uint32 // SRT wire-timestamp epoch (captured at construction)

	// Send side.
	sendBuf      *buffer.SendBuffer
	sendCC       congestion.Controller
	sendQueue    fifo[[]byte]    // app payloads awaiting transmission
	msgNumber    uint32          // 26-bit wrapping message counter
	nextSendTime clock.Timestamp // pacing deadline for the next send
	flowWindow   int             // negotiated FC window (max in flight)
	rcvFlowWin   int             // dynamic window from peer ACK (0 = unknown)

	// Receive side.
	recvBuf      *buffer.RecvBuffer
	tsbpdTimer   *tsbpd.Timer // non-nil in live mode; schedules playout
	tsbpdBaseSet bool         // time base initialized from the first data packet
	recvDropped  uint64       // packets dropped too-late (TSBPD)

	// ACK / NAK / RTT state.
	ackSeqNo        uint32
	rcvLastAckAck   seq.Number
	lastFullACKTime clock.Timestamp
	rcvPktCount     int
	lightACKCount   int
	ackSlots        [ackTimeSlots]ackSlot
	lastACKACKTime  clock.Timestamp
	lastACKACKSeq   uint32
	rtt             clock.Microseconds
	rttVar          clock.Microseconds

	closed bool

	outputs fifo[Output]
	events  fifo[Event]
}

// ackSlot records when a Full ACK was sent so the matching ACKACK can measure RTT.
type ackSlot struct {
	ackNo    uint32          // ACK sub-sequence number (echoed in ACKACK)
	sendTime clock.Timestamp // when the ACK was sent
	dataSeq  uint32          // data seqno this ACK reported
	valid    bool
}

// NewEstablished builds a connection already in the connected state and arms
// the periodic ACK and NAK timers. Handshake is out of scope for Phase 1.
func NewEstablished(cfg Config, now clock.Timestamp) *Conn {
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = packet.MaxPayloadSize
	}
	if cfg.BufferCapacity <= 0 {
		cfg.BufferCapacity = 8192
	}
	if cfg.FlowWindow <= 0 {
		cfg.FlowWindow = 25600
	}
	c := &Conn{
		peerSocketID:  cfg.PeerSocketID,
		payloadSize:   cfg.PayloadSize,
		sndTSBase:     now.SRTTimestamp(),
		sendBuf:       buffer.NewSendBuffer(cfg.BufferCapacity, cfg.SendISN),
		sendCC:        congestion.NewLiveCC(cfg.MaxBW, cfg.PayloadSize),
		recvBuf:       buffer.NewRecvBuffer(cfg.BufferCapacity, cfg.RecvISN),
		flowWindow:    cfg.FlowWindow,
		rcvLastAckAck: cfg.RecvISN,
		rtt:           initialRTT,
		rttVar:        initialRTT / 2,
		lightACKCount: 1,
	}
	if cfg.Live {
		delay := cfg.TsbpdDelay
		if delay <= 0 {
			delay = defaultTsbpdDelay
		}
		// Time base is set from the first received packet; drift correction is
		// deferred to a later phase, so disable it for now.
		c.tsbpdTimer = tsbpd.New(delay, 0)
		c.tsbpdTimer.SetDriftEnabled(false)
		c.recvBuf.SetOnRead(c.tsbpdTimer.UpdateWrap)
		c.recvBuf.SetOnDrop(c.tsbpdTimer.UpdateWrap)
	}
	c.outputs.push(SetTimer{ID: TimerACK, Deadline: now.Add(synInterval)})
	c.outputs.push(SetTimer{ID: TimerNAK, Deadline: now.Add(c.nakInterval())})
	return c
}

// PollOutput drains the next wire/timer effect; ok is false when none remain.
func (c *Conn) PollOutput() (Output, bool) { return c.outputs.pop() }

// PollEvent drains the next application-visible event; ok is false when none remain.
func (c *Conn) PollEvent() (Event, bool) { return c.events.pop() }

// ---- inputs ----

// Write enqueues an application payload for transmission and attempts to send
// as much as the flow-control window and pacing allow. The core takes
// ownership of payload (it is not copied here; packet construction copies into
// a pooled buffer at send time).
func (c *Conn) Write(now clock.Timestamp, payload []byte) {
	if c.closed {
		return
	}
	c.sendQueue.push(payload)
	c.pump(now)
}

// HandlePacket feeds one received SRT packet into the state machine.
func (c *Conn) HandlePacket(now clock.Timestamp, p packet.Packet) {
	if c.closed {
		return
	}
	if p.Header.IsControl {
		switch p.Header.ControlType {
		case packet.CtrlTypeACK:
			c.handleACK(now, p)
		case packet.CtrlTypeNAK:
			c.handleNAK(now, p)
		case packet.CtrlTypeACKACK:
			c.handleACKACK(now, p)
		case packet.CtrlTypeShutdown:
			c.closed = true
			c.events.push(Closed{})
		}
		return
	}
	c.handleData(now, p)
}

// HandleTimer fires a logical timer the host previously armed via SetTimer.
func (c *Conn) HandleTimer(now clock.Timestamp, id TimerID) {
	if c.closed {
		return
	}
	switch id {
	case TimerACK:
		c.sendFullACK(now)
		c.outputs.push(SetTimer{ID: TimerACK, Deadline: now.Add(synInterval)})
	case TimerNAK:
		c.sendPeriodicNAK(now)
		c.outputs.push(SetTimer{ID: TimerNAK, Deadline: now.Add(c.nakInterval())})
	case TimerSndPacing:
		c.pump(now)
	case TimerTSBPD:
		if c.tsbpdTimer != nil {
			c.deliverTSBPD(now)
		}
	}
}

// ---- send path ----

// pump sends queued payloads while the flow-control window has room and pacing
// permits. Pacing is a token bucket: nextSendTime advances by one packet
// interval per send, so when the host's timer fires late (OS timers are
// ~millisecond-grained) several packets come due at once and are sent as a
// catch-up burst — without this, throughput would be capped at the timer
// resolution. When no packet is yet due, it arms TimerSndPacing for the next.
func (c *Conn) pump(now clock.Timestamp) {
	for c.sendQueue.len() > 0 {
		if c.sendBuf.Size() >= c.window() {
			return // flow-control stalled; a future ACK reopens the window
		}
		if !c.nextSendTime.IsZero() && now.Before(c.nextSendTime) {
			// Re-arm is idempotent: SetTimer replaces any prior SndPacing deadline.
			c.outputs.push(SetTimer{ID: TimerSndPacing, Deadline: c.nextSendTime})
			return
		}
		payload, _ := c.sendQueue.pop()
		interval := c.sendOne(now, payload)
		switch {
		case c.nextSendTime.IsZero():
			c.nextSendTime = now.Add(interval)
		case now.Sub(c.nextSendTime) > maxPacingBurst:
			// Fell far behind (long idle or very coarse timer): drop stale credit
			// so we don't dump an unbounded burst.
			c.nextSendTime = now.Add(interval)
		default:
			c.nextSendTime = c.nextSendTime.Add(interval)
		}
	}
}

// sendOne builds, buffers, and emits one data packet. It returns the pacing
// interval the caller should apply before the next send (0 for a probe pair's
// first packet, which is sent back-to-back with the next).
func (c *Conn) sendOne(now clock.Timestamp, payload []byte) clock.Microseconds {
	seqNo := c.sendBuf.NextSeq()
	c.msgNumber = nextMsgNo(c.msgNumber)

	p := packet.NewData(nil, seqNo.Value(), c.wireTS(now), c.peerSocketID, payload)
	p.Header.MessageNumber = c.msgNumber
	p.Header.PacketPosition = packet.PositionSingle
	p.Header.Order = true

	if !c.sendBuf.Push(p, now) {
		// Window check above should prevent this; drop defensively.
		p.Release()
		return 0
	}
	// The buffer retains p for retransmission; emit it by reference (Owned=false).
	c.outputs.push(SendPacket{Packet: p, Owned: false})

	c.sendCC.OnPacketSent(seqNo.Value(), len(payload))
	if c.sendCC.IsProbePacket() {
		return 0 // probe pair: next packet back-to-back
	}
	return c.sendCC.PacketInterval()
}

// window returns the current maximum number of in-flight packets allowed.
func (c *Conn) window() int {
	w := c.flowWindow
	if c.rcvFlowWin > 0 && c.rcvFlowWin < w {
		w = c.rcvFlowWin
	}
	if cw := c.sendCC.CongestionWindow(); cw < w {
		w = cw
	}
	return w
}

// ---- receive path ----

func (c *Conn) handleData(now clock.Timestamp, p packet.Packet) {
	res := c.recvBuf.Insert(p, now)
	if !res.Inserted {
		return // duplicate or belated
	}
	c.rcvPktCount++

	c.sendCC.OnPktArrival(len(p.Data), now)
	if !p.Header.Retransmitted {
		c.sendCC.OnPacketReceived(p.Header.SequenceNumber, len(p.Data), now)
	}

	if c.tsbpdTimer != nil {
		if !c.tsbpdBaseSet {
			// Anchor the time base so this first packet plays out at now+delay:
			// DeliveryTime(ts) = timeBase + ts + delay, so timeBase = now - ts.
			c.tsbpdTimer.SetTimeBase(now.Add(-clock.Microseconds(p.Header.Timestamp)))
			c.tsbpdBaseSet = true
		}
		c.tsbpdTimer.UpdateWrap(p.Header.Timestamp)
	}

	if res.HasGap() {
		c.sendImmediateNAK(now, res.GapStart, res.GapEnd)
	}

	// Lite ACK escalation: every liteACKPeriod*lightACKCount packets.
	if c.lightACKCount > 0 && c.rcvPktCount >= liteACKPeriod*c.lightACKCount {
		c.sendLiteACK(now)
		c.lightACKCount++
	}

	if c.tsbpdTimer != nil {
		c.deliverTSBPD(now)
	} else {
		c.deliver()
	}
}

// deliver drains all now-contiguous packets to the application as DataReceived
// events. Used in file mode (no TSBPD playout hold).
func (c *Conn) deliver() {
	for {
		p, ok := c.recvBuf.ReadNext()
		if !ok {
			return
		}
		c.emitData(p)
	}
}

// deliverTSBPD delivers every packet whose TSBPD playout time has arrived,
// drops empty head slots that are now too late, and arms TimerTSBPD for the
// next packet's playout instant.
func (c *Conn) deliverTSBPD(now clock.Timestamp) {
	dt := c.tsbpdTimer.DeliveryTime
	if dropped := c.recvBuf.DropTooLate(now, dt); dropped > 0 {
		c.recvDropped += uint64(dropped)
	}
	for {
		p, ok := c.recvBuf.ReadTSBPD(now, dt)
		if !ok {
			break
		}
		c.emitData(p)
	}
	if ts, ok := c.recvBuf.PeekNextAvailableTimestamp(); ok {
		c.outputs.push(SetTimer{ID: TimerTSBPD, Deadline: dt(ts)})
	}
}

// emitData copies a delivered packet's payload into an owned slice and queues
// it as a DataReceived event, releasing the pooled packet buffer.
func (c *Conn) emitData(p packet.Packet) {
	data := make([]byte, len(p.Data))
	copy(data, p.Data)
	p.Release()
	c.events.push(DataReceived{Data: data})
}

// ---- ACK ----

func (c *Conn) sendFullACK(now clock.Timestamp) {
	ackSeq := c.recvBuf.ACKSequence()
	needFull := now.Sub(c.lastFullACKTime) >= synInterval

	// Suppress a redundant ACK the peer has already confirmed.
	if ackSeq == c.rcvLastAckAck && !needFull {
		return
	}

	c.ackSeqNo++
	if c.ackSeqNo == 0 {
		c.ackSeqNo++ // skip 0 per SRT
	}

	ack := packet.CIFACK{
		LastACKPacketSequenceNumber: ackSeq.Value(),
		RTT:                         uint32(c.rtt),
		RTTVariance:                 uint32(c.rttVar),
		AvailableBufferSize:         uint32(c.recvBuf.AvailableSize(ackSeq)),
	}
	if needFull {
		pktRate, bytesRate := c.sendCC.DeliveryRate()
		ack.PacketsReceivingRate = pktRate
		ack.EstimatedLinkCapacity = c.sendCC.EstimatedBandwidth()
		ack.ReceivingRate = bytesRate
	}

	p := packet.NewControl(nil, packet.CtrlTypeACK, c.peerSocketID, c.wireTS(now))
	p.Header.TypeSpecific = c.ackSeqNo // ACK sub-number, echoed in ACKACK
	if err := p.MarshalCIF(&ack); err != nil {
		p.Release()
		return
	}

	slot := c.ackSeqNo & (ackTimeSlots - 1)
	c.ackSlots[slot] = ackSlot{ackNo: c.ackSeqNo, sendTime: now, dataSeq: ackSeq.Value(), valid: true}

	c.outputs.push(SendPacket{Packet: p, Owned: true})
	c.lastFullACKTime = now
	c.rcvPktCount = 0
	c.lightACKCount = 1
}

func (c *Conn) sendLiteACK(now clock.Timestamp) {
	ackSeq := c.recvBuf.ACKSequence()
	p := packet.NewControl(nil, packet.CtrlTypeACK, c.peerSocketID, c.wireTS(now))
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ackSeq.Value())
	p.SetData(b[:])
	c.outputs.push(SendPacket{Packet: p, Owned: true})
}

func (c *Conn) handleACK(now clock.Timestamp, p packet.Packet) {
	var ack packet.CIFACK
	if err := p.UnmarshalCIF(&ack); err != nil {
		return
	}
	isLite := len(p.Data) == 4
	ackd := c.sendBuf.ACK(seq.Number(ack.LastACKPacketSequenceNumber))

	if isLite {
		if ackd > 0 && c.rcvFlowWin > 0 {
			c.rcvFlowWin -= ackd
		}
		c.pump(now)
		return
	}

	// Respond with ACKACK (throttled to one per SYN, or repeat on same sub-no).
	ackSubNo := p.Header.TypeSpecific
	if now.Sub(c.lastACKACKTime) >= synInterval || ackSubNo == c.lastACKACKSeq {
		aa := packet.NewControl(nil, packet.CtrlTypeACKACK, c.peerSocketID, c.wireTS(now))
		aa.Header.TypeSpecific = ackSubNo
		aa.SetData([]byte{0, 0, 0, 0}) // libsrt requires a non-empty CIF
		c.outputs.push(SendPacket{Packet: aa, Owned: true})
		c.lastACKACKTime = now
		c.lastACKACKSeq = ackSubNo
	}

	// Adopt the peer's reported flow window and RTT estimate.
	c.rcvFlowWin = int(ack.AvailableBufferSize)
	if ack.RTT > 0 {
		c.rtt = clock.Microseconds(ack.RTT)
		c.rttVar = clock.Microseconds(ack.RTTVariance)
	}
	c.sendCC.OnACK(ack.LastACKPacketSequenceNumber, c.rtt, ack.EstimatedLinkCapacity, ack.PacketsReceivingRate)
	c.pump(now)
}

func (c *Conn) handleACKACK(now clock.Timestamp, p packet.Packet) {
	ackNo := p.Header.TypeSpecific
	slot := ackNo & (ackTimeSlots - 1)
	e := c.ackSlots[slot]
	if !e.valid || e.ackNo != ackNo {
		return // unknown or stale
	}
	c.ackSlots[slot].valid = false

	rtt := now.Sub(e.sendTime)
	if rtt > 0 && rtt < rttSanityCap {
		if c.rtt == 0 {
			c.rtt = rtt
			c.rttVar = rtt / 2
		} else {
			c.rtt = (c.rtt*7 + rtt) / 8
			diff := (rtt - c.rtt).Abs()
			c.rttVar = (c.rttVar*3 + diff) / 4
		}
	}
	if seq.Number(e.dataSeq).GreaterThan(c.rcvLastAckAck) {
		c.rcvLastAckAck = seq.Number(e.dataSeq)
	}
}

// ---- NAK ----

func (c *Conn) sendImmediateNAK(now clock.Timestamp, gapStart, gapEnd uint32) {
	s, end := seq.Number(gapStart), seq.Number(gapEnd)
	losses := make([]uint32, 0, s.Distance(end)+1)
	for {
		losses = append(losses, s.Value())
		if s == end || len(losses) >= 10000 {
			break
		}
		s = s.Inc()
	}
	c.emitNAK(now, losses)
}

func (c *Conn) sendPeriodicNAK(now clock.Timestamp) {
	c.emitNAK(now, c.recvBuf.GenerateLossList())
}

func (c *Conn) emitNAK(now clock.Timestamp, losses []uint32) {
	if len(losses) == 0 {
		return
	}
	nak := packet.CIFNAK{LossList: losses}
	p := packet.NewControl(nil, packet.CtrlTypeNAK, c.peerSocketID, c.wireTS(now))
	if err := p.MarshalCIF(&nak); err != nil {
		p.Release()
		return
	}
	c.outputs.push(SendPacket{Packet: p, Owned: true})
}

func (c *Conn) handleNAK(now clock.Timestamp, p packet.Packet) {
	var nak packet.CIFNAK
	if err := p.UnmarshalCIF(&nak); err != nil {
		return
	}
	c.sendCC.OnNAK(nak.LossList)

	var rexmit []packet.Packet
	if c.rtt > 0 {
		rexmit = c.sendBuf.NAKTimed(nak.LossList, now, c.rtt, c.rttVar)
	} else {
		rexmit = c.sendBuf.NAK(nak.LossList)
	}
	for _, rp := range rexmit {
		c.outputs.push(SendPacket{Packet: rp, Owned: true})
	}
}

// nakInterval returns the periodic-NAK report interval: max(RTT+4*RTTVar, floor).
func (c *Conn) nakInterval() clock.Microseconds {
	base := c.rtt + 4*c.rttVar
	if m := c.sendCC.MinNAKInterval(); base < m {
		base = m
	}
	if base < minNAKInterval {
		base = minNAKInterval
	}
	return base
}

// ---- helpers ----

func (c *Conn) wireTS(now clock.Timestamp) uint32 {
	return now.SRTTimestamp() - c.sndTSBase
}

// nextMsgNo advances the 26-bit message counter, skipping 0.
func nextMsgNo(n uint32) uint32 {
	n = (n + 1) & 0x03FFFFFF
	if n == 0 {
		n = 1
	}
	return n
}
