package core

import (
	"encoding/binary"
	"errors"

	"github.com/zsiec/srtgo/internal/buffer"
	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/congestion"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/filter"
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
	keepaliveInterval = 1 * clock.Second        // idle keepalive cadence
)

// ErrPeerIdle is the Failed-event error when no packet arrives from the peer
// within the configured PeerIdleTimeout (the peer is presumed dead).
var ErrPeerIdle = errors.New("srt: peer idle timeout")

// Config parameters an already-established connection (NewEstablished). The
// caller handshake (Dial, see handshake.go) produces the equivalent parameters
// itself; this is used when the connection is set up out of band.
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

	// Congestion selects the congestion controller: "file" -> window-based AIMD
	// (FileCC); anything else (incl. "") -> the fixed-rate live pacer (LiveCC).
	Congestion string

	// Message enables message-mode framing (SRTO_MESSAGEAPI): a payload larger
	// than one packet is fragmented into PB_FIRST..PB_LAST sharing one message
	// number, and the receiver reassembles and delivers complete messages (in
	// order, or out of order when a message's Order bit is clear). Only honored
	// when Live is false; live mode already frames each Write as one packet and
	// plays out via TSBPD. When both are false the connection is a byte stream.
	Message bool

	// TLPktDrop enables sender-side too-late packet drop (SRTO_TLPKTDROP): in
	// live mode the sender abandons head packets older than the drop threshold
	// and tells the receiver to skip them (DROPREQ), trading completeness for
	// latency. Off by default; only honored when Live.
	TLPktDrop bool
	// SndDropDelay (SRTO_SNDDROPDELAY) adds this many milliseconds to the sender
	// drop threshold, which is otherwise max(TsbpdDelay, 1s) + 20ms. Ignored
	// unless TLPktDrop.
	SndDropDelay int

	// LossMaxTTL (SRTO_LOSSMAXTTL) is the reorder tolerance in packets: a sequence
	// gap within this many packets of the most recently received packet is not
	// NAKed immediately, giving a reordered packet time to arrive. 0 (default)
	// reports every gap immediately.
	LossMaxTTL int

	// DisableNAKReport turns off periodic loss reporting in live mode
	// (SRTO_NAKREPORT=false). The default (false) keeps periodic NAK on in live
	// mode; file mode never sends periodic NAKs regardless.
	DisableNAKReport bool

	// PeerIdleTimeout declares the peer dead (a Failed event) if no packet at all
	// arrives for this long (SRTO_PEERIDLETIMEO). While it is set, the connection
	// also emits periodic keepalives so an otherwise-idle peer stays alive. 0
	// disables dead-peer detection.
	PeerIdleTimeout clock.Microseconds

	// Encryption (nil = unencrypted). The host owns the context's entropy.
	CryptoCtx  *crypto.Context
	ActiveKey  packet.PacketEncryption // outgoing key slot (0/None -> Even)
	Passphrase string
	// KMRefreshRate is the number of encrypted packets between key rotations
	// (SRTO_KMREFRESHRATE); 0 disables mid-stream rotation. KMPreAnnounce is how
	// many packets before the switch the new key is announced via KMREQ
	// (SRTO_KMPREANNOUNCE); 0 picks a default derived from the refresh rate.
	KMRefreshRate uint64
	KMPreAnnounce uint64

	FilterConfig string // FEC packet filter, e.g. "fec,cols:10,rows:5,arq:onreq" ("" = off)
}

// MsgOptions carries per-message send metadata (the send-relevant half of the
// public MsgCtrl). The zero value matches a plain Write.
type MsgOptions struct {
	// SrcTime overrides the packet's source (wire) timestamp. Zero means "use
	// the current time"; all fragments of one message share this value.
	SrcTime uint32
	// InOrder sets the message's in-order delivery bit. In live and stream mode
	// it has no effect (TSBPD/stream delivery is always in order); in message
	// mode a clear bit lets the receiver deliver this message ahead of an
	// earlier incomplete one.
	InOrder bool
	// TTL is a per-message time-to-live: the sender drops the message (and tells
	// the receiver to skip it) if it still hasn't been acknowledged this long
	// after first transmission. Zero means no per-message TTL. Enforced
	// independently of TLPktDrop.
	TTL clock.Microseconds
}

// Conn is the pure, single-threaded SRT state machine for one connection. It
// performs no I/O, reads no clock, and spawns no goroutines: the host feeds it
// packets/timers (each call carries `now`) and drains its outputs and events.
//
// Scope so far: the caller-side HSv5 handshake (see handshake.go) and
// steady-state live data transfer — ACK, NAK (immediate + periodic),
// retransmission, flow control, token-bucket pacing, ACKACK-based RTT, and
// TSBPD playout with too-late drop, message-mode framing, and sender-side
// too-late drop (TLPKTDROP + per-message TTL). Encryption, FEC, the listener/
// rendezvous handshakes, and groups are layered on in their own files.
type Conn struct {
	peerSocketID uint32
	payloadSize  int
	sndTSBase    uint32             // SRT wire-timestamp epoch (captured at construction)
	lastNow      clock.Timestamp    // most recent loop time seen (for time-relative stats)
	sndISN       seq.Number         // local initial send sequence number
	rcvISN       seq.Number         // peer's initial sequence number (local receive ISN)
	peerVersion  uint32             // peer's SRT version from the handshake (0 if unknown)
	tlPktDrop    bool               // sender too-late drop enabled (for SndDropDelay recompute)
	dropBaseUS   clock.Microseconds // base delay for the sender drop threshold (recompute input)

	// Send side.
	sendBuf      *buffer.SendBuffer
	sendCC       congestion.Controller
	sendQueue    fifo[frame]     // framed packets awaiting transmission
	msgNumber    uint32          // 26-bit wrapping message counter
	nextSendTime clock.Timestamp // pacing deadline for the next send
	flowWindow   int             // negotiated FC window (max in flight)
	rcvFlowWin   int             // dynamic window from peer ACK (0 = unknown)

	// Sender-side too-late drop (TLPKTDROP) + per-message TTL.
	sendDropThresh   clock.Microseconds // age past which head packets are dropped (0 = no TSBPD-deadline drop)
	msgTTLActive     bool               // a per-message TTL has been set on some packet (gates the drop check)
	sentDropped      uint64             // packets abandoned from the send buffer (too late / TTL)
	sentDroppedBytes uint64

	// Receive side.
	recvBuf      *buffer.RecvBuffer
	tsbpdTimer   *tsbpd.Timer // non-nil in live mode; schedules playout
	tsbpdBaseSet bool         // time base initialized from the first data packet
	recvDropped  uint64       // packets dropped too-late (TSBPD)
	messageMode  bool         // message-mode framing: fragment on send, reassemble on receive
	periodicNAK  bool         // send periodic loss reports (live mode; off in file mode / NAKREPORT=false)
	groupIdle    bool         // peer alive (keepalive) but no data flowing (group idle-link signal)

	// peerNakReport is whether the peer advertised periodic NAK reporting. When
	// false the peer only NAKs reactively, so the RTO blind-retransmit (handleEXP)
	// is the sole backstop for a lost reactive NAK — which it already provides
	// unconditionally (a unified, more-robust FASTREXMIT/LATEREXMIT).
	peerNakReport bool

	// Reorder tolerance (SRTO_LOSSMAXTTL). A gap within reorderTolerance packets of
	// the newest received packet is not NAKed immediately; deferredLoss holds those
	// still-missing seqnos until a reordered packet fills them or they fall beyond
	// the tolerance and are reported. Zero tolerance => NAK every gap immediately.
	reorderTolerance int
	deferredLoss     map[uint32]struct{}

	// Liveness (0 timeout = disabled). lastRecvTime feeds dead-peer detection;
	// lastSentDataTime feeds the idle keepalive.
	peerIdleTimeout  clock.Microseconds
	lastRecvTime     clock.Timestamp
	lastSentDataTime clock.Timestamp

	// Encryption (nil when unencrypted). The context (salt + even/odd SEKs) is
	// created by the host; the core only wraps it for KMREQ and en/decrypts.
	cryptoCtx     *crypto.Context
	activeKey     packet.PacketEncryption // even/odd key slot for outgoing data
	passphrase    string                  // for wrapping key material (KMREQ)
	recvUndecrypt uint64                  // packets that failed decryption

	// Mid-stream key rotation (0 refresh rate = disabled). Driven by the encrypted
	// send count: pre-announce the next-slot key via KMREQ, switch the active slot
	// at the refresh boundary, then decommission the old key. See keyrotation.go.
	kmRefreshRate  uint64
	kmPreAnnounce  uint64
	kmPacketCount  uint64
	kmAnnounced    bool
	kmConfirmed    bool
	kmDecommission bool
	kmSwitchCount  uint64
	kmRetryKey     packet.PacketEncryption
	kmRetryCount   int
	sndKmState     int32 // 0=unsecured 1=securing 2=secured 3=nosecret 4=badsecret
	rcvKmState     int32
	sentKM         uint64 // KMREQ/KMRSP control packets sent
	recvKM         uint64 // KMREQ/KMRSP control packets received

	// FEC (nil when no packet filter is negotiated). Works with encryption: the
	// engine combines packets as on-wire ciphertext and recovered packets are
	// decrypted on insert.
	fecSender   *filter.FECSender
	fecReceiver *filter.FECReceiver
	fecARQLevel filter.ARQLevel

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

	// RTO / blind retransmit (the EXP timer). lastACKTime is when we last heard
	// an ACK; rexmitCount backs off the RTO across consecutive timeouts. When the
	// peer stops ACKing while data is in flight (e.g. a lost tail or a lost NAK),
	// the EXP timer blind-retransmits the unacked packets — reactive NAK handling
	// alone can't recover a tail the receiver never detected as a gap.
	lastACKTime clock.Timestamp
	rexmitCount int

	// Statistics — plain counters (single-threaded); snapshotted via Stats.
	sentPackets      uint64
	sentBytes        uint64
	retransPackets   uint64
	retransBytes     uint64
	recvPackets      uint64
	recvBytes        uint64
	recvRetrans      uint64 // received packets carrying the retransmit (R) bit
	recvRetransBytes uint64
	recvLoss         uint64
	recvBelated      uint64 // packets that arrived after their sequence was already ACK'd/read past
	recvBelatedBytes uint64
	recvAvgBelatedUS float64 // EWMA of how late belated packets arrived vs their play deadline (µs)
	recvReorderDist  int32   // max observed reorder distance (packets) — a reordered packet's lag
	lostPackets      uint64  // sequence numbers the peer reported lost (sum over received NAKs)
	sentACKs         uint64
	sentNAKs         uint64
	sentACKACKs      uint64
	recvACKs         uint64
	recvNAKs         uint64
	recvACKACKs      uint64
	sentFEC          uint64 // FEC repair packets sent
	recvFECRecov     uint64 // packets reconstructed by FEC

	negotiatedLatency clock.Microseconds // TSBPD delay agreed for this connection (live)

	state  connState  // handshake progress / connected / failed
	dial   *dialState // caller handshake parameters (nil once established or for NewEstablished)
	rdv    *rdvDial   // rendezvous handshake state (nil unless a rendezvous dial is in progress)
	closed bool

	outputs fifo[Output]
	events  fifo[Event]
}

// Stats is a snapshot of a connection's counters and live levels. It is the
// internal source the public ConnStats is projected from; wall-clock-rate fields
// (Mbps, samples/sec) and not-yet-implemented subsystems (KM state, reorder,
// belated arrivals) are filled in by the host / as those features land.
type Stats struct {
	// Cumulative packet/byte counters.
	SentPackets       uint64
	SentBytes         uint64
	SentUniquePackets uint64 // SentPackets minus retransmissions
	SentUniqueBytes   uint64
	RetransPackets    uint64
	RetransBytes      uint64
	RecvPackets       uint64
	RecvBytes         uint64
	RecvUniquePackets uint64 // RecvPackets minus received retransmissions
	RecvUniqueBytes   uint64
	RecvRetrans       uint64 // received packets carrying the retransmit (R) bit
	RecvRetransBytes  uint64

	// Loss / drop.
	RecvLoss         uint64 // gaps detected at the receiver
	LostPackets      uint64 // sequence numbers the peer reported lost (sum over received NAKs)
	RecvDropped      uint64 // dropped too-late (TSBPD) or skipped on a peer DROPREQ
	RecvUndecrypt    uint64 // failed decryption
	SentDropped      uint64 // packets abandoned from the send buffer (TLPKTDROP / TTL)
	SentDroppedBytes uint64

	// Control-packet counters.
	SentACKs    uint64
	SentNAKs    uint64
	SentACKACKs uint64
	RecvACKs    uint64
	RecvNAKs    uint64
	RecvACKACKs uint64

	// FEC.
	SentFEC      uint64 // FEC repair packets sent
	RecvFECRecov uint64 // packets reconstructed by FEC

	// Key material / rotation.
	SentKM     uint64 // KMREQ/KMRSP control packets sent
	RecvKM     uint64 // KMREQ/KMRSP control packets received
	SndKmState int32  // 0=unsecured 1=securing 2=secured 3=nosecret 4=badsecret
	RcvKmState int32

	// RTT (microseconds).
	RTTMicros    int64
	RTTVarMicros int64

	// Live levels (sampled at snapshot time).
	FlightSize         int                // packets in flight (unacked)
	FlowWindow         int                // negotiated flow-control window (packets)
	CongestionWindow   int                // effective send window (packets)
	SendBufPackets     int                // packets currently in the send buffer
	SendBufAvailable   int                // free send-buffer slots
	RecvBufPackets     int                // packets currently in the receive buffer
	RecvBufAvailable   int                // free receive-buffer slots
	PacketRecvRate     uint32             // receiver-estimated arrival rate (packets/sec)
	EstimatedBandwidth uint32             // probe-estimated link capacity (packets/sec)
	PktSndPeriodMicros int64              // current inter-packet send period (microseconds)
	NegotiatedLatency  clock.Microseconds // negotiated TSBPD delay (live mode)
	DriftMicros        clock.Microseconds // TSBPD clock-drift correction (live mode; from ACKACK/keepalive)
	PeerNakReport      bool               // peer advertised periodic NAK reporting in the handshake

	RecvBelated      uint64             // packets that arrived after their sequence was read/ACK'd past
	RecvBelatedBytes uint64             // payload bytes of belated packets
	AvgBelatedMicros clock.Microseconds // EWMA lateness of belated packets vs their play deadline
	ReorderDistance  int32              // max observed reorder distance (packets)
	PeerVersion      uint32             // peer's SRT version from the handshake
	SendISN          uint32             // local initial send sequence number
	RecvISN          uint32             // peer's initial sequence number
	MsSndBuf         clock.Microseconds // age of the oldest unacked send-buffer packet
	MsRcvBuf         clock.Microseconds // buffered playout span in the receive buffer
}

// Stats returns a snapshot of the connection's counters and live levels. Call it
// from the host's loop goroutine (the core is single-threaded).
func (c *Conn) Stats() Stats {
	s := Stats{
		SentPackets:       c.sentPackets,
		SentBytes:         c.sentBytes,
		SentUniquePackets: c.sentPackets - c.retransPackets,
		SentUniqueBytes:   c.sentBytes - c.retransBytes,
		RetransPackets:    c.retransPackets,
		RetransBytes:      c.retransBytes,
		RecvPackets:       c.recvPackets,
		RecvBytes:         c.recvBytes,
		RecvUniquePackets: c.recvPackets - c.recvRetrans,
		RecvUniqueBytes:   c.recvBytes - c.recvRetransBytes,
		RecvRetrans:       c.recvRetrans,
		RecvRetransBytes:  c.recvRetransBytes,
		RecvLoss:          c.recvLoss,
		LostPackets:       c.lostPackets,
		RecvDropped:       c.recvDropped,
		RecvUndecrypt:     c.recvUndecrypt,
		SentDropped:       c.sentDropped,
		SentDroppedBytes:  c.sentDroppedBytes,
		SentACKs:          c.sentACKs,
		SentNAKs:          c.sentNAKs,
		SentACKACKs:       c.sentACKACKs,
		RecvACKs:          c.recvACKs,
		RecvNAKs:          c.recvNAKs,
		RecvACKACKs:       c.recvACKACKs,
		SentFEC:           c.sentFEC,
		RecvFECRecov:      c.recvFECRecov,
		SentKM:            c.sentKM,
		RecvKM:            c.recvKM,
		SndKmState:        c.sndKmState,
		RcvKmState:        c.rcvKmState,
		RTTMicros:         int64(c.rtt),
		RTTVarMicros:      int64(c.rttVar),
		FlowWindow:        c.flowWindow,
		NegotiatedLatency: c.negotiatedLatency,
		PeerNakReport:     c.peerNakReport,
		RecvBelated:       c.recvBelated,
		RecvBelatedBytes:  c.recvBelatedBytes,
		AvgBelatedMicros:  clock.Microseconds(c.recvAvgBelatedUS),
		ReorderDistance:   c.recvReorderDist,
		PeerVersion:       c.peerVersion,
		SendISN:           c.sndISN.Value(),
		RecvISN:           c.rcvISN.Value(),
	}
	if c.sendBuf != nil {
		s.FlightSize = c.sendBuf.Size()
		s.SendBufPackets = c.sendBuf.Size()
		s.SendBufAvailable = c.sendBuf.Available()
		if oldest := c.sendBuf.OldestSentAt(); oldest != 0 && c.lastNow > oldest {
			s.MsSndBuf = c.lastNow.Sub(oldest)
		}
	}
	if c.recvBuf != nil {
		s.RecvBufPackets = c.recvBuf.Size()
		s.RecvBufAvailable = c.recvBuf.AvailableSize(c.recvBuf.ACKSequence())
		s.MsRcvBuf = c.recvBuf.BufferedTimeSpan()
	}
	if c.sendCC != nil {
		s.CongestionWindow = c.window()
		pktRate, _ := c.sendCC.DeliveryRate()
		s.PacketRecvRate = pktRate
		s.EstimatedBandwidth = c.sendCC.EstimatedBandwidth()
		s.PktSndPeriodMicros = int64(c.sendCC.PacketInterval())
	}
	if c.tsbpdTimer != nil {
		s.DriftMicros = c.tsbpdTimer.DriftOffset()
	}
	return s
}

// ackSlot records when a Full ACK was sent so the matching ACKACK can measure RTT.
type ackSlot struct {
	ackNo    uint32          // ACK sub-sequence number (echoed in ACKACK)
	sendTime clock.Timestamp // when the ACK was sent
	dataSeq  uint32          // data seqno this ACK reported
	valid    bool
}

// establishParams carries the data-path parameters needed to bring a connection
// into the connected state, whether built directly (NewEstablished) or produced
// by a completed handshake (see handshake.go).
type establishParams struct {
	PeerSocketID     uint32
	PayloadSize      int
	SendISN          seq.Number
	RecvISN          seq.Number
	PeerVersion      uint32 // peer's SRT version from the handshake (0 if unknown)
	FlowWindow       int
	BufferCapacity   int // shared default when SendBufCapacity/RecvBufCapacity are 0
	SendBufCapacity  int
	RecvBufCapacity  int
	MaxBW            int64
	Live             bool
	TsbpdDelay       clock.Microseconds
	Congestion       string
	Message          bool
	TLPktDrop        bool
	SndDropDelay     int
	LossMaxTTL       int
	DisableNAKReport bool // suppress periodic NAK in live mode (SRTO_NAKREPORT=false)
	PeerNakReport    bool // the peer advertised periodic NAK reporting in its handshake
	PeerIdleTimeout  clock.Microseconds
	CryptoCtx        *crypto.Context
	ActiveKey        packet.PacketEncryption
	Passphrase       string
	KMRefreshRate    uint64
	KMPreAnnounce    uint64
	FilterConfig     string
}

// NewEstablished builds a connection already in the connected state and arms
// the periodic ACK and NAK timers (no handshake).
func NewEstablished(cfg Config, now clock.Timestamp) *Conn {
	c := &Conn{}
	c.establish(now, establishParams{
		PeerSocketID:     cfg.PeerSocketID,
		PayloadSize:      cfg.PayloadSize,
		SendISN:          cfg.SendISN,
		RecvISN:          cfg.RecvISN,
		FlowWindow:       cfg.FlowWindow,
		BufferCapacity:   cfg.BufferCapacity,
		MaxBW:            cfg.MaxBW,
		Live:             cfg.Live,
		TsbpdDelay:       cfg.TsbpdDelay,
		Congestion:       cfg.Congestion,
		Message:          cfg.Message,
		TLPktDrop:        cfg.TLPktDrop,
		SndDropDelay:     cfg.SndDropDelay,
		LossMaxTTL:       cfg.LossMaxTTL,
		DisableNAKReport: cfg.DisableNAKReport,
		PeerNakReport:    true, // no handshake here; assume the peer reports (conservative)
		PeerIdleTimeout:  cfg.PeerIdleTimeout,
		CryptoCtx:        cfg.CryptoCtx,
		ActiveKey:        cfg.ActiveKey,
		Passphrase:       cfg.Passphrase,
		KMRefreshRate:    cfg.KMRefreshRate,
		KMPreAnnounce:    cfg.KMPreAnnounce,
		FilterConfig:     cfg.FilterConfig,
	})
	return c
}

// establish initializes the data-path state (buffers, congestion control, TSBPD)
// and arms the periodic ACK/NAK timers, moving the connection to the connected
// state. Shared by NewEstablished and the handshake completion path.
func (c *Conn) establish(now clock.Timestamp, ep establishParams) {
	if ep.PayloadSize <= 0 {
		ep.PayloadSize = packet.MaxPayloadSize
	}
	if ep.BufferCapacity <= 0 {
		ep.BufferCapacity = 8192
	}
	// Independent send/recv capacities (fall back to the shared BufferCapacity).
	sndCap, rcvCap := ep.SendBufCapacity, ep.RecvBufCapacity
	if sndCap <= 0 {
		sndCap = ep.BufferCapacity
	}
	if rcvCap <= 0 {
		rcvCap = ep.BufferCapacity
	}
	if ep.FlowWindow <= 0 {
		ep.FlowWindow = 25600
	}
	c.peerSocketID = ep.PeerSocketID
	c.payloadSize = ep.PayloadSize
	c.sndTSBase = now.SRTTimestamp()
	c.lastNow = now
	c.sndISN = ep.SendISN
	c.rcvISN = ep.RecvISN
	c.peerVersion = ep.PeerVersion
	c.sendBuf = buffer.NewSendBuffer(sndCap, ep.SendISN)
	// File mode uses the window-based AIMD controller (slow start + congestion
	// window); live mode uses the fixed-rate pacer. The core's window() already
	// honors the controller's CongestionWindow, so FileCC's adaptive cwnd gates
	// the send window automatically.
	if ep.Congestion == "file" {
		c.sendCC = congestion.NewFileCC(ep.MaxBW, ep.PayloadSize, ep.FlowWindow, ep.SendISN.Value())
	} else {
		c.sendCC = congestion.NewLiveCC(ep.MaxBW, ep.PayloadSize)
	}
	c.recvBuf = buffer.NewRecvBuffer(rcvCap, ep.RecvISN)
	c.flowWindow = ep.FlowWindow
	c.rcvLastAckAck = ep.RecvISN
	c.rtt = initialRTT
	c.rttVar = initialRTT / 2
	c.lightACKCount = 1
	if ep.Live {
		delay := ep.TsbpdDelay
		if delay <= 0 {
			delay = defaultTsbpdDelay
		}
		// Time base is set from the first received packet. Drift correction is
		// enabled (the SRT default): OnACK accumulates samples and nudges the
		// time base once per 1000 packets.
		c.tsbpdTimer = tsbpd.New(delay, 0)
		c.negotiatedLatency = delay
		c.recvBuf.SetOnRead(c.tsbpdTimer.UpdateWrap)
		c.recvBuf.SetOnDrop(c.tsbpdTimer.UpdateWrap)
		// Sender too-late drop threshold: max(peer playout delay, 1s) + 2*SYN,
		// plus the configured extra. (The negotiated live latency is symmetric,
		// so the local delay stands in for the peer's.)
		if ep.TLPktDrop {
			c.tlPktDrop = true
			c.dropBaseUS = delay
			thr := delay + clock.Microseconds(ep.SndDropDelay)*clock.Millisecond
			if thr < 1*clock.Second {
				thr = 1 * clock.Second
			}
			c.sendDropThresh = thr + 20*clock.Millisecond
		}
	} else if ep.Message {
		// Message mode (file API): reassemble multi-packet messages and honor the
		// per-message Order bit for in-order vs out-of-order delivery.
		c.messageMode = true
		c.recvBuf.SetMessageAPI(true)
	}
	if ep.CryptoCtx != nil {
		c.cryptoCtx = ep.CryptoCtx
		c.passphrase = ep.Passphrase
		c.activeKey = ep.ActiveKey
		if c.activeKey == packet.EncryptionNone {
			c.activeKey = packet.EncryptionEven
		}
		c.sndKmState = kmStateSecured
		c.rcvKmState = kmStateSecured
		c.kmRefreshRate = ep.KMRefreshRate
		c.kmPreAnnounce = ep.KMPreAnnounce
		// A 0 (or oversized) pre-announce window defaults to half the refresh rate
		// so the new key is announced with a packet of margin before the switch.
		if c.kmRefreshRate > 0 && (c.kmPreAnnounce == 0 || c.kmPreAnnounce >= c.kmRefreshRate) {
			c.kmPreAnnounce = c.kmRefreshRate / 2
		}
	}
	if ep.FilterConfig != "" {
		if fcfg, err := filter.ParseConfig(ep.FilterConfig); err == nil {
			c.fecSender = filter.NewFECSender(fcfg, ep.PayloadSize, ep.SendISN.Value())
			c.fecReceiver = filter.NewFECReceiver(fcfg, ep.PayloadSize, ep.RecvISN.Value())
			c.fecARQLevel = fcfg.ARQ
		}
	}
	c.rexmitCount = 1
	c.lastACKTime = now
	// Periodic loss reporting is a live-mode feature; file mode relies on reactive
	// (immediate) NAK plus the RTO blind-retransmit, so it suppresses periodic NAK.
	// SRTO_NAKREPORT=false also disables it in live mode.
	c.periodicNAK = ep.Congestion != "file" && !ep.DisableNAKReport
	c.peerNakReport = ep.PeerNakReport
	if ep.LossMaxTTL > 0 {
		c.reorderTolerance = ep.LossMaxTTL
		c.deferredLoss = make(map[uint32]struct{})
	}
	c.state = stateConnected
	c.outputs.push(SetTimer{ID: TimerACK, Deadline: now.Add(synInterval)})
	if c.periodicNAK {
		c.outputs.push(SetTimer{ID: TimerNAK, Deadline: now.Add(c.nakInterval())})
	}
	c.outputs.push(SetTimer{ID: TimerEXP, Deadline: now.Add(c.rto())})
	if ep.PeerIdleTimeout > 0 {
		c.peerIdleTimeout = ep.PeerIdleTimeout
		c.lastRecvTime = now
		c.lastSentDataTime = now
		c.outputs.push(SetTimer{ID: TimerKeepalive, Deadline: now.Add(keepaliveInterval)})
		c.outputs.push(SetTimer{ID: TimerPeerIdle, Deadline: now.Add(c.peerIdleTimeout)})
	}
}

// PollOutput drains the next wire/timer effect; ok is false when none remain.
func (c *Conn) PollOutput() (Output, bool) { return c.outputs.pop() }

// PollEvent drains the next application-visible event; ok is false when none remain.
func (c *Conn) PollEvent() (Event, bool) { return c.events.pop() }

// ---- inputs ----

// Write enqueues an application payload for transmission with default framing
// (a single message, in-order delivery, live wire timestamp) and attempts to
// send as much as the flow-control window and pacing allow.
func (c *Conn) Write(now clock.Timestamp, payload []byte) {
	c.WriteMsg(now, payload, MsgOptions{InOrder: true})
}

// SetMaxBW changes the maximum sending bandwidth (bytes/sec) at runtime; 0 means
// auto. Call it on the host loop goroutine.
func (c *Conn) SetMaxBW(bw int64) {
	if c.sendCC != nil {
		c.sendCC.SetMaxBandwidth(bw)
	}
}

// SetInputBW updates the estimated input bandwidth (bytes/sec) used for auto-rate
// when MaxBW is 0.
func (c *Conn) SetInputBW(bw int64) {
	if c.sendCC != nil {
		c.sendCC.UpdateBandwidth(c.sendCC.MaxBandwidth(), bw)
	}
}

// SetOverhead updates the retransmit bandwidth overhead percentage (5..100).
func (c *Conn) SetOverhead(pct int) {
	if c.sendCC != nil {
		c.sendCC.SetOverhead(pct)
	}
}

// SendISN returns the local initial send sequence number.
func (c *Conn) SendISN() uint32 { return c.sndISN.Value() }

// RecvISN returns the peer's initial sequence number (local receive ISN).
func (c *Conn) RecvISN() uint32 { return c.rcvISN.Value() }

// PeerVersion returns the peer's SRT version from the handshake (0 if unknown).
func (c *Conn) PeerVersion() uint32 { return c.peerVersion }

// SetSndDropDelay updates the extra sender-drop delay (ms) at runtime, recomputing
// the send-drop threshold. No-op if too-late drop is disabled for this connection.
func (c *Conn) SetSndDropDelay(ms int) {
	if !c.tlPktDrop {
		return
	}
	thr := c.dropBaseUS + clock.Microseconds(ms)*clock.Millisecond
	if thr < 1*clock.Second {
		thr = 1 * clock.Second
	}
	c.sendDropThresh = thr + 20*clock.Millisecond
}

// SetReorderTolerance updates the reorder tolerance (SRTO_LOSSMAXTTL) at runtime.
func (c *Conn) SetReorderTolerance(n int) {
	if n < 0 {
		n = 0
	}
	c.reorderTolerance = n
	if n > 0 && c.deferredLoss == nil {
		c.deferredLoss = make(map[uint32]struct{})
	}
}

// ---- group bonding primitives (driven by the host's group loop) ----

// SchedSeqNo returns the next sequence number the sender will assign.
func (c *Conn) SchedSeqNo() seq.Number {
	if c.sendBuf == nil {
		return 0
	}
	return c.sendBuf.NextSeq()
}

// OverrideSndSeqNo forces the next send sequence number (group sequence sync).
func (c *Conn) OverrideSndSeqNo(nextSeq seq.Number) bool {
	if c.sendBuf == nil {
		return false
	}
	return c.sendBuf.OverrideNextSeq(nextSeq)
}

// LastMsgNo returns the most recently assigned message number.
func (c *Conn) LastMsgNo() uint32 { return c.msgNumber }

// GroupIdle reports whether the link is alive (last heard a keepalive) but has
// no data flowing — used by the group's backup monitor.
func (c *Conn) GroupIdle() bool { return c.groupIdle }

// AckSeqNo returns the receiver's current ACK point (next-expected sequence),
// a monotonic progress indicator for the group's backup health checks.
func (c *Conn) AckSeqNo() seq.Number {
	if c.recvBuf == nil {
		return 0
	}
	return c.recvBuf.ACKSequence()
}

// RcvBufEmpty reports whether the receive buffer has no available packets.
func (c *Conn) RcvBufEmpty() bool { return c.recvBuf == nil || c.recvBuf.IsEmpty() }

// RcvBufStartSeq returns the first sequence number in the receive buffer.
func (c *Conn) RcvBufStartSeq() seq.Number {
	if c.recvBuf == nil {
		return 0
	}
	return c.recvBuf.StartSeq()
}

// ResetRecvState realigns the receiver to nextSeq (group failover), dropping any
// buffered data; the TSBPD time base is left intact.
func (c *Conn) ResetRecvState(nextSeq seq.Number) {
	if c.recvBuf != nil {
		c.resetRecvTo(nextSeq)
	}
}

// TSBPDTimeBase returns this connection's TSBPD time base for group drift sync,
// or nil if not in live mode.
func (c *Conn) TSBPDTimeBase() *tsbpd.GroupTimeBase {
	if c.tsbpdTimer == nil {
		return nil
	}
	tb := c.tsbpdTimer.GetInternalTimeBase()
	return &tb
}

// ApplyGroupDrift applies a group-wide drift correction to the TSBPD timer.
func (c *Conn) ApplyGroupDrift(tb tsbpd.GroupTimeBase) {
	if c.tsbpdTimer != nil {
		c.tsbpdTimer.ApplyGroupDrift(tb)
	}
}

// ApplyGroupTime applies a group-wide time base to the TSBPD timer.
func (c *Conn) ApplyGroupTime(tb tsbpd.GroupTimeBase) {
	if c.tsbpdTimer != nil {
		c.tsbpdTimer.ApplyGroupTime(tb, c.tsbpdTimer.Delay())
	}
}

// SendKeepAlive emits a KEEPALIVE immediately (group idle-link liveness).
func (c *Conn) SendKeepAlive(now clock.Timestamp) {
	if c.closed {
		return
	}
	p := packet.NewControl(nil, packet.CtrlTypeKeepalive, c.peerSocketID, c.wireTS(now))
	c.outputs.push(SendPacket{Packet: p, Owned: true})
}

// PendingSend returns the number of unacknowledged packets in the send buffer.
// The host uses it to linger on close until in-flight data has drained.
func (c *Conn) PendingSend() int {
	if c.sendBuf == nil {
		return 0
	}
	return c.sendBuf.Size()
}

// Shutdown emits a SHUTDOWN control packet telling the peer the connection is
// closing (so its Read returns EOF promptly instead of waiting for an idle
// timeout) and marks the connection closed. Idempotent.
func (c *Conn) Shutdown(now clock.Timestamp) {
	if c.closed {
		return
	}
	c.closed = true
	p := packet.NewControl(nil, packet.CtrlTypeShutdown, c.peerSocketID, c.wireTS(now))
	p.SetData([]byte{0, 0, 0, 0}) // libsrt requires a non-empty CIF
	c.outputs.push(SendPacket{Packet: p, Owned: true})
}

// WriteMsg enqueues an application payload as one message with per-message
// options (source timestamp override, in-order bit). In message mode a payload
// larger than one packet is fragmented into PB_FIRST..PB_LAST sharing a single
// message number; otherwise it is sent as one packet (live mode rejects oversize
// payloads upstream in the host). The core takes ownership of payload; packet
// construction copies each fragment into a pooled buffer at send time.
func (c *Conn) WriteMsg(now clock.Timestamp, payload []byte, opts MsgOptions) {
	if c.closed || c.state != stateConnected {
		return
	}
	c.msgNumber = nextMsgNo(c.msgNumber)
	msgNo := c.msgNumber

	var ttlNs int64
	if opts.TTL > 0 {
		ttlNs = int64(opts.TTL) * 1000 // microseconds -> nanoseconds (buffer's unit)
		c.msgTTLActive = true          // start running the drop check for this conn
	}

	ps := c.payloadSize
	if ps <= 0 || len(payload) <= ps || c.tsbpdTimer != nil {
		// Single packet: a small payload, or live mode — which frames exactly one
		// packet per Write and rejects oversize payloads at the public API, so it
		// never fragments here. A zero srcTime defers to the live wire time at
		// send, preserving the single-packet behavior of stamping at transmission.
		c.sendQueue.push(frame{payload: payload, msgNo: msgNo, pos: packet.PositionSingle, order: opts.InOrder, srcTime: opts.SrcTime, ttlNs: ttlNs})
		c.pump(now)
		return
	}

	// Multi-packet message: pin one source timestamp so every fragment carries
	// it (fragments are sent across separate pacing steps, so deferring to the
	// send-time wire clock would give them differing timestamps).
	srcTime := opts.SrcTime
	if srcTime == 0 {
		srcTime = c.wireTS(now)
	}

	// Fragment into First/Middle/Last sharing msgNo. Each fragment is queued
	// independently and sent under its own flow-control/pacing step; the receiver
	// only delivers the message once every fragment has arrived.
	for off := 0; off < len(payload); off += ps {
		end := off + ps
		if end > len(payload) {
			end = len(payload)
		}
		pos := packet.PositionMiddle
		if off == 0 {
			pos |= packet.PositionFirst
		}
		if end == len(payload) {
			pos |= packet.PositionLast
		}
		c.sendQueue.push(frame{payload: payload[off:end], msgNo: msgNo, pos: pos, order: opts.InOrder, srcTime: srcTime, ttlNs: ttlNs})
	}
	c.pump(now)
}

// HandlePacket feeds one received SRT packet into the state machine.
func (c *Conn) HandlePacket(now clock.Timestamp, p packet.Packet) {
	c.lastNow = now
	if c.closed {
		return
	}
	if p.Header.IsControl && p.Header.ControlType == packet.CtrlTypeHandshake {
		c.handleHandshake(now, p)
		return
	}
	if c.state != stateConnected {
		// Before the connection is up, a SHUTDOWN is how an HSv4 listener refuses.
		if c.dial != nil && p.Header.IsControl && p.Header.ControlType == packet.CtrlTypeShutdown {
			c.handshakeRefused()
		}
		return // otherwise ignore data/ACK/NAK until the handshake completes
	}
	// Any packet from the peer is proof of life for dead-peer detection.
	if c.peerIdleTimeout > 0 {
		c.lastRecvTime = now
	}
	if p.Header.IsControl {
		switch p.Header.ControlType {
		case packet.CtrlTypeACK:
			c.handleACK(now, p)
		case packet.CtrlTypeNAK:
			c.handleNAK(now, p)
		case packet.CtrlTypeACKACK:
			c.handleACKACK(now, p)
		case packet.CtrlTypeDropReq:
			c.handleDropReq(now, p)
		case packet.CtrlTypeUser:
			switch p.Header.SubType {
			case packet.ExtTypeKMReq:
				c.handleKMRequest(now, p)
			case packet.ExtTypeKMRsp:
				c.handleKMResponse(p)
			case packet.ExtTypeHSReq:
				c.handleHSv4HSREQ(p)
			case packet.ExtTypeHSRsp:
				c.handleHSv4HSRSP(p)
			}
		case packet.CtrlTypeKeepalive:
			// Liveness, plus a TSBPD drift sample from the sender's clock (no RTT
			// sample available here) — useful during data pauses when no ACKACKs flow.
			c.groupIdle = true // alive but no data flowing (group idle-link signal)
			if c.tsbpdTimer != nil {
				c.tsbpdTimer.UpdateWrap(p.Header.Timestamp)
				c.tsbpdTimer.OnACK(p.Header.Timestamp, now, -1)
			}
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
	c.lastNow = now
	if c.closed {
		return
	}
	switch id {
	case TimerACK:
		c.sendFullACK(now)
		c.outputs.push(SetTimer{ID: TimerACK, Deadline: now.Add(synInterval)})
		// Heartbeat for the sender side: when the window is full and no ACKs are
		// arriving, this periodic tick is what lets too-late head packets age out
		// and frees the window. Only for drop-enabled connections (pump runs the
		// drop check at its top).
		if c.sendDropThresh > 0 || c.msgTTLActive {
			c.pump(now)
		}
	case TimerNAK:
		if !c.periodicNAK {
			return // periodic loss reporting disabled (file mode)
		}
		if c.fecReceiver == nil || c.fecARQLevel == filter.ARQAlways {
			c.sendPeriodicNAK(now)
		}
		c.outputs.push(SetTimer{ID: TimerNAK, Deadline: now.Add(c.nakInterval())})
	case TimerSndPacing:
		c.pump(now)
	case TimerTSBPD:
		if c.tsbpdTimer != nil {
			c.deliverTSBPD(now)
		}
	case TimerHandshake:
		c.handleHandshakeTimer(now)
	case TimerKMRefresh:
		c.retryKMREQ(now)
	case TimerKeepalive:
		c.checkKeepalive(now)
	case TimerPeerIdle:
		c.checkPeerIdle(now)
	case TimerEXP:
		c.handleEXP(now)
	}
}

// rto returns the current retransmission timeout: (RTT + 4·RTTVar + 2·SYN),
// scaled by the consecutive-timeout count for exponential-ish backoff, plus a
// small floor. Mirrors the legacy EXP interval.
func (c *Conn) rto() clock.Microseconds {
	n := c.rexmitCount
	if n < 1 {
		n = 1
	}
	return clock.Microseconds(n)*(c.rtt+4*c.rttVar+2*synInterval) + 10*clock.Millisecond
}

// handleEXP is the retransmission-timeout timer. When data is in flight and no
// ACK has advanced it within the RTO, it blind-retransmits the unacked packets
// (the receiver may never have detected a lost tail as a gap, so it never NAKs
// it) and tells the congestion controller a timeout occurred. It always re-arms.
func (c *Conn) handleEXP(now clock.Timestamp) {
	if c.sendBuf != nil && c.sendBuf.Size() > 0 && now.Sub(c.lastACKTime) > c.rto() {
		c.sendCC.OnTimeout()
		c.rexmitCount++
		c.retransmitAll(now)
		c.lastACKTime = now // avoid immediate refire before the next RTO
	}
	c.outputs.push(SetTimer{ID: TimerEXP, Deadline: now.Add(c.rto())})
}

// retransmitAll re-sends every unacknowledged packet (blind retransmit on RTO).
// The send buffer returns retransmit clones (R bit set); the host releases them.
func (c *Conn) retransmitAll(now clock.Timestamp) {
	for _, rp := range c.sendBuf.GetAllUnacked() {
		c.retransPackets++
		c.retransBytes += uint64(len(rp.Data))
		c.outputs.push(SendPacket{Packet: rp, Owned: true})
	}
}

// checkKeepalive sends a KEEPALIVE when no data has been sent for the keepalive
// interval, so an otherwise-idle connection stays alive at the peer, then re-arms.
func (c *Conn) checkKeepalive(now clock.Timestamp) {
	if c.peerIdleTimeout <= 0 {
		return
	}
	if now.Sub(c.lastSentDataTime) >= keepaliveInterval {
		p := packet.NewControl(nil, packet.CtrlTypeKeepalive, c.peerSocketID, c.wireTS(now))
		p.SetData([]byte{0, 0, 0, 0}) // non-empty CIF
		c.outputs.push(SendPacket{Packet: p, Owned: true})
	}
	c.outputs.push(SetTimer{ID: TimerKeepalive, Deadline: now.Add(keepaliveInterval)})
}

// checkPeerIdle declares the peer dead (Failed) when nothing has arrived for the
// idle timeout; otherwise it re-arms to fire when the timeout would next elapse.
func (c *Conn) checkPeerIdle(now clock.Timestamp) {
	if c.peerIdleTimeout <= 0 {
		return
	}
	if now.Sub(c.lastRecvTime) >= c.peerIdleTimeout {
		c.closed = true
		c.events.push(Failed{Err: ErrPeerIdle})
		return // dead: stop re-arming
	}
	c.outputs.push(SetTimer{ID: TimerPeerIdle, Deadline: c.lastRecvTime.Add(c.peerIdleTimeout)})
}

// ---- send path ----

// frame is one queued packet's worth of payload plus the framing the send path
// stamps onto it: the shared message number, the position within the message
// (Single, or First/Middle/Last for a fragmented one), the in-order bit, and an
// optional explicit source timestamp (0 -> the live wire time at send). All
// fragments of one message carry the same msgNo and srcTime.
type frame struct {
	payload []byte
	msgNo   uint32
	pos     packet.PacketPosition
	order   bool
	srcTime uint32
	ttlNs   int64 // per-message TTL in nanoseconds (0 = none); tags the send buffer entry
}

// pump sends queued payloads while the flow-control window has room and pacing
// permits. Pacing is a token bucket: nextSendTime advances by one packet
// interval per send, so when the host's timer fires late (OS timers are
// ~millisecond-grained) several packets come due at once and are sent as a
// catch-up burst — without this, throughput would be capped at the timer
// resolution. When no packet is yet due, it arms TimerSndPacing for the next.
func (c *Conn) pump(now clock.Timestamp) {
	// Abandon any head packets that have aged out (TLPKTDROP / per-message TTL)
	// before sending more — this also frees flow-control window for fresh data.
	c.checkSendDrop(now)
	for c.sendQueue.len() > 0 {
		if c.sendBuf.Size() >= c.window() {
			return // flow-control stalled; a future ACK reopens the window
		}
		if !c.nextSendTime.IsZero() && now.Before(c.nextSendTime) {
			// Re-arm is idempotent: SetTimer replaces any prior SndPacing deadline.
			c.outputs.push(SetTimer{ID: TimerSndPacing, Deadline: c.nextSendTime})
			return
		}
		f, _ := c.sendQueue.pop()
		interval := c.sendOne(now, f)
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

// sendOne builds, buffers, and emits the frame as one data packet with the next
// sequence number, using the frame's source timestamp (or the live wire time
// when unset). It returns the pacing interval the caller should apply before the
// next send (0 for a probe pair's first packet, sent back-to-back with the next).
func (c *Conn) sendOne(now clock.Timestamp, f frame) clock.Microseconds {
	ts := f.srcTime
	if ts == 0 {
		ts = c.wireTS(now)
	}
	c.sendData(now, c.sendBuf.NextSeq(), ts, f)
	if c.sendCC.IsProbePacket() {
		return 0 // probe pair: next packet back-to-back
	}
	return c.sendCC.PacketInterval()
}

// sendData builds, encrypts, buffers, and emits one data packet from the frame
// with an explicit sequence number and wire timestamp, then feeds FEC. seqNo
// must equal the send buffer's next sequence. Shared by the normal send path and
// the group-coordinated send path (WriteCoordinated). The message number is
// assigned by the caller (WriteMsg / WriteCoordinated) and carried on the frame.
func (c *Conn) sendData(now clock.Timestamp, seqNo seq.Number, ts uint32, f frame) {
	p := packet.NewData(nil, seqNo.Value(), ts, c.peerSocketID, f.payload)
	p.Header.MessageNumber = f.msgNo
	p.Header.PacketPosition = f.pos
	p.Header.Order = f.order

	// Encrypt before buffering so retransmissions resend identical ciphertext
	// (same sequence number -> same keystream) with no re-encryption.
	if c.cryptoCtx != nil {
		c.encrypt(&p, seqNo.Value())
	}

	if !c.sendBuf.Push(p, now) {
		// Window check above should prevent this; drop defensively.
		p.Release()
		return
	}
	if f.ttlNs > 0 {
		c.sendBuf.SetMsgTTL(f.ttlNs) // tag the just-pushed entry for TTL drop
	}
	// The buffer retains p for retransmission; emit it by reference (Owned=false).
	c.outputs.push(SendPacket{Packet: p, Owned: false})
	c.sentPackets++
	c.sentBytes += uint64(len(f.payload))
	c.lastSentDataTime = now // feeds the idle keepalive

	c.sendCC.OnPacketSent(seqNo.Value(), len(f.payload))

	// FEC: clip the (post-encryption) payload into groups and emit any completed
	// repair packets. Repair packets share the group's last sequence number and
	// are not buffered for retransmission.
	if c.fecSender != nil {
		c.fecSender.FeedSource(seqNo.Value(), p.Header.Timestamp, uint8(p.Header.Encryption), p.Data)
		c.drainFECSender()
	}

	// Advance the key-rotation state machine on each encrypted send (this packet
	// was encrypted with the current active key; rotation affects later packets).
	if c.cryptoCtx != nil && c.kmRefreshRate > 0 {
		c.checkKeyRotation(now)
	}
}

// checkSendDrop abandons send-buffer head packets the sender has given up on —
// those older than the TLPKTDROP threshold or past their per-message TTL — and
// tells the receiver to skip them with a DROPREQ so it stops NAKing the gap and
// its ACK can advance. Dropping frees flow-control window for fresh data. It is
// a no-op (one comparison) unless sender-drop or a per-message TTL is in play.
func (c *Conn) checkSendDrop(now clock.Timestamp) {
	if (c.sendDropThresh <= 0 && !c.msgTTLActive) || c.sendBuf == nil {
		return
	}
	dropped, first, last := c.sendBuf.DropTooLateSend(now, c.sendDropThresh)
	if dropped == 0 {
		return
	}
	c.sentDropped += uint64(dropped)
	c.sentDroppedBytes += uint64(dropped) * uint64(c.payloadSize)
	c.emitDropReq(now, first.Value(), last.Value())
}

// emitDropReq sends a DROPREQ control packet asking the peer to skip the
// inclusive sequence range [firstSeq, lastSeq] (the sender has abandoned it).
func (c *Conn) emitDropReq(now clock.Timestamp, firstSeq, lastSeq uint32) {
	dr := &packet.CIFDropReq{FirstSeqNo: firstSeq, LastSeqNo: lastSeq}
	data, err := dr.MarshalCIF()
	if err != nil {
		return
	}
	p := packet.NewControl(nil, packet.CtrlTypeDropReq, c.peerSocketID, c.wireTS(now))
	p.SetData(data)
	c.outputs.push(SendPacket{Packet: p, Owned: true})
}

// resetRecvTo advances this connection's receive state so the next expected
// sequence number is nextSeq, dropping any buffered data. Used by backup-mode
// bonding to keep a standby link's receiver aligned with the active link, so it
// is ready to accept packets on failover without a huge spurious gap. The TSBPD
// time base is left intact — the group keeps all members' time bases in lockstep
// (see Group.syncTimebases), so the standby plays out in step with the active
// link rather than re-anchoring to its own (skewed) reference.
func (c *Conn) resetRecvTo(nextSeq seq.Number) {
	c.recvBuf.SetInitialRcvSeq(nextSeq)
	c.rcvLastAckAck = nextSeq
}

// WriteCoordinated sends one data packet with a group-assigned sequence number
// and source timestamp (connection bonding): every member of a broadcast group
// sends the same payload with the same sequence and timestamp so the receiver
// can deduplicate across links. Pacing and flow control are the group's concern,
// so the packet is emitted immediately. Used by Group.
func (c *Conn) WriteCoordinated(now clock.Timestamp, payload []byte, seqNo seq.Number, srcTime uint32) {
	if c.closed || c.state != stateConnected {
		return
	}
	// The send buffer stores packets at its own next sequence, so align it to the
	// group sequence (usually already aligned in lockstep broadcast).
	if c.sendBuf.NextSeq() != seqNo {
		c.sendBuf.OverrideNextSeq(seqNo)
	}
	c.msgNumber = nextMsgNo(c.msgNumber)
	c.sendData(now, seqNo, srcTime, frame{
		payload: payload,
		msgNo:   c.msgNumber,
		pos:     packet.PositionSingle,
		order:   true,
	})
}

// drainFECSender emits every pending FEC repair packet as an SRT data packet
// with MessageNumber 0 (the FEC marker) and no encryption.
func (c *Conn) drainFECSender() {
	for {
		data, _, fecSeqNo, fecTS, ok := c.fecSender.PackControlPacket()
		if !ok {
			break
		}
		fp := packet.NewData(nil, fecSeqNo, fecTS, c.peerSocketID, data)
		fp.Header.MessageNumber = 0 // FEC repair marker
		fp.Header.PacketPosition = packet.PositionSingle
		fp.Header.Encryption = packet.EncryptionNone
		c.outputs.push(SendPacket{Packet: fp, Owned: true})
		c.sentFEC++
	}
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

// ---- crypto ----

// encrypt sets the encryption flag and encrypts the packet payload in place
// (CTR) or replaces it with ciphertext+tag (GCM). seqNo drives the per-packet
// IV. For GCM the marshaled header is the AAD.
func (c *Conn) encrypt(p *packet.Packet, seqNo uint32) {
	p.Header.Encryption = c.activeKey
	var aad []byte
	if c.cryptoCtx.Mode() == crypto.CipherGCM {
		var hb [16]byte
		p.Header.Marshal(hb[:])
		aad = hb[:]
	}
	if enc, err := c.cryptoCtx.EncryptPayload(p.Data, aad, c.activeKey, seqNo); err == nil {
		p.Data = enc
	}
}

// decrypt reverses encrypt. It returns false (drop the packet) on auth/decrypt
// failure. On an unencrypted connection packets pass through; on a secured
// connection a plaintext (EncryptionNone) data packet is rejected as stray or
// injected — all data is encrypted once a crypto context is negotiated. For GCM
// the AAD must match the sender's original header, so the retransmit (R) bit is
// zeroed before marshal.
func (c *Conn) decrypt(p *packet.Packet) bool {
	if c.cryptoCtx == nil {
		return true // unencrypted connection
	}
	if p.Header.Encryption == packet.EncryptionNone {
		c.recvUndecrypt++ // plaintext on a secured connection: drop
		return false
	}
	var aad []byte
	if c.cryptoCtx.Mode() == crypto.CipherGCM {
		savedR := p.Header.Retransmitted
		p.Header.Retransmitted = false
		var hb [16]byte
		p.Header.Marshal(hb[:])
		aad = hb[:]
		p.Header.Retransmitted = savedR
	}
	dec, err := c.cryptoCtx.DecryptPayload(p.Data, aad, p.Header.Encryption, p.Header.SequenceNumber)
	if err != nil {
		c.recvUndecrypt++
		return false
	}
	p.Data = dec
	return true
}

// ---- receive path ----

func (c *Conn) handleData(now clock.Timestamp, p packet.Packet) {
	// FEC repair packet (MessageNumber == 0): feed the FEC engine, never deliver.
	if c.fecReceiver != nil && p.Header.MessageNumber == 0 {
		rec, lossReport, _ := c.fecReceiver.Receive(p.Header.SequenceNumber, p.Header.Timestamp,
			uint8(p.Header.Encryption), p.Header.MessageNumber, p.Data)
		p.Release()
		c.insertRecovered(now, rec)
		if len(lossReport) > 0 { // ARQ=onreq: FEC asks for these via NAK
			c.emitNAK(now, lossReport)
		}
		c.deliverNow(now)
		return
	}

	// FEC protects the on-wire ciphertext, so capture it before decrypting in
	// place (CTR decryption is in-place): the FEC engine must combine source and
	// repair packets over the same bytes the sender computed the repair from.
	// Recovered packets come back as ciphertext and are decrypted in
	// insertRecovered.
	var fecCipher []byte
	if c.fecReceiver != nil && p.Header.Encryption != packet.EncryptionNone {
		fecCipher = append(fecCipher, p.Data...)
	}

	if !c.decrypt(&p) {
		p.Release()
		return // undecryptable: drop
	}
	belatedBefore := seq.Number(p.Header.SequenceNumber).LessThan(c.recvBuf.StartSeq())
	res := c.recvBuf.Insert(p, now)
	if !res.Inserted {
		if belatedBefore { // arrived after its sequence was already read/ACK'd past
			c.recvBelated++
			c.recvBelatedBytes += uint64(len(p.Data))
			// Track how late it arrived versus its TSBPD play deadline (EWMA, 1/8).
			if c.tsbpdTimer != nil {
				if late := now.Sub(c.tsbpdTimer.DeliveryTime(p.Header.Timestamp)); late > 0 {
					if c.recvAvgBelatedUS == 0 {
						c.recvAvgBelatedUS = float64(late)
					} else {
						c.recvAvgBelatedUS = c.recvAvgBelatedUS*0.875 + float64(late)*0.125
					}
				}
			}
		}
		return // duplicate or belated
	}
	c.groupIdle = false // data is flowing again (clears the group idle-link signal)
	// Reorder tolerance: a packet we were holding off NAKing has now arrived (it
	// was merely reordered, not lost) — cancel its deferred loss report and record
	// how far it lagged the frontier (max observed reorder distance).
	if c.deferredLoss != nil {
		if _, deferred := c.deferredLoss[p.Header.SequenceNumber]; deferred {
			if d := int32(seq.Number(p.Header.SequenceNumber).Distance(c.recvBuf.MaxSeq())); d > c.recvReorderDist {
				c.recvReorderDist = d
			}
		}
		delete(c.deferredLoss, p.Header.SequenceNumber)
	}
	c.rcvPktCount++
	c.recvPackets++
	c.recvBytes += uint64(len(p.Data))

	c.sendCC.OnPktArrival(len(p.Data), now)
	if p.Header.Retransmitted {
		c.recvRetrans++
		c.recvRetransBytes += uint64(len(p.Data))
	} else {
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
		// NB: drift samples are NOT taken here. A data packet's timestamp is the
		// application's source time (subject to pacing/buffering jitter), not the
		// sender's clock at send. Drift is sampled from ACKACK and keepalive
		// timestamps instead (handleACKACK / the keepalive case), which reflect the
		// sender's clock directly at a known round trip.
	}

	// Feed the data packet into the FEC engine for group accumulation; it may
	// reconstruct earlier losses. Encrypted connections feed the captured
	// ciphertext (fecCipher); unencrypted ones feed the payload directly.
	if c.fecReceiver != nil {
		fecData := p.Data
		if fecCipher != nil {
			fecData = fecCipher
		}
		rec, _, _ := c.fecReceiver.Receive(p.Header.SequenceNumber, p.Header.Timestamp,
			uint8(p.Header.Encryption), p.Header.MessageNumber, fecData)
		c.insertRecovered(now, rec)
	}

	if res.HasGap() {
		c.recvLoss += uint64(seq.Number(res.GapStart).Distance(seq.Number(res.GapEnd))) + 1
		// Suppress SRT's own NAK when FEC is expected to recover the loss; FEC
		// reports irrecoverable losses itself (lossReport) when ARQ=onreq.
		if c.fecReceiver == nil || c.fecARQLevel == filter.ARQAlways {
			c.reportGap(now, res.GapStart, res.GapEnd, p.Header.SequenceNumber)
		}
	}
	// As the received frontier advances, NAK any deferred losses that have now
	// fallen beyond the reorder window (they were real losses, not reordering).
	if len(c.deferredLoss) > 0 {
		c.flushDeferredLoss(now, p.Header.SequenceNumber)
	}

	// Lite ACK escalation: every liteACKPeriod*lightACKCount packets.
	if c.lightACKCount > 0 && c.rcvPktCount >= liteACKPeriod*c.lightACKCount {
		c.sendLiteACK(now)
		c.lightACKCount++
	}

	c.deliverNow(now)
}

// handleDropReq processes a peer DROPREQ: the sender abandoned the inclusive
// sequence range [FirstSeqNo, LastSeqNo], so skip it in the receive buffer.
// Skipping advances the ACK point and removes the range from the loss list (it
// will never be retransmitted), stopping spurious NAKs, and may unblock delivery
// of packets that were stuck behind the gap. Drop only moves forward (a range
// already read/dropped past is a no-op).
func (c *Conn) handleDropReq(now clock.Timestamp, p packet.Packet) {
	var dr packet.CIFDropReq
	if err := dr.UnmarshalCIF(p.Data); err != nil {
		return
	}
	if dropped := c.recvBuf.Drop(seq.Number(dr.LastSeqNo).Inc()); dropped > 0 {
		c.recvDropped += uint64(dropped)
	}
	c.deliverNow(now)
}

// deliverNow dispatches to TSBPD playout (live), message reassembly (message
// mode), or immediate in-order byte delivery (stream mode).
func (c *Conn) deliverNow(now clock.Timestamp) {
	switch {
	case c.tsbpdTimer != nil:
		c.deliverTSBPD(now)
	case c.messageMode:
		c.deliverMessages()
	default:
		c.deliver()
	}
}

// deliverMessages reassembles and delivers every complete message currently
// available. Each message is concatenated from its PB_FIRST..PB_LAST fragments
// (a single-packet message is one PB_SINGLE) and surfaced as one DataReceived
// carrying the message's number, first sequence number, and boundary. Honors
// the Order bit: an out-of-order message can be delivered ahead of an earlier
// incomplete one.
func (c *Conn) deliverMessages() {
	for {
		pkts, ok := c.recvBuf.ReadMessage()
		if !ok {
			return
		}
		c.emitMessage(pkts)
	}
}

// insertRecovered inserts FEC-reconstructed packets into the receive buffer.
func (c *Conn) insertRecovered(now clock.Timestamp, rec []filter.RecoveredPacket) {
	for _, rp := range rec {
		p := packet.NewData(nil, rp.SeqNo, rp.Timestamp, c.peerSocketID, rp.Payload)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		p.Header.Encryption = packet.PacketEncryption(rp.EncFlag)
		p.Header.Retransmitted = true
		if !c.decrypt(&p) { // no-op for unencrypted; recovered ciphertext otherwise
			p.Release()
			continue
		}
		if c.recvBuf.Insert(p, now).Inserted {
			c.recvPackets++
			c.recvBytes += uint64(len(p.Data))
			c.recvFECRecov++
		} else {
			p.Release()
		}
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

// emitData copies a delivered single packet's payload into an owned slice and
// queues it as a DataReceived event (with its sequence number for bonding dedup
// and per-message metadata), releasing the pooled packet buffer.
func (c *Conn) emitData(p packet.Packet) {
	data := make([]byte, len(p.Data))
	copy(data, p.Data)
	c.events.push(DataReceived{
		Data:     data,
		Seq:      p.Header.SequenceNumber,
		MsgNo:    p.Header.MessageNumber,
		Boundary: int(p.Header.PacketPosition),
	})
	p.Release()
}

// emitMessage concatenates a reassembled message's fragments into one owned
// payload and queues it as a single DataReceived event. The metadata is taken
// from the first fragment: its message number, its sequence number (the
// message's first), and the boundary it carries (PB_SINGLE for a one-packet
// message, PB_FIRST for a fragmented one).
func (c *Conn) emitMessage(pkts []packet.Packet) {
	total := 0
	for _, p := range pkts {
		total += len(p.Data)
	}
	data := make([]byte, 0, total)
	for _, p := range pkts {
		data = append(data, p.Data...)
	}
	first := pkts[0].Header
	c.events.push(DataReceived{
		Data:     data,
		Seq:      first.SequenceNumber,
		MsgNo:    first.MessageNumber,
		Boundary: int(first.PacketPosition),
	})
	for _, p := range pkts {
		p.Release()
	}
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
	c.sentACKs++
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
	c.sentACKs++
}

func (c *Conn) handleACK(now clock.Timestamp, p packet.Packet) {
	var ack packet.CIFACK
	if err := p.UnmarshalCIF(&ack); err != nil {
		return
	}
	c.recvACKs++
	isLite := len(p.Data) == 4
	ackd := c.sendBuf.ACK(seq.Number(ack.LastACKPacketSequenceNumber))

	// Only ACK *progress* (the ack point advancing) resets the RTO clock and the
	// backoff. Redundant periodic ACKs that re-confirm the same point must not, or
	// a stalled tail (acked-up-to-here, nothing new) would keep the EXP timer from
	// ever firing.
	if ackd > 0 {
		c.lastACKTime = now
		c.rexmitCount = 1
	}

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
		c.sentACKACKs++
		c.lastACKACKTime = now
		c.lastACKACKSeq = ackSubNo
	}

	// Adopt the peer's reported flow window and RTT estimate.
	c.rcvFlowWin = int(ack.AvailableBufferSize)
	if ack.RTT > 0 {
		c.rtt = clock.Microseconds(ack.RTT)
		c.rttVar = clock.Microseconds(ack.RTTVariance)
	}
	c.sendCC.OnACK(now, ack.LastACKPacketSequenceNumber, c.rtt, ack.EstimatedLinkCapacity, ack.PacketsReceivingRate)
	c.pump(now)
}

func (c *Conn) handleACKACK(now clock.Timestamp, p packet.Packet) {
	c.recvACKACKs++
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

	// TSBPD drift sample from the ACKACK timestamp (the sender's clock), with the
	// raw round-trip from this pair — not the smoothed EWMA — so the drift tracer
	// sees instantaneous path-delay measurements.
	if c.tsbpdTimer != nil {
		rttSample := int64(-1)
		if rtt > 0 && rtt < rttSanityCap {
			rttSample = int64(rtt)
		}
		c.tsbpdTimer.UpdateWrap(p.Header.Timestamp)
		c.tsbpdTimer.OnACK(p.Header.Timestamp, now, rttSample)
	}
}

// ---- NAK ----

// reportGap reports a newly detected loss range [gapStart, gapEnd], frontier
// being the just-received sequence number (gapEnd+1). With reorder tolerance
// disabled it NAKs the whole gap immediately. Otherwise it NAKs the part already
// beyond the reorder window and defers the last reorderTolerance sequence numbers
// (closest to the frontier) — a reordered packet still has time to arrive before
// they are reported as lost.
func (c *Conn) reportGap(now clock.Timestamp, gapStart, gapEnd, frontier uint32) {
	if c.reorderTolerance == 0 || c.deferredLoss == nil {
		c.sendImmediateNAK(now, gapStart, gapEnd)
		return
	}
	startN, endN := seq.Number(gapStart), seq.Number(gapEnd)
	gapSize := int(startN.Distance(endN)) + 1
	if gapSize <= c.reorderTolerance {
		c.deferGap(startN, endN) // whole gap is within the reorder window
		return
	}
	// Defer the last reorderTolerance sequence numbers; NAK everything before them.
	deferStart := endN
	for i := 0; i < c.reorderTolerance-1; i++ {
		deferStart = deferStart.Dec()
	}
	c.sendImmediateNAK(now, gapStart, deferStart.Dec().Value())
	c.deferGap(deferStart, endN)
}

// deferGap records the inclusive sequence range [start, end] as deferred losses.
func (c *Conn) deferGap(start, end seq.Number) {
	for s := start; ; s = s.Inc() {
		c.deferredLoss[s.Value()] = struct{}{}
		if s == end {
			break
		}
	}
}

// flushDeferredLoss NAKs any deferred loss that has fallen more than
// reorderTolerance packets behind the received frontier — it was a genuine loss,
// not reordering, so report it now.
func (c *Conn) flushDeferredLoss(now clock.Timestamp, frontier uint32) {
	fr := seq.Number(frontier)
	for s := range c.deferredLoss {
		if int(seq.Number(s).Distance(fr)) > c.reorderTolerance {
			c.sendImmediateNAK(now, s, s)
			delete(c.deferredLoss, s)
		}
	}
}

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
	c.sentNAKs++
}

func (c *Conn) handleNAK(now clock.Timestamp, p packet.Packet) {
	var nak packet.CIFNAK
	if err := p.UnmarshalCIF(&nak); err != nil {
		return
	}
	c.recvNAKs++
	c.lostPackets += uint64(len(nak.LossList))
	c.sendCC.OnNAK(nak.LossList)

	var rexmit []packet.Packet
	if c.rtt > 0 {
		rexmit = c.sendBuf.NAKTimed(nak.LossList, now, c.rtt, c.rttVar)
	} else {
		rexmit = c.sendBuf.NAK(nak.LossList)
	}
	for _, rp := range rexmit {
		c.retransPackets++
		c.retransBytes += uint64(len(rp.Data))
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
