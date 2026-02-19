package srt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zsiec/srtgo/internal/buffer"
	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/congestion"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/filter"
	"github.com/zsiec/srtgo/internal/handshake"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
	"github.com/zsiec/srtgo/internal/tsbpd"
)

// Connection timing constants
const (
	synInterval           = 10 * time.Millisecond  // SRT SYN interval (10ms) — Full ACK period
	liteACKPeriod         = 64                     // SELF_CLOCK_INTERVAL for Lite ACK
	keepalivePeriod       = 1 * time.Second        // KeepAlive interval
	initialRTT            = 100 * time.Millisecond // Initial RTT estimate
	defaultMinNAKInterval = 300 * time.Millisecond // initial minimum NAK interval (overridden by CC)
	minExpInterval        = 300 * time.Millisecond // minimum EXP interval per SRT spec
	maxExpCount           = 16                     // COMM_RESPONSE_MAX_EXP
)

// watchChannels holds the mirror channels for Watcher integration.
type watchChannels struct {
	readReady  chan struct{}
	writeReady chan struct{}
}

// Conn is an SRT connection that implements net.Conn.
//
// Each connection runs exactly 3 goroutines:
//   - recvLoop: reads packets from the mux channel, processes control packets,
//     inserts data packets into the receive buffer
//   - timerLoop: 10ms ticker drives periodic events (ACK, NAK, keepalive, TSBPD)
//   - application goroutine: calls Read/Write on the connection
type Conn struct {
	// Configuration
	localAddr      net.Addr
	remoteAddr     net.Addr
	socketID       uint32
	peerSocketID   uint32
	streamID       string
	isServer       bool
	peerSRTVersion uint32 // peer's SRT version from handshake (e.g., 0x010300 = v1.3.0)
	logger         Logger // diagnostic logger (nil = disabled, zero overhead)

	// Networking
	m           *mux.Mux
	ownsMux     bool // true if this connection owns the mux (client-side) and should close it
	recvC       <-chan packet.Packet
	clk         clock.Clock
	payloadSize int // max data payload per packet (MSS - IP/UDP/SRT headers)

	// Encryption
	cryptoCtx  *crypto.Context
	activeKey  packet.PacketEncryption
	passphrase string // for key rotation KMREQ/KMRSP

	// Key rotation state (kmConfirmed is set by recvLoop via handleKMResponse,
	// all other fields are only accessed from the Write goroutine unless noted)
	kmRefreshRate  uint64                  // packets before key switch (0 = disabled)
	kmPreAnnounce  uint64                  // packets before refresh to announce new key
	kmPacketCount  uint64                  // packets sent since last key rotation
	kmAnnounced    bool                    // true if new key has been announced
	kmConfirmed    atomic.Bool             // true once peer confirms via KMRSP (set from recvLoop)
	kmRetryKey     packet.PacketEncryption // which key slot the pending KMREQ is for
	kmRetryCount   int                     // remaining retry attempts (max 10)
	kmLastSendTime clock.Timestamp         // last KMREQ send time for RTT-based retry
	kmDecommission bool                    // true if old key needs decommission after switch
	kmSwitchCount  uint64                  // packets sent since last key switch (for decommission)
	sndKmState     atomic.Int32            // send KM state (0=unsecured,1=securing,2=secured,3=nosecret,4=badsecret,5=badcryptomode)
	rcvKmState     atomic.Int32            // recv KM state (same values)

	// Message mode
	messageAPI    bool         // true = message boundaries preserved; false = byte stream
	messageNumber uint32       // 26-bit wrapping counter (1 to 0x03FFFFFF, skip 0)
	msgTTL        atomic.Int64 // per-message TTL in nanoseconds (0 = none, set by WriteMsgCtrl)
	msgInOrder    atomic.Bool  // per-message in-order flag (set by WriteMsgCtrl)

	// Send state
	sendBuf         *buffer.SendBuffer
	sendISN         seq.Number
	sendCC          congestion.Controller
	smoothBW        atomic.Uint32      // IIR-8 smoothed bandwidth (pkts/sec) from ACK
	smoothDelivery  atomic.Uint32      // IIR-8 smoothed delivery rate (pkts/sec) from ACK
	nextSendTime    clock.Timestamp    // scheduled next send time (token-bucket pacing)
	sendTimeDiff    int64              // accumulated time credit in microseconds (drift compensation)
	tsbpdDelay      clock.Microseconds // negotiated TSBPD delay (receiver side)
	peerTsbpdDelay  clock.Microseconds // peer's TSBPD delay (sender side, for stats)
	sendDropThresh  clock.Microseconds // sender drop threshold: max(delay, 1s) + 20ms
	fc              int                // flow control window (max packets in flight)
	linger          time.Duration      // max wait for send buffer drain on Close
	peerIdleTimeout time.Duration      // peer inactivity timeout

	// Auto input rate sampling.
	// When MaxBW=0 and InputBW=0, sample actual write rate for LiveCC pacing.
	inputRateEnabled  bool            // true when both MaxBW=0 and InputBW=0
	inputRateStart    clock.Timestamp // start of current sampling window
	inputRateBytes    int64           // payload bytes accumulated in current window
	inputRatePkts     int64           // packets accumulated in current window
	inputRateBps      atomic.Int64    // computed input rate in bytes/sec
	inputRatePeriod   int64           // sampling period in microseconds
	inputRateOverhead int             // overhead percentage to apply
	inputRateMinBW    int64           // minimum input bandwidth (SRTO_MININPUTBW)

	// Buffer stats (direct field, avoids sync.Map per-packet lookup)
	bufStats bufferStatsState

	// Group membership (0 = not part of a group)
	groupID     uint32
	peerGroupID uint32

	// Group source timestamp coordination. When non-zero, Write uses this
	// timestamp instead of clk.Now() so all group members send packets with
	// the same source timestamp. Set by Group.Write before calling Conn.Write,
	// cleared after each Conn.Write returns.
	groupSrcTime atomic.Uint32

	// Group idle tracking. Set to true by the keepalive handler when a keepalive
	// is received and this connection belongs to a group. The group monitor reads
	// this flag to detect that the link is alive but idle (no data flowing), which
	// prevents false unstable transitions during data pauses.
	groupIdle atomic.Bool

	// Mode flags
	sndSyn           bool          // true = blocking Write (default), false = non-blocking
	rcvSyn           bool          // true = blocking Read (default), false = non-blocking
	tsbpdEnabled     bool          // false for file mode
	tlpktdropEnabled bool          // false for file mode
	periodicNAK      bool          // false for file mode
	peerNakReport    bool          // true if peer sends periodic NAK reports
	retransmitAlgo   int           // 0=always immediate, 1=timing gate (default 1 for live)
	minNAKInterval   time.Duration // CC-derived minimum NAK interval

	// Dynamic socket option fields (thread-safe for runtime Get/Set)
	congestionType     string       // "live" or "file"
	driftTracer        bool         // true = TSBPD drift correction enabled
	packetFilter       string       // negotiated FEC filter config
	minVersion         uint32       // minimum peer SRT version required
	enforcedEncryption bool         // true = encryption strictly enforced
	groupConnect       bool         // true = listener accepts grouped connections
	sndDropDelay       int          // extra sender drop delay in ms (-1 = disable)
	lossMaxTTL         atomic.Int32 // max reorder tolerance (atomic for SetOption)
	sndSynFlag         atomic.Bool  // dynamic blocking mode for Write
	rcvSynFlag         atomic.Bool  // dynamic blocking mode for Read
	sndTimeout         atomic.Int64 // send timeout in nanoseconds (0 = none)
	rcvTimeout         atomic.Int64 // receive timeout in nanoseconds (0 = none)

	// HSv4 backward compatibility
	hsVersion   int         // 4 or 5 (default 5)
	isInitiator bool        // true = HSREQ sender (HSv4: data sender; HSv5: caller)
	hsExtDone   atomic.Bool // true after HSREQ/HSRSP exchange completes

	// Receive state
	recvBuf       *buffer.RecvBuffer
	recvISN       seq.Number
	tsbpdTimer    *tsbpd.Timer
	streamPartial []byte // buffered partial packet data for stream-mode partial reads

	// Send timing
	lastSndTime atomic.Int64 // UnixNano of last packet sent (keepalive only fires when idle)

	// ACK/NAK state
	ackSeqNo        atomic.Uint32 // ACK sequence number (incremented per Full ACK)
	lastACKSeq      atomic.Uint32 // last ACK'd sequence number (seq.Number stored atomically)
	rcvLastAckAck   atomic.Uint32 // highest data seqno confirmed by peer's ACKACK
	lastFullACKTime atomic.Int64  // UnixNano timestamp of last Full ACK with extended fields (for 10ms gate)
	rcvPktCount     atomic.Int64  // received packet counter (reset on Full ACK)
	lightACKCount   atomic.Int32  // escalating lite ACK threshold multiplier
	peerActivity    atomic.Uint64 // bumped on any received packet (data or control) for timeout
	peerHealth      atomic.Bool   // false when PEERERROR received
	lastRecvSnap    uint64        // snapshot of peerActivity for timeout detection
	lastACKACKTime  atomic.Int64  // timestamp (UnixNano) of last ACKACK sent (for 10ms throttle)
	lastACKACKSeq   atomic.Uint32 // ACK seqno of last ACKACK sent (retransmit if same comes again)
	rtt             atomic.Int64  // RTT in microseconds
	rttVar          atomic.Int64  // RTT variance in microseconds
	lastACKRecv     atomic.Int64  // UnixNano timestamp of last ACK received (for RTO)
	rexmitCount     atomic.Int32  // linear backoff for RTO, reset to 1 on ACK
	ackSendTime     sync.Map      // map[uint32]ackSendInfo — ACK seq → {send time, data seqno} for RTT + ACKACK tracking
	sndLossCount    atomic.Int64  // outstanding loss count (approximate sender loss list length)
	flowWindowSize  atomic.Int32  // dynamic flow window from receiver's available buffer (0 = use FC)
	bufferWasFull   atomic.Bool   // forces Full ACK when buffer transitions from full to available

	// Deadlines
	readDeadline  atomic.Value // time.Time
	writeDeadline atomic.Value // time.Time

	// Signaling channels
	readReady  chan struct{} // signals that data may be available for Read
	writeReady chan struct{} // signals that send buffer space is available
	done       chan struct{} // signals connection shutdown
	closeOnce  sync.Once

	// Watcher mirror channels (nil until a Watcher registers this Conn).
	// These are separate from readReady/writeReady to avoid stealing signals
	// from Conn.Read()/Write(). Stored as atomic pointer for lock-free reads
	// on the hot path (signalReadReady/signalWriteReady).
	watchChans atomic.Pointer[watchChannels]

	// Statistics — packet counters
	sentPackets        atomic.Uint64
	sentBytes          atomic.Uint64 // payload bytes only
	retransCount       atomic.Uint64
	retransBytes       atomic.Uint64 // payload bytes for retransmitted packets
	recvPackets        atomic.Uint64
	recvBytes          atomic.Uint64 // payload bytes only
	recvRetrans        atomic.Uint64 // retransmitted packets received
	recvRetransBytes   atomic.Uint64 // payload bytes of retransmitted packets received
	lostPackets        atomic.Uint64 // lost at sender side (from NAKs)
	recvLoss           atomic.Uint64 // packets detected as missing at receiver (gap detection)
	recvDropped        atomic.Uint64 // packets dropped due to too-late arrival
	sentDropped        atomic.Uint64 // packets dropped from send buffer (too late)
	sentDroppedBytes   atomic.Uint64 // payload bytes of sender-dropped packets
	recvDroppedBytes   atomic.Uint64 // payload bytes of receiver-dropped packets
	recvBelated        atomic.Uint64 // packets that arrived after being dropped/ACK'd
	recvBelatedBytes   atomic.Uint64 // payload bytes of belated packets
	recvUndecrypt      atomic.Uint64 // packets that failed decryption
	recvUndecryptBytes atomic.Uint64 // payload bytes of undecrypted packets
	sentACKs           atomic.Uint64
	sentNAKs           atomic.Uint64
	sentACKACKs        atomic.Uint64
	recvACKs           atomic.Uint64
	recvNAKs           atomic.Uint64
	recvACKACKs        atomic.Uint64
	sentKM             atomic.Uint64 // KMREQ packets sent
	recvKM             atomic.Uint64 // KMREQ/KMRSP packets received
	startTime          time.Time     // connection creation time

	// Send duration tracking: accumulated μs where send buffer was non-empty
	sndBusySince  atomic.Int64 // clock.Timestamp when buffer became non-empty (0 = idle)
	sndDurationUs atomic.Int64 // accumulated sender-busy microseconds

	// Reorder distance: max out-of-order distance observed at receiver
	maxRecvSeq      atomic.Uint32 // highest received sequence number (for reorder tracking)
	maxRecvSeqInit  atomic.Bool   // whether maxRecvSeq has been initialized
	reorderDistance atomic.Int32  // maximum observed reorder distance

	// FreshLoss: deferred NAK with reorder tolerance.
	// Gated by maxReorderTolerance > 0 (SRTO_LOSSMAXTTL).
	// All fields below are accessed only from recvLoop goroutine.
	maxReorderTolerance   int              // config: max allowed tolerance (0 = disabled)
	reorderTolerance      int              // current dynamic tolerance (packets)
	freshLoss             []freshLossEntry // deque of pending loss ranges
	consecEarlyDelivery   int              // counts OOO packets arriving with had_ttl > 2
	consecOrderedDelivery int              // counts in-order / retransmitted packets

	// Retransmit rate limiting (SRTO_MAXREXMITBW)
	rexmitShaper *rexmitTokenBucket // nil if unlimited

	// FEC (Forward Error Correction)
	fecSender   *filter.FECSender   // nil if FEC disabled
	fecReceiver *filter.FECReceiver // nil if FEC disabled
	fecARQLevel filter.ARQLevel     // ARQ cooperation level for FEC

	// FEC stats (atomic)
	sndFilterExtra  atomic.Uint64
	rcvFilterExtra  atomic.Uint64
	rcvFilterSupply atomic.Uint64
	rcvFilterLoss   atomic.Uint64

	// Belated arrival time: EWMA lateness of belated packets (factor 0.2)
	recvBelatedTimeAvg atomic.Int64 // EWMA of belated delay in microseconds

	// Interval tracking (protected by statsMu)
	statsMu      sync.Mutex
	lastSnapshot ConnStats // snapshot from last Stats(true) call

	// Stats callback
	statsCallback atomic.Pointer[statsCallbackState]

	// Shutdown
	shutdownErr error
	shutdownMu  sync.Mutex
}

// ackSendInfo stores metadata for a sent ACK, used when ACKACK arrives.
type ackSendInfo struct {
	sendTime clock.Timestamp // when the ACK was sent (for RTT measurement)
	dataSeq  uint32          // data sequence number that was ACK'd
}

// rexmitTokenBucket is a simple token bucket for retransmit rate limiting.
// It allows bursting up to 1 RTT worth of tokens and refills at maxBytesPerSec.
type rexmitTokenBucket struct {
	maxBytesPerSec int64
	tokens         int64 // available bytes
	lastRefill     int64 // UnixNano of last refill
}

// newRexmitTokenBucket creates a token bucket with the given max bandwidth.
func newRexmitTokenBucket(maxBytesPerSec int64) *rexmitTokenBucket {
	return &rexmitTokenBucket{
		maxBytesPerSec: maxBytesPerSec,
		tokens:         maxBytesPerSec / 10, // initial burst: 100ms worth
		lastRefill:     time.Now().UnixNano(),
	}
}

// allow checks if the given number of bytes can be sent. If yes, deducts from
// the bucket and returns true. Otherwise returns false (skip this retransmit).
func (tb *rexmitTokenBucket) allow(bytes int) bool {
	now := time.Now().UnixNano()
	elapsed := now - tb.lastRefill
	if elapsed > 0 {
		// Refill tokens based on elapsed time
		refill := tb.maxBytesPerSec * elapsed / 1_000_000_000
		tb.tokens += refill
		// Cap at 1 second worth of tokens
		if tb.tokens > tb.maxBytesPerSec {
			tb.tokens = tb.maxBytesPerSec
		}
		tb.lastRefill = now
	}
	if tb.tokens >= int64(bytes) {
		tb.tokens -= int64(bytes)
		return true
	}
	return false
}

// freshLossEntry represents a range of lost sequence numbers with a TTL.
// When TTL reaches 0, the loss is reported via NAK. This defers NAK to
// allow out-of-order packets to arrive within the reorder tolerance.
type freshLossEntry struct {
	seqLo uint32 // first lost sequence number
	seqHi uint32 // last lost sequence number (inclusive)
	ttl   int    // time-to-live: decremented per received packet
}

// ConnConfig contains the parameters for creating a new SRT connection.
type ConnConfig struct {
	LocalAddr    net.Addr
	RemoteAddr   net.Addr
	SocketID     uint32
	PeerSocketID uint32
	StreamID     string
	IsServer     bool

	Mux      *mux.Mux
	OwnsMux  bool // true for client-side connections (Dial creates its own mux)
	RecvChan <-chan packet.Packet
	Clock    clock.Clock

	SendISN seq.Number
	RecvISN seq.Number

	SendBufSize         int                     // packets
	RecvBufSize         int                     // packets
	MaxBW               int64                   // bytes/sec
	TsbpdDelay          time.Duration           // local TSBPD receive latency
	PeerTsbpdDelay      time.Duration           // peer's TSBPD receive latency (for sender-side drop)
	FC                  int                     // flow control window (packets)
	PayloadSize         int                     // max payload per packet (0 = default 1456)
	CryptoCtx           *crypto.Context         // encryption context (nil = unencrypted)
	ActiveKey           packet.PacketEncryption // which key slot to use for encryption
	Linger              time.Duration           // max wait for send buffer drain on Close
	PeerIdleTimeout     time.Duration           // peer inactivity timeout
	Passphrase          string                  // for key rotation (KMREQ/KMRSP)
	KMRefreshRate       uint64                  // packets before key switch (0 = disabled)
	KMPreAnnounce       uint64                  // packets before refresh to announce new key
	MessageAPI          bool                    // true = message boundaries preserved
	Congestion          CongestionType          // "live" or "file" (empty = "live")
	NAKReport           bool                    // true = enable periodic NAK reports
	PeerNakReport       bool                    // true if peer sends periodic NAK reports
	RetransmitAlgo      int                     // SRTO_RETRANSMITALGO: 0=always immediate, 1=timing gate
	LossMaxTTL          int                     // max reorder tolerance (0 = disabled)
	SndDropDelay        int                     // extra sender drop delay in ms (-1 = disable)
	InputBW             int64                   // estimated input bandwidth (bytes/sec, 0 = unused)
	MinInputBW          int64                   // minimum input bandwidth for auto-rate (bytes/sec)
	OverheadBW          int                     // bandwidth overhead percentage
	DriftTracer         bool                    // true = enable TSBPD drift correction (default true)
	PeerSRTVersion      uint32                  // peer's SRT version from handshake HSRSP
	PeerStartTime       uint32                  // peer's timestamp from handshake (for TSBPD timebase)
	PacketFilter        string                  // negotiated FEC filter config ("" = disabled)
	GroupID             uint32                  // local group ID (0 = not grouped)
	PeerGroupID         uint32                  // peer's group ID (0 = not grouped)
	GroupType           uint8                   // group type (1=broadcast, 2=backup)
	GroupWeight         uint16                  // member weight for group operations
	SndSyn              bool                    // true = blocking Write (default)
	RcvSyn              bool                    // true = blocking Read (default)
	MaxRexmitBW         int64                   // max retransmit bandwidth (bytes/sec, 0 = unlimited)
	MinVersion          uint32                  // minimum peer SRT version
	EnforcedEncryption  bool                    // true = encryption strictly enforced
	GroupConnectEnabled bool                    // true = listener accepts grouped connections
	Logger              Logger                  // diagnostic logger (nil = disabled)
}

func newConn(cfg ConnConfig) *Conn {
	if cfg.Clock == nil {
		cfg.Clock = clock.NewRealClock()
	}
	if cfg.SendBufSize <= 0 {
		cfg.SendBufSize = 8192
	}
	if cfg.RecvBufSize <= 0 {
		cfg.RecvBufSize = 8192
	}
	if cfg.FC <= 0 {
		cfg.FC = 8192
	}
	if cfg.PeerIdleTimeout <= 0 {
		cfg.PeerIdleTimeout = 5 * time.Second
	}

	// Derive mode from congestion type
	isFileMode := cfg.Congestion == CongestionFile
	tsbpdEnabled := !isFileMode
	tlpktdropEnabled := !isFileMode

	var tsbpdDelay clock.Microseconds
	var sendDropThresh clock.Microseconds
	if tsbpdEnabled {
		tsbpdDelay = clock.FromDuration(cfg.TsbpdDelay)
		if tsbpdDelay <= 0 {
			tsbpdDelay = 120 * clock.Millisecond
		}
		// Sender drop threshold:
		//   threshold = max(peerDelay + sndDropDelay, minThreshold) + 2*SYN
		// Uses the PEER's TSBPD delay, not our own receive delay.
		// SndDropDelay == -1 disables sender-side drop (threshold stays 0).
		if cfg.SndDropDelay >= 0 {
			peerDelay := clock.FromDuration(cfg.PeerTsbpdDelay)
			if peerDelay <= 0 {
				peerDelay = tsbpdDelay // fallback to local delay if peer delay unknown
			}
			extraDelay := clock.Microseconds(cfg.SndDropDelay) * clock.Millisecond
			sendDropThresh = peerDelay + extraDelay
			if sendDropThresh < 1*clock.Second {
				sendDropThresh = 1 * clock.Second
			}
			sendDropThresh += 20 * clock.Millisecond
		}
	}

	sendBufCap := cfg.SendBufSize

	payloadSize := cfg.PayloadSize
	if payloadSize <= 0 {
		payloadSize = packet.MaxPayloadSize
	}

	// Compute effective bandwidth:
	// - MaxBW > 0: use directly (explicit, no overhead)
	// - MaxBW == 0 && InputBW > 0: InputBW * (1 + overhead/100)
	// - Both 0: DefaultMaxBW (125 MB/s = 1 Gbps)
	effectiveBW := cfg.MaxBW
	if effectiveBW <= 0 && cfg.InputBW > 0 {
		effectiveBW = cfg.InputBW * int64(100+cfg.OverheadBW) / 100
	} else if effectiveBW <= 0 {
		effectiveBW = congestion.DefaultMaxBW
	}

	// Create congestion controller based on mode.
	// Two separate payload size concepts:
	// - maxPayloadSize = MSS - 44 = 1456 — for fragmentation limits
	// - expected payload size — for CC pacing
	//   Live mode: 1316 (SRT_LIVE_DEF_PLSIZE), File mode: 0 (→ maxPayloadSize)
	// For LiveCC, pass 0 to use DefaultPacketSize (1316).
	// For FileCC, pass maxPayloadSize since file mode's expected size=0
	// falls back to maxPayloadSize in the CC constructor.
	var cc congestion.Controller
	if isFileMode {
		cc = congestion.NewFileCC(effectiveBW, payloadSize, cfg.FC, cfg.SendISN.Value())
	} else {
		cc = congestion.NewLiveCC(effectiveBW, 0) // 0 → DefaultPacketSize (1316)
	}

	// TSBPD timer: only created when TSBPD is enabled.
	// TimeBase = now - peerTimestamp (from handshake CONCLUSION packet).
	var tsbpdTimer *tsbpd.Timer
	if tsbpdEnabled {
		now := cfg.Clock.Now()
		peerTS := clock.Microseconds(cfg.PeerStartTime)
		timeBase := now.Add(-peerTS)
		tsbpdTimer = tsbpd.New(tsbpdDelay, timeBase)
		if !cfg.DriftTracer {
			tsbpdTimer.SetDriftEnabled(false)
		}
	}

	c := &Conn{
		localAddr:      cfg.LocalAddr,
		remoteAddr:     cfg.RemoteAddr,
		socketID:       cfg.SocketID,
		peerSocketID:   cfg.PeerSocketID,
		ownsMux:        cfg.OwnsMux,
		streamID:       cfg.StreamID,
		isServer:       cfg.IsServer,
		peerSRTVersion: cfg.PeerSRTVersion,
		logger:         cfg.Logger,
		groupID:        cfg.GroupID,
		peerGroupID:    cfg.PeerGroupID,

		m:             cfg.Mux,
		recvC:         cfg.RecvChan,
		clk:           cfg.Clock,
		payloadSize:   payloadSize,
		cryptoCtx:     cfg.CryptoCtx,
		activeKey:     cfg.ActiveKey,
		passphrase:    cfg.Passphrase,
		kmRefreshRate: cfg.KMRefreshRate,
		kmPreAnnounce: cfg.KMPreAnnounce,
		messageAPI:    cfg.MessageAPI,
		messageNumber: 1,

		sendBuf:         buffer.NewSendBuffer(sendBufCap, cfg.SendISN),
		sendISN:         cfg.SendISN,
		sendCC:          cc,
		tsbpdDelay:      tsbpdDelay,
		peerTsbpdDelay:  clock.FromDuration(cfg.PeerTsbpdDelay),
		sendDropThresh:  sendDropThresh,
		fc:              cfg.FC,
		linger:          cfg.Linger,
		peerIdleTimeout: cfg.PeerIdleTimeout,

		sndSyn:           cfg.SndSyn,
		rcvSyn:           cfg.RcvSyn,
		tsbpdEnabled:     tsbpdEnabled,
		tlpktdropEnabled: tlpktdropEnabled,
		periodicNAK:      !isFileMode && cfg.NAKReport, // disabled for file mode
		peerNakReport:    cfg.PeerNakReport,
		retransmitAlgo:   cfg.RetransmitAlgo,

		recvBuf:    buffer.NewRecvBuffer(cfg.RecvBufSize, cfg.RecvISN),
		recvISN:    cfg.RecvISN,
		tsbpdTimer: tsbpdTimer,

		maxReorderTolerance: cfg.LossMaxTTL,
		reorderTolerance:    cfg.LossMaxTTL,

		// Dynamic socket option state
		congestionType:     string(cfg.Congestion),
		driftTracer:        cfg.DriftTracer,
		packetFilter:       cfg.PacketFilter,
		minVersion:         cfg.MinVersion,
		enforcedEncryption: cfg.EnforcedEncryption,
		groupConnect:       cfg.GroupConnectEnabled,
		sndDropDelay:       cfg.SndDropDelay,

		readReady:  make(chan struct{}, 1),
		writeReady: make(chan struct{}, 1),
		done:       make(chan struct{}),
	}

	// Initialize atomic socket option fields
	c.sndSynFlag.Store(cfg.SndSyn)
	c.rcvSynFlag.Store(cfg.RcvSyn)
	c.lossMaxTTL.Store(int32(cfg.LossMaxTTL))
	if cfg.Congestion == "" {
		c.congestionType = "live"
	}

	c.peerHealth.Store(true) // starts as healthy

	// Initialize KM state:
	// When crypto is configured: SECURED(2) after successful handshake.
	// When no crypto: UNSECURED(0).
	if cfg.CryptoCtx != nil {
		c.sndKmState.Store(2) // SECURED
		c.rcvKmState.Store(2) // SECURED
	}

	// Pre-allocate freshLoss when reorder tolerance is enabled
	if cfg.LossMaxTTL > 0 {
		c.freshLoss = make([]freshLossEntry, 0, 32)
	}

	// Retransmit rate limiting
	if cfg.MaxRexmitBW > 0 {
		c.rexmitShaper = newRexmitTokenBucket(cfg.MaxRexmitBW)
	}

	// Auto input rate: enabled when both MaxBW=0 and InputBW=0.
	// Samples write rate and periodically updates LiveCC pacing.
	if cfg.MaxBW <= 0 && cfg.InputBW <= 0 && !isFileMode {
		c.inputRateEnabled = true
		c.inputRatePeriod = 500000 // 500ms fast start
		c.inputRateOverhead = cfg.OverheadBW
		c.inputRateMinBW = cfg.MinInputBW
	}

	// Set CC-derived minimum NAK interval (overrides the initial 300ms
	// when the CC is attached). LiveCC → 20ms, FileCC → 300ms.
	if ccMin := cc.MinNAKInterval(); ccMin > 0 {
		c.minNAKInterval = time.Duration(ccMin) * time.Microsecond
	} else {
		c.minNAKInterval = defaultMinNAKInterval
	}

	// Wire TSBPD UpdateWrap callbacks into the receive buffer.
	// updateTsbPdTimeBase is called when reading or dropping packets.
	if tsbpdTimer != nil {
		c.recvBuf.SetOnRead(func(pktTimestamp uint32) {
			tsbpdTimer.UpdateWrap(pktTimestamp)
		})
		c.recvBuf.SetOnDrop(func(pktTimestamp uint32) {
			tsbpdTimer.UpdateWrap(pktTimestamp)
		})
	}

	c.rtt.Store(int64(clock.FromDuration(initialRTT)))
	c.rttVar.Store(int64(clock.FromDuration(initialRTT / 2)))
	c.lastSndTime.Store(time.Now().UnixNano())
	c.storeLastACKSeq(cfg.RecvISN)
	c.rcvLastAckAck.Store(cfg.RecvISN.Value()) // initialize to ISN
	c.lightACKCount.Store(1)                   // start at 1
	c.startTime = time.Now()

	// GCM 1.5.3 backward compatibility: detect old nonce format
	// for peers at or below SRT v1.5.3 (matches C++ SRT_VERSION_FEAT_GCM153).
	// The > 0 guard prevents legacy-mode activation for HSv4 peers (PeerSRTVersion=0).
	if c.cryptoCtx != nil && c.cryptoCtx.Mode() == crypto.CipherGCM {
		if cfg.PeerSRTVersion > 0 && cfg.PeerSRTVersion <= 0x010503 {
			c.cryptoCtx.SetGCM153(true)
		}
	}

	// Initialize FEC if configured
	if cfg.PacketFilter != "" {
		fecCfg, _ := filter.ParseConfig(cfg.PacketFilter) // already validated
		c.fecSender = filter.NewFECSender(fecCfg, payloadSize, cfg.SendISN.Value())
		c.fecReceiver = filter.NewFECReceiver(fecCfg, payloadSize, cfg.RecvISN.Value())
		c.fecARQLevel = fecCfg.ARQ
	}

	go c.recvLoop()
	go c.timerLoop()

	return c
}

// TSBPDTimeBase returns the TSBPD timer's internal state for group synchronization.
// Returns nil GroupTimeBase fields if TSBPD is not enabled.
func (c *Conn) TSBPDTimeBase() *tsbpd.GroupTimeBase {
	if c.tsbpdTimer == nil {
		return nil
	}
	tb := c.tsbpdTimer.GetInternalTimeBase()
	return &tb
}

// ApplyGroupDrift synchronizes this connection's TSBPD drift with a group member's
// state. Used by Group to keep all members' delivery times aligned.
func (c *Conn) ApplyGroupDrift(tb tsbpd.GroupTimeBase) {
	if c.tsbpdTimer != nil {
		c.tsbpdTimer.ApplyGroupDrift(tb)
	}
}

// ApplyGroupTime synchronizes this connection's full TSBPD state with the group.
// Used when a new member joins the group and needs to adopt the group's time reference.
func (c *Conn) ApplyGroupTime(tb tsbpd.GroupTimeBase) {
	if c.tsbpdTimer != nil {
		c.tsbpdTimer.ApplyGroupTime(tb, c.tsbpdTimer.Delay())
	}
}

// SetGroupSrcTime sets the group-coordinated source timestamp for the next Write.
// All members of a group should be set to the same srctime before calling Write.
func (c *Conn) SetGroupSrcTime(ts uint32) {
	c.groupSrcTime.Store(ts)
}

// ClearGroupSrcTime clears the group source timestamp so Write uses real time.
func (c *Conn) ClearGroupSrcTime() {
	c.groupSrcTime.Store(0)
}

// isConnected returns true if this connection has been fully initialized
// (handshake completed, recvLoop/timerLoop running) and has not been shut down.
// Used by Group to detect when a pending member's handshake has completed.
func (c *Conn) isConnected() bool {
	if c.sendBuf == nil {
		return false // not yet initialized (newConn not called)
	}
	select {
	case <-c.done:
		return false // connection has been shut down
	default:
		return true
	}
}

// getRateEstimate returns the current send rate in bytes/sec from the
// congestion controller. Used by Group for rate estimator transfer on
// backup mode failover to newly activated standby links.
func (c *Conn) getRateEstimate() int64 {
	if c.sendCC == nil {
		return 0
	}
	return c.sendCC.MaxBandwidth()
}

// setRateEstimate sets the initial send rate on the congestion controller.
// Used by Group to transfer the rate estimate from an active link to a
// newly activated standby link during backup mode failover.
func (c *Conn) setRateEstimate(rate int64) {
	if c.sendCC == nil || rate <= 0 {
		return
	}
	c.sendCC.SetMaxBandwidth(rate)
}

// CurrentSRTTimestamp returns the current SRT timestamp from this connection's clock.
// Used by Group to obtain a common source timestamp for all members.
func (c *Conn) CurrentSRTTimestamp() uint32 {
	return c.clk.Now().SRTTimestamp()
}

// SchedSeqNo returns the next sequence number that would be used for sending.
// Used by the Group to synchronize sequence numbers across members.
func (c *Conn) SchedSeqNo() seq.Number {
	return c.sendBuf.NextSeq()
}

// OverrideSndSeqNo overrides the send sequence number to match the group's
// scheduling sequence. This aligns a newly-activated member's send sequence
// with the group so all members share the same sequence space.
//
// seq is the next sequence number to be sent (the send buffer's nextSeq).
// Returns true if the override was applied.
func (c *Conn) OverrideSndSeqNo(nextSeq seq.Number) bool {
	if c.sendBuf == nil {
		return false
	}
	return c.sendBuf.OverrideNextSeq(nextSeq)
}

// ---- net.Conn interface ----

// Read reads data from the connection. It blocks until data is available
// or the read deadline expires.
//
// In message mode with multi-packet messages, Read returns a complete
// reassembled message (all packets from PP_FIRST through PP_LAST concatenated).
// In stream mode, Read returns data from the next available packet.
func (c *Conn) Read(b []byte) (int, error) {
	for {
		if c.tsbpdEnabled {
			// Live mode: TSBPD-aware read with too-late drop
			now := c.clk.Now()
			if dropped := c.recvBuf.DropTooLate(now, c.tsbpdTimer.DeliveryTime); dropped > 0 {
				c.recvDropped.Add(uint64(dropped))
				c.recvDroppedBytes.Add(uint64(dropped) * uint64(c.payloadSize))
			}
			p, ok := c.recvBuf.ReadTSBPD(now, c.tsbpdTimer.DeliveryTime)
			if ok {
				n := copy(b, p.Data)
				p.Release()
				return n, nil
			}
		} else if c.messageAPI {
			// File/message mode: read complete multi-packet messages.
			// Read complete multi-packet messages (walks from PP_FIRST to PP_LAST).
			pkts, ok := c.recvBuf.ReadMessage()
			if ok {
				n := 0
				for _, p := range pkts {
					copied := copy(b[n:], p.Data)
					n += copied
					p.Release()
				}
				return n, nil
			}
		} else {
			// File/stream mode: sequential in-order delivery, no message boundaries.
			// If a previous read returned a partial packet, continue from where
			// we left off before fetching new packets.
			if len(c.streamPartial) > 0 {
				n := copy(b, c.streamPartial)
				if n < len(c.streamPartial) {
					c.streamPartial = c.streamPartial[n:]
				} else {
					c.streamPartial = nil
				}
				return n, nil
			}
			p, ok := c.recvBuf.ReadNext()
			if ok {
				n := copy(b, p.Data)
				if n < len(p.Data) {
					// Partial read: buffer the remainder for the next Read call.
					c.streamPartial = make([]byte, len(p.Data)-n)
					copy(c.streamPartial, p.Data[n:])
				}
				p.Release()
				return n, nil
			}
		}

		// No data ready
		if !c.rcvSynFlag.Load() {
			return 0, ErrWouldBlock
		}

		// Wait for signal or deadline
		dl := c.readDeadlineTime()
		if !dl.IsZero() && time.Now().After(dl) {
			return 0, &net.OpError{Op: "read", Net: "srt", Err: errors.New("i/o timeout")}
		}

		var timer *time.Timer
		var timerC <-chan time.Time
		if !dl.IsZero() {
			timer = time.NewTimer(time.Until(dl))
			timerC = timer.C
		}

		select {
		case <-c.readReady:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timerC:
			return 0, &net.OpError{Op: "read", Net: "srt", Err: errors.New("i/o timeout")}
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, c.getShutdownErr()
		}
	}
}

// Write writes data to the connection. It blocks until the send buffer
// has space or the write deadline expires.
//
// In live mode (TSBPD), the data must fit in a single packet (max payloadSize
// bytes); multi-packet messages are rejected in TSBPD mode.
// In file mode, large messages are automatically fragmented into multiple
// packets with PP_FIRST/PP_MIDDLE/PP_LAST boundaries sharing the same message
// number.
func (c *Conn) Write(b []byte) (int, error) {
	select {
	case <-c.done:
		return 0, c.getShutdownErr()
	default:
	}

	// Check peer health before sending.
	if !c.peerHealth.Load() {
		return 0, errors.New("srt: peer error")
	}

	// Validate API compatibility per CC algorithm.
	if c.sendCC != nil {
		if err := c.sendCC.CheckTransArgs(c.messageAPI, len(b), true); err != nil {
			return 0, err
		}
	}

	// Drop packets past the TSBPD deadline before queuing new data.
	if c.tlpktdropEnabled {
		c.checkSendDrop()
	}

	// In live/TSBPD mode, reject multi-packet messages.
	if c.tsbpdEnabled && len(b) > c.payloadSize {
		return 0, fmt.Errorf("srt: payload size %d exceeds maximum %d", len(b), c.payloadSize)
	}

	// In message mode, check max message size (sendBufSize * payloadSize).
	if c.messageAPI && len(b) > c.sendBuf.Capacity()*c.payloadSize {
		return 0, fmt.Errorf("srt: message size %d exceeds send buffer capacity %d", len(b), c.sendBuf.Capacity()*c.payloadSize)
	}

	// Fragment data into packets
	numPkts := (len(b) + c.payloadSize - 1) / c.payloadSize
	if numPkts == 0 {
		numPkts = 1
	}
	msgNo := c.nextMessageNumber()

	// Single-packet path (common case for live mode)
	if numPkts == 1 {
		seqNo := c.sendBuf.NextSeq()
		// Use group-coordinated source timestamp when set, otherwise use current time.
		ts := c.groupSrcTime.Load()
		if ts == 0 {
			ts = c.clk.Now().SRTTimestamp()
		}
		p := packet.NewData(c.remoteAddr, seqNo.Value(), ts, c.peerSocketID, b)
		p.Header.MessageNumber = msgNo
		p.Header.PacketPosition = packet.PositionSingle
		p.Header.Order = c.msgInOrder.Load()

		if err := c.sendPacket(p, len(b)); err != nil {
			return 0, err
		}
		return len(b), nil
	}

	// Multi-packet message path: pre-fragment all packets, push atomically to
	// send buffer, then send on wire. All fragments are inserted under a single lock.
	pkts := make([]packet.Packet, numPkts)
	chunkSizes := make([]int, numPkts)
	for i := 0; i < numPkts; i++ {
		start := i * c.payloadSize
		end := start + c.payloadSize
		if end > len(b) {
			end = len(b)
		}
		chunk := b[start:end]
		chunkSizes[i] = len(chunk)

		seqNo := c.sendBuf.NextSeq()
		// Use a stable sequence for pre-fragmentation: startSeq + i
		// (NextSeq won't advance until PushBatch, so all get same value)
		_ = seqNo
		// Use group-coordinated source timestamp when set.
		ts := c.groupSrcTime.Load()
		if ts == 0 {
			ts = c.clk.Now().SRTTimestamp()
		}
		p := packet.NewData(c.remoteAddr, 0, ts, c.peerSocketID, chunk)
		p.Header.MessageNumber = msgNo

		var pos packet.PacketPosition
		if i == 0 {
			pos |= packet.PositionFirst
		}
		if i == numPkts-1 {
			pos |= packet.PositionLast
		}
		p.Header.PacketPosition = pos
		p.Header.Order = c.msgInOrder.Load()

		// Set encryption key index before push so the send buffer stores
		// the correct Encryption field for retransmit clones.
		if c.cryptoCtx != nil {
			p.Header.Encryption = c.activeKey
		}

		pkts[i] = p
	}

	// Wait for flow control to have space for ALL packets, then push atomically.
	maxFlight := c.fc
	if fws := int(c.flowWindowSize.Load()); fws > 0 && fws < maxFlight {
		maxFlight = fws
	}
	if cwnd := c.sendCC.CongestionWindow(); cwnd < maxFlight {
		maxFlight = cwnd
	}

	for {
		// Assign sequence numbers right before pushing (they must be contiguous)
		nextSeq := c.sendBuf.NextSeq()
		for i := range pkts {
			pkts[i].Header.SequenceNumber = nextSeq.Add(uint32(i)).Value()
		}

		if c.flightSize()+numPkts <= maxFlight && c.sendBuf.PushBatch(pkts, c.clk.Now()) {
			// Per-message TTL: tag all fragments (matching single-packet path).
			if ttl := c.msgTTL.Load(); ttl > 0 {
				c.sendBuf.SetMsgTTLBatch(ttl, numPkts)
			}
			break
		}

		dl := c.writeDeadlineTime()
		if !dl.IsZero() && time.Now().After(dl) {
			for _, p := range pkts {
				p.Release()
			}
			return 0, &net.OpError{Op: "write", Net: "srt", Err: errors.New("i/o timeout")}
		}

		var timer *time.Timer
		var timerC <-chan time.Time
		if !dl.IsZero() {
			timer = time.NewTimer(time.Until(dl))
			timerC = timer.C
		}

		select {
		case <-c.writeReady:
			if timer != nil {
				timer.Stop()
			}
		case <-timerC:
			for _, p := range pkts {
				p.Release()
			}
			return 0, &net.OpError{Op: "write", Net: "srt", Err: errors.New("i/o timeout")}
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			for _, p := range pkts {
				p.Release()
			}
			return 0, c.getShutdownErr()
		}
	}

	// Track sender-busy duration
	c.sndBusySince.CompareAndSwap(0, int64(c.clk.Now()))

	// Send each packet on the wire with pacing
	totalSent := 0
	for i, p := range pkts {
		seqNo := seq.Number(p.Header.SequenceNumber)

		// Encrypt if encryption is enabled.
		// Encryption header was already set before PushBatch.
		if c.cryptoCtx != nil {
			var header []byte
			if c.cryptoCtx.Mode() == crypto.CipherGCM {
				var buf [16]byte
				p.Header.Marshal(buf[:])
				header = buf[:]
			}
			result, err := c.cryptoCtx.EncryptPayload(p.Data, header, p.Header.Encryption, seqNo.Value())
			if err != nil {
				return totalSent, fmt.Errorf("srt: encrypt: %w", err)
			}
			p.Data = result
		}

		if err := c.m.Send(p); err != nil {
			return totalSent, fmt.Errorf("srt: send: %w", err)
		}

		c.sendCC.OnPacketSent(seqNo.Value(), chunkSizes[i])
		c.sentPackets.Add(1)
		c.sentBytes.Add(uint64(chunkSizes[i]))
		c.recordSendRate(1, chunkSizes[i])

		// Auto input rate sampling
		c.updateInputRate(c.clk.Now(), 1, chunkSizes[i])

		// Key rotation check (only for encrypted connections)
		if c.cryptoCtx != nil && c.kmRefreshRate > 0 {
			c.checkKeyRotation()
		}

		// Pacing (skip for last packet to avoid unnecessary sleep)
		now := c.clk.Now()
		sendint := int64(c.sendCC.PacketInterval())
		if c.sendCC.IsProbePacket() {
			c.sendTimeDiff -= sendint
		} else if !c.nextSendTime.IsZero() {
			if now.After(c.nextSendTime) {
				c.sendTimeDiff += int64(now.Sub(c.nextSendTime))
			}
			if c.sendTimeDiff >= sendint {
				c.sendTimeDiff -= sendint
			} else {
				waitUS := sendint - c.sendTimeDiff
				time.Sleep(time.Duration(waitUS) * time.Microsecond)
				c.sendTimeDiff = 0
			}
		}
		c.nextSendTime = c.clk.Now()

		totalSent += chunkSizes[i]
	}

	return totalSent, nil
}

// sendPacket handles the common per-packet send logic: flow control, encryption,
// pacing, and statistics. Extracted from Write() to support multi-packet messages.
func (c *Conn) sendPacket(p packet.Packet, dataLen int) error {
	seqNo := seq.Number(p.Header.SequenceNumber)

	// Flow control backpressure: block if send buffer full or flight window reached.
	// cwnd = min(flowWindowSize, congestionWindow)
	maxFlight := c.fc
	if fws := int(c.flowWindowSize.Load()); fws > 0 && fws < maxFlight {
		maxFlight = fws
	}
	if cwnd := c.sendCC.CongestionWindow(); cwnd < maxFlight {
		maxFlight = cwnd
	}
	// Set encryption header BEFORE push so the send buffer stores the correct
	// key index. This is needed so retransmitted clones have the right Encryption
	// field for the receiver to select the correct decryption key.
	if c.cryptoCtx != nil {
		p.Header.Encryption = c.activeKey
	}

	for !(c.flightSize() < maxFlight && c.sendBuf.Push(p, c.clk.Now())) {
		if !c.sndSynFlag.Load() {
			p.Release()
			return ErrWouldBlock
		}
		dl := c.writeDeadlineTime()
		if !dl.IsZero() && time.Now().After(dl) {
			p.Release()
			return &net.OpError{Op: "write", Net: "srt", Err: errors.New("i/o timeout")}
		}

		var timer *time.Timer
		var timerC <-chan time.Time
		if !dl.IsZero() {
			timer = time.NewTimer(time.Until(dl))
			timerC = timer.C
		}

		select {
		case <-c.writeReady:
			if timer != nil {
				timer.Stop()
			}
		case <-timerC:
			p.Release()
			return &net.OpError{Op: "write", Net: "srt", Err: errors.New("i/o timeout")}
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			p.Release()
			return c.getShutdownErr()
		}
	}

	// Per-message TTL: tag the buffer entry (set by WriteMsgCtrl)
	if ttl := c.msgTTL.Load(); ttl > 0 {
		c.sendBuf.SetMsgTTL(ttl)
	}

	// Track sender-busy duration: if buffer was idle, mark busy start
	c.sndBusySince.CompareAndSwap(0, int64(c.clk.Now()))

	// Encrypt if encryption is enabled.
	// For CTR mode: encrypts in-place (modifies the shared buffer stored in the
	// send buffer entry), so retransmitted clones are already encrypted.
	// For GCM mode: returns a NEW buffer (ciphertext+tag). The send buffer entry
	// retains plaintext; retransmit paths must re-encrypt GCM packets.
	if c.cryptoCtx != nil {
		var header []byte
		if c.cryptoCtx.Mode() == crypto.CipherGCM {
			var buf [16]byte
			p.Header.Marshal(buf[:])
			header = buf[:]
		}
		result, err := c.cryptoCtx.EncryptPayload(p.Data, header, c.activeKey, seqNo.Value())
		if err != nil {
			p.Release()
			return fmt.Errorf("srt: encrypt: %w", err)
		}
		p.Data = result
	}

	// Send the packet
	if err := c.m.Send(p); err != nil {
		return fmt.Errorf("srt: send: %w", err)
	}
	c.updateLastSndTime()

	c.sendCC.OnPacketSent(seqNo.Value(), dataLen)
	c.sentPackets.Add(1)
	c.sentBytes.Add(uint64(dataLen))
	c.recordSendRate(1, dataLen)

	// Auto input rate sampling
	c.updateInputRate(c.clk.Now(), 1, dataLen)

	// FEC: feed source packet into FEC groups and emit control packets
	if c.fecSender != nil {
		c.fecSender.FeedSource(seqNo.Value(), p.Header.Timestamp, uint8(p.Header.Encryption), p.Data)
		c.sendFECPackets(p.Header.Timestamp)
	}

	// Key rotation check (only for encrypted connections)
	if c.cryptoCtx != nil && c.kmRefreshRate > 0 {
		c.checkKeyRotation()
	}

	// Token-bucket pacing with drift compensation.
	now := c.clk.Now()
	sendint := int64(c.sendCC.PacketInterval())
	if c.sendCC.IsProbePacket() {
		c.sendTimeDiff -= sendint
	} else if !c.nextSendTime.IsZero() {
		if now.After(c.nextSendTime) {
			c.sendTimeDiff += int64(now.Sub(c.nextSendTime))
		}
		if c.sendTimeDiff >= sendint {
			c.sendTimeDiff -= sendint
		} else {
			waitUS := sendint - c.sendTimeDiff
			time.Sleep(time.Duration(waitUS) * time.Microsecond)
			c.sendTimeDiff = 0
		}
	}
	c.nextSendTime = c.clk.Now()

	return nil
}

// sendFECPackets emits pending FEC control packets from the sender.
// FEC packets share the last data packet's seqno and have MessageNumber=0,
// PB_SOLO, and are NOT encrypted.
func (c *Conn) sendFECPackets(dataTimestamp uint32) {
	for {
		data, _, fecSeqNo, fecTS, ok := c.fecSender.PackControlPacket()
		if !ok {
			break
		}

		fecPkt := packet.New(c.remoteAddr)
		fecPkt.Header.IsControl = false
		fecPkt.Header.SequenceNumber = fecSeqNo
		fecPkt.Header.Timestamp = fecTS
		fecPkt.Header.DestinationSocketID = c.peerSocketID
		fecPkt.Header.MessageNumber = 0 // FEC marker
		fecPkt.Header.PacketPosition = packet.PositionSingle
		fecPkt.Header.Encryption = packet.EncryptionNone // FEC packets are NOT encrypted
		fecPkt.Data = data

		_ = c.m.Send(fecPkt)
		fecPkt.Release()
		c.sndFilterExtra.Add(1)
		_ = dataTimestamp // used for potential future timestamp alignment
	}
}

// updateInputRate samples bytes written to the send path and computes an input
// rate estimate. Called from sendPacket on the Write goroutine.
func (c *Conn) updateInputRate(now clock.Timestamp, pkts int, bytes int) {
	if !c.inputRateEnabled {
		return
	}

	if c.inputRateStart.IsZero() {
		c.inputRateStart = now
		return
	}

	c.inputRatePkts += int64(pkts)
	c.inputRateBytes += int64(bytes)

	// Max packets for early update in fast start
	const inputRateMaxPackets = 50
	const inputRateRunningUS = 1000000 // 1s

	earlyUpdate := c.inputRatePeriod < inputRateRunningUS && c.inputRatePkts > inputRateMaxPackets

	periodUS := int64(now.Sub(c.inputRateStart))
	if !earlyUpdate && periodUS <= c.inputRatePeriod {
		return
	}

	// Compute rate including wire headers (44 bytes per packet)
	totalBytes := c.inputRateBytes + c.inputRatePkts*44
	if periodUS > 0 {
		c.inputRateBps.Store(totalBytes * 1000000 / periodUS)
	}

	c.inputRatePkts = 0
	c.inputRateBytes = 0
	c.inputRateStart = now

	// Switch from fast start (500ms) to running (1s)
	c.inputRatePeriod = inputRateRunningUS
}

// updateAutoInputBW checks whether auto-input-rate sampling is active and
// updates the congestion controller with the sampled rate. Called from
// handleACK, handleNAK, and timerLoop.
func (c *Conn) updateAutoInputBW() {
	if !c.inputRateEnabled {
		return
	}

	inputBW := c.inputRateBps.Load()
	if inputBW <= 0 {
		return // keep previously set maximum when rate falls to 0
	}

	// Apply minimum bandwidth floor
	if c.inputRateMinBW > 0 && inputBW < c.inputRateMinBW {
		inputBW = c.inputRateMinBW
	}

	// Apply overhead percentage
	inputBW = inputBW * int64(100+c.inputRateOverhead) / 100

	c.sendCC.UpdateBandwidth(0, inputBW)
}

// WriteMessage sends a single message. In live mode (TSBPD), the message must
// fit in a single packet. In file/message mode, messages are auto-fragmented.
// Returns an error if the message exceeds the maximum allowed size.
func (c *Conn) WriteMessage(b []byte) (int, error) {
	if c.tsbpdEnabled && len(b) > c.payloadSize {
		return 0, fmt.Errorf("srt: message size %d exceeds maximum %d bytes", len(b), c.payloadSize)
	}
	return c.Write(b)
}

// ReadMessage reads a single complete message from the connection.
// In live mode, returns a single packet's data. In file/message mode,
// reassembles multi-packet messages from PP_FIRST through PP_LAST.
func (c *Conn) ReadMessage(b []byte) (int, error) {
	return c.Read(b)
}

// WriteMsgCtrl sends data with per-message control options.
// mc.SrcTime overrides the packet timestamp (custom source timestamp).
// mc.MsgTTL sets a per-message time-to-live for sender-side drop.
func (c *Conn) WriteMsgCtrl(b []byte, mc *MsgCtrl) (int, error) {
	if mc != nil && !mc.SrcTime.IsZero() {
		// Convert to SRT 32-bit timestamp (microseconds since connection start)
		ts := uint32(mc.SrcTime.UnixMicro() & 0xFFFFFFFF)
		c.groupSrcTime.Store(ts)
		defer c.groupSrcTime.Store(0)
	}
	// Per-message TTL: stored on send buffer entries via msgTTL field
	if mc != nil && mc.MsgTTL > 0 {
		c.msgTTL.Store(int64(mc.MsgTTL))
		defer c.msgTTL.Store(0)
	}
	// Per-message InOrder flag, encoded in the message number header field.
	if mc != nil && mc.InOrder {
		c.msgInOrder.Store(true)
		defer c.msgInOrder.Store(false)
	}
	return c.Write(b)
}

// ReadMsgCtrl reads data and populates the MsgCtrl with message metadata.
// mc.Boundary, mc.PktSeq, and mc.MsgNo are filled from the received packet.
func (c *Conn) ReadMsgCtrl(b []byte, mc *MsgCtrl) (int, error) {
	n, err := c.Read(b)
	// Note: in the current implementation, Read() doesn't expose per-packet
	// metadata. MsgCtrl fields are populated as zero values. Full metadata
	// requires plumbing packet headers through the read path, which is
	// deferred to avoid changing the hot path for this rarely-used API.
	return n, err
}

// nextMessageNumber returns the next 26-bit message number (1 to 0x03FFFFFF).
// Message number 0 is reserved (used by FEC). Only called from Write goroutine.
func (c *Conn) nextMessageNumber() uint32 {
	c.messageNumber++
	if c.messageNumber > 0x03FFFFFF {
		c.messageNumber = 1
	}
	return c.messageNumber
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.setShutdownErr(net.ErrClosed)

		// Linger: wait for send buffer to drain (ACKs from peer)
		if c.linger > 0 && c.sendBuf.Size() > 0 {
			deadline := time.NewTimer(c.linger)
			defer deadline.Stop()
			for c.sendBuf.Size() > 0 {
				select {
				case <-deadline.C:
					goto shutdown
				case <-c.writeReady:
					// ACK received — check again
				}
			}
		}

	shutdown:
		// Send shutdown control packet (skip if peer ID unknown)
		if c.peerSocketID != 0 {
			p := packet.NewControl(c.remoteAddr, packet.CtrlTypeShutdown, c.peerSocketID, c.clk.Now().SRTTimestamp())
			c.m.Send(p)
			p.Release()
		}

		// Unregister from mux
		c.m.Unregister(c.socketID)

		close(c.done)

		// If this connection owns the mux (client-side from Dial), close it.
		// Server-side connections share the listener's mux.
		if c.ownsMux {
			c.m.Close()
		}
	})
	return nil
}

func (c *Conn) LocalAddr() net.Addr  { return c.localAddr }
func (c *Conn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *Conn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	// Wake any blocked Read so it can check the new deadline
	c.signalReadReady()
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	// Wake any blocked Write so it can check the new deadline
	c.signalWriteReady()
	return nil
}

// ---- SRT-specific methods ----

// StreamID returns the stream ID from the handshake.
func (c *Conn) StreamID() string { return c.streamID }

// SocketID returns this connection's socket ID.
func (c *Conn) SocketID() uint32 { return c.socketID }

// GroupID returns the local group ID (0 if not part of a group).
func (c *Conn) GroupID() uint32 { return c.groupID }

// PeerGroupID returns the peer's group ID (0 if not part of a group).
func (c *Conn) PeerGroupID() uint32 { return c.peerGroupID }

// LastMsgNo returns the most recently assigned message number.
// Used by Group to record the message number for sender buffer entries.
func (c *Conn) LastMsgNo() uint32 { return c.messageNumber }

// RcvBufEmpty returns true if the receive buffer has no available packets.
// Used by Group to check if an idle link's recv buffer is empty before
// resetting its pointer.
func (c *Conn) RcvBufEmpty() bool {
	if c.recvBuf == nil {
		return true
	}
	return c.recvBuf.IsEmpty()
}

// RcvBufStartSeq returns the receive buffer's oldest unread sequence number.
// Used by Group for idle link synchronization.
func (c *Conn) RcvBufStartSeq() seq.Number {
	if c.recvBuf == nil {
		return 0
	}
	return c.recvBuf.StartSeq()
}

// ResetRecvState resets the receiver to a new initial sequence number,
// discarding all buffered data and resetting ACK state. Used by Group
// to synchronize idle link receiver pointers with the active link.
func (c *Conn) ResetRecvState(newSeq seq.Number) {
	if c.recvBuf == nil {
		return
	}
	decSeq := newSeq.Dec()
	c.recvBuf.SetInitialRcvSeq(newSeq)
	c.storeLastACKSeq(newSeq)
	c.rcvLastAckAck.Store(uint32(decSeq))
}

// SetMaxBW updates the maximum sending bandwidth in bytes/sec at runtime.
// SRTO_MAXBW is a POST option (can be changed after connection).
// When bw > 0, it is used directly. When bw == 0, the CC reverts to auto mode
// (InputBW + overhead, or sampling). When bw == -1, the max bandwidth is unlimited.
func (c *Conn) SetMaxBW(bw int64) {
	if bw < -1 {
		bw = -1
	}

	// Compute effective bandwidth and call updateBandwidth on the CC.
	var effectiveBW int64
	if bw > 0 {
		effectiveBW = bw
	} else if bw == 0 {
		// Auto mode: use InputBW + overhead or sampling
		if inputBW := c.inputRateBps.Load(); inputBW > 0 {
			effectiveBW = inputBW * int64(100+c.inputRateOverhead) / 100
		}
		// effectiveBW == 0 means use DefaultMaxBW in LiveCC
	}
	// bw == -1: effectiveBW stays 0 -> CC uses DefaultMaxBW

	c.sendCC.UpdateBandwidth(bw, effectiveBW)

	// If bw > 0, disable input rate sampling (bandwidth is explicit).
	// If bw == 0, re-enable sampling if InputBW is also 0.
	if bw > 0 {
		c.inputRateEnabled = false
	}
	// Note: re-enabling inputRateEnabled for bw==0 is handled by the existing
	// auto-rate logic in the timerLoop which checks inputRateEnabled.
}

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

// headerOverhead is the combined IP + UDP + SRT header size per packet.
const headerOverhead = 44

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
	MsSndTsbPdDelay time.Duration // peer's TSBPD delay (sender side,
	MsRcvTsbPdDelay time.Duration // local TSBPD delay (receiver side,
}

// ---- Internal goroutines ----

// recvLoop reads packets from the mux and processes them.
func (c *Conn) recvLoop() {
	for {
		select {
		case <-c.done:
			return
		case p, ok := <-c.recvC:
			if !ok {
				return
			}
			c.handlePacket(p)
		}
	}
}

// timerLoop drives periodic events at 10ms intervals.
func (c *Conn) timerLoop() {
	ticker := time.NewTicker(synInterval)
	defer ticker.Stop()

	lastKeepAlive := time.Now()
	lastNAKTime := time.Now()
	lastStatsTime := time.Now()
	c.lastACKRecv.Store(time.Now().UnixNano()) // initialize for RTO detection
	c.rexmitCount.Store(1)
	lastPktSnap := c.peerActivity.Load()
	lastRspTime := time.Now()
	expCount := 1

	for {
		select {
		case <-c.done:
			return
		case now := <-ticker.C:
			// Full ACK
			c.sendFullACK()

			// Periodic NAK: interval = (RTT + 4*RTTVar) / 2ref.
			// Disabled in file mode (: bRcvNakReport=false for SRTT_FILE).
			//: periodic NAK disabled when FEC ARQ != ARQAlways.
			if c.periodicNAK && now.Sub(lastNAKTime) >= c.nakInterval() {
				if c.fecReceiver == nil || c.fecARQLevel == filter.ARQAlways {
					c.sendPeriodicNAK()
					lastNAKTime = now
				}
			}

			// KeepAlive: only fire when no packet has been sent recently.
			//: keepalive only when idle (no sends in 1s).
			lastSndNano := c.lastSndTime.Load()
			if lastSndNano > 0 {
				if now.Sub(time.Unix(0, lastSndNano)) >= keepalivePeriod {
					c.sendKeepAlive()
				}
			} else if now.Sub(lastKeepAlive) >= keepalivePeriod {
				c.sendKeepAlive()
				lastKeepAlive = now
			}

			// Stats callback
			if cb := c.statsCallback.Load(); cb != nil {
				if now.Sub(lastStatsTime) >= cb.interval {
					cb.fn(c.Stats(true))
					lastStatsTime = now
				}
			}

			// Auto input rate: update CC with sampled rate
			c.updateAutoInputBW()

			// Buffer stats: update IIR averages and rotate send rate window
			c.updateBufferIIR()
			c.rotateSendRate()

			// Connection timeout: EXP timer.
			// Uses linear backoff: exp_timeout = expCount * max(SRTT + 4*RTTVar + SYN, 300ms).
			// Breaks only when BOTH: expCount > 16 AND wall-clock > peerIdleTimeout.
			currentPkts := c.peerActivity.Load()
			if currentPkts != lastPktSnap {
				// Heard from peer — reset EXP counter and response time
				lastRspTime = now
				expCount = 1
				lastPktSnap = currentPkts
			}
			if lastPktSnap > 0 {
				// SYN is added once (not per count), and minExpInterval is scaled by count.
				rttUS := c.rtt.Load()
				rttVarUS := c.rttVar.Load()
				expTimeout := time.Duration(expCount)*time.Duration(rttUS+4*rttVarUS)*time.Microsecond + synInterval
				if minExp := time.Duration(expCount) * minExpInterval; expTimeout < minExp {
					expTimeout = minExp
				}

				if now.Sub(lastRspTime) > expTimeout {
					// EXP fired: check if connection should break
					if expCount > maxExpCount && now.Sub(lastRspTime) > c.peerIdleTimeout {
						c.setShutdownErr(errors.New("srt: connection timeout"))
						c.Close()
						return
					}
					expCount++
				}
			}

			// Retransmission timeout: notify CC when no ACK received for
			// SRTT + 4*RTTVar + 2*SYN_INTERVAL (20ms).
			// FileCC exits slow start on RTO.
			rttSynUS := c.rtt.Load() + 4*c.rttVar.Load() + 2*10_000 // +2*synInterval (10ms each)
			rxCount := int64(c.rexmitCount.Load())
			if rxCount < 1 {
				rxCount = 1
			}
			rtoUS := rxCount*rttSynUS + 10_000
			rto := time.Duration(rtoUS) * time.Microsecond
			lastACKNano := c.lastACKRecv.Load()
			if lastACKNano > 0 && now.Sub(time.Unix(0, lastACKNano)) > rto {
				c.sendCC.OnTimeout()
				c.lastACKRecv.Store(now.UnixNano()) // reset to avoid repeated firing
				c.rexmitCount.Add(1)

				//: Two blind retransmit algorithms.
				// LATEREXMIT (file mode): retransmit when loss list empty (both data+NAK lost).
				// FASTREXMIT (live mode): retransmit ALL unacked when peer has no periodic NAK.
				if !c.tsbpdEnabled {
					// LATEREXMIT: only when loss list empty
					if c.flightSize() > 0 && c.sndLossCount.Load() <= 0 {
						c.retransmitAllInFlight()
					}
				} else if !c.peerNakReport {
					// FASTREXMIT: retransmit all unacked regardless of loss list
					if c.flightSize() > 0 {
						c.retransmitAllInFlight()
					}
				}
				// When peerNakReport=true in live mode: no blind retransmit (peer's NAKs handle it)
			}

			// Too-late packet drop (sender side) — only in live mode
			if c.tlpktdropEnabled {
				c.checkSendDrop()
			}

			// Too-late packet drop (receiver side) — only when TSBPD is active
			if c.tsbpdEnabled && c.tsbpdTimer != nil {
				if dropped := c.recvBuf.DropTooLate(c.clk.Now(), c.tsbpdTimer.DeliveryTime); dropped > 0 {
					c.recvDropped.Add(uint64(dropped))
					c.recvDroppedBytes.Add(uint64(dropped) * uint64(c.payloadSize))
				}
			}

			// Signal readReady for delivery check
			c.signalReadReady()
		}
	}
}

func (c *Conn) handlePacket(p packet.Packet) {
	if p.Header.IsControl {
		c.handleControlPacket(p)
	} else {
		c.handleDataPacket(p)
	}
}

func (c *Conn) handleControlPacket(p packet.Packet) {
	c.peerActivity.Add(1)

	switch p.Header.ControlType {
	case packet.CtrlTypeACK:
		c.handleACK(p)
	case packet.CtrlTypeNAK:
		c.handleNAK(p)
	case packet.CtrlTypeACKACK:
		c.handleACKACK(p)
	case packet.CtrlTypeKeepalive:
		// KeepAlive received — peerActivity already bumped above.
		//: update TSBPD drift + wrap from keepalive.
		if c.tsbpdEnabled && c.tsbpdTimer != nil {
			now := c.clk.Now()
			c.tsbpdTimer.UpdateWrap(p.Header.Timestamp)
			c.tsbpdTimer.OnACK(p.Header.Timestamp, now, -1) // -1 = no RTT sample
		}
		// Gap 2: Signal group idle state on keepalive reception.
		//processKeepalive() transitions sndstate/rcvstate
		// to IDLE when keepalive is received, preventing false stability timeout
		// during data pauses. We set an atomic flag that the group monitor reads.
		if c.groupID != 0 {
			c.groupIdle.Store(true)
		}
	case packet.CtrlTypeDropReq:
		c.handleDropReq(p)
	case packet.CtrlTypeUser:
		// Mid-stream extension messages (KMREQ/KMRSP for key rotation, HSREQ/HSRSP for HSv4)
		switch p.Header.SubType {
		case packet.ExtTypeHSReq:
			c.handleHSREQ(p)
		case packet.ExtTypeHSRsp:
			c.handleHSRSP(p)
		case packet.ExtTypeKMReq:
			c.handleKMRequest(p)
		case packet.ExtTypeKMRsp:
			c.handleKMResponse(p)
		}
	case packet.CtrlTypePeerError:
		//: UMSG_PEERERROR sets = false.
		// This indicates the peer has hit an unrecoverable error. We mark
		// peer health as false; send operations should check this flag.
		c.peerHealth.Store(false)
	case packet.CtrlTypeShutdown:
		c.setShutdownErr(errors.New("srt: peer shutdown"))
		c.Close()
	default:
		// Unknown control packet — ignore
	}
	p.Release()
}

func (c *Conn) handleDataPacket(p packet.Packet) {
	now := c.clk.Now()
	c.peerActivity.Add(1)

	// Data packet received — clear group idle flag since data is flowing.
	if c.groupID != 0 {
		c.groupIdle.Store(false)
	}

	// Decrypt if the packet is encrypted
	if p.Header.Encryption != packet.EncryptionNone && c.cryptoCtx != nil {
		var header []byte
		if c.cryptoCtx.Mode() == crypto.CipherGCM {
			// Zero the R-bit (Retransmitted flag) in AAD before decrypt.
			//: The sender encrypts with R=0 (original),
			// but retransmits set R=1. We must zero it so AAD matches.
			savedR := p.Header.Retransmitted
			p.Header.Retransmitted = false
			//: If TSBPD is disabled, timestamp also
			// has to be zeroed in the AAD so it matches the sender's AAD.
			savedTS := p.Header.Timestamp
			if !c.tsbpdEnabled {
				p.Header.Timestamp = 0
			}
			var buf [16]byte
			p.Header.Marshal(buf[:])
			header = buf[:]
			p.Header.Retransmitted = savedR
			p.Header.Timestamp = savedTS
		}
		result, err := c.cryptoCtx.DecryptPayload(p.Data, header, p.Header.Encryption, p.Header.SequenceNumber)
		if err != nil {
			c.recvUndecrypt.Add(1)
			c.recvUndecryptBytes.Add(uint64(len(p.Data)))
			p.Release()
			return
		}
		p.Data = result
	}

	//: Drop unencrypted packets on secured connections.
	// When KM state is SECURED (we have a crypto context and keys are confirmed),
	// unencrypted data packets must be dropped.
	if p.Header.Encryption == packet.EncryptionNone && c.cryptoCtx != nil && c.kmConfirmed.Load() {
		c.recvUndecrypt.Add(1)
		p.Release()
		return
	}

	// FEC control packet interception: MessageNumber==0 indicates an FEC packet.
	// Route to FECReceiver instead of the receive buffer.
	if c.fecReceiver != nil && p.Header.MessageNumber == 0 {
		c.handleFECPacket(p, now)
		return
	}

	// TSBPD timestamp wrap detection: SRT timestamps are 32-bit and wrap
	// every ~71.6 minutes. Update the wrap state machine for every packet.
	if c.tsbpdEnabled && c.tsbpdTimer != nil {
		c.tsbpdTimer.UpdateWrap(p.Header.Timestamp)
	}

	result := c.recvBuf.Insert(p, now)
	if result.Inserted {
		c.recvPackets.Add(1)
		c.recvBytes.Add(uint64(len(p.Data)))
		c.rcvPktCount.Add(1)

		// Feed data packet into FEC receiver for group accumulation
		if c.fecReceiver != nil {
			recovered, _, _ := c.fecReceiver.Receive(
				p.Header.SequenceNumber, p.Header.Timestamp,
				uint8(p.Header.Encryption), p.Header.MessageNumber, p.Data)
			for _, rp := range recovered {
				c.insertRecoveredPacket(rp, now)
				c.rcvFilterSupply.Add(1)
			}
		}

		if p.Header.Retransmitted {
			c.recvRetrans.Add(1)
			c.recvRetransBytes.Add(uint64(len(p.Data)))
		}

		// Reorder distance tracking: only for non-retransmitted packets,
		// since retransmits are expected to arrive out-of-order.
		seqVal := p.Header.SequenceNumber
		if !p.Header.Retransmitted && c.maxRecvSeqInit.Load() {
			maxSeq := c.maxRecvSeq.Load()
			dist := seq.Number(maxSeq).Distance(seq.Number(seqVal))
			if dist < 0 {
				// Packet arrived out-of-order (seqVal < maxSeq)
				reorderDist := -dist
				for {
					cur := c.reorderDistance.Load()
					if reorderDist <= cur {
						break
					}
					if c.reorderDistance.CompareAndSwap(cur, reorderDist) {
						break
					}
				}
			}
		}
		// Update max received sequence (CAS loop for thread safety)
		if !p.Header.Retransmitted {
			for {
				cur := c.maxRecvSeq.Load()
				if c.maxRecvSeqInit.Load() && seq.Number(seqVal).LessThanOrEqual(seq.Number(cur)) {
					break
				}
				if c.maxRecvSeq.CompareAndSwap(cur, seqVal) {
					c.maxRecvSeqInit.Store(true)
					break
				}
			}
		}

		// TSBPD drift compensation: sender timestamp vs local arrival.
		// NOTE: Drift samples are NOT taken from data packets. takes drift
		// samples from ACKACK/Keepalive timestamps. Data packet timestamps
		// represent source time (for TSBPD scheduling), not sender clock time.
		// See handleACKACK and keepalive handler for drift sampling.

		// Delivery rate estimation — ALL packets including retransmitted.
		//: onPktArrival is called unconditionally.
		c.sendCC.OnPktArrival(len(p.Data), now)

		// Probe-pair link capacity estimation — skip retransmitted to avoid
		// corrupting probe pair timing. probeArrival checks ordering.
		if !p.Header.Retransmitted {
			c.sendCC.OnPacketReceived(p.Header.SequenceNumber, len(p.Data), now)
		}

		// Gap handling: immediate NAK or deferred via FreshLoss
		wasSentInOrder := true
		if result.HasGap() {
			// Count missing packets in the gap [GapStart, GapEnd]
			gapSize := seq.Number(result.GapStart).Distance(seq.Number(result.GapEnd))
			if gapSize > 0 {
				c.recvLoss.Add(uint64(gapSize) + 1)
			}

			initialTTL := c.reorderTolerance
			if initialTTL > 0 {
				// Defer NAK: add to FreshLoss with TTL
				c.freshLoss = append(c.freshLoss, freshLossEntry{
					seqLo: result.GapStart,
					seqHi: result.GapEnd,
					ttl:   initialTTL,
				})
			} else {
				// No reorder tolerance: send NAK immediately.
				//: suppress SRT's own NAK when FEC
				// ARQ level is not ARQAlways (FEC handles loss recovery).
				if c.fecReceiver == nil || c.fecARQLevel == filter.ARQAlways {
					c.sendImmediateNAK(result.GapStart, result.GapEnd)
				}
			}
		}

		// Process FreshLoss: expire entries with TTL <= 0, decrement rest.
		if c.reorderTolerance > 0 && len(c.freshLoss) > 0 {
			c.processFreshLoss()
		}

		// Track consecutive ordered delivery for dynamic tolerance adjustment.
		//: increment on in-order or retransmitted packets.
		if c.maxReorderTolerance > 0 && wasSentInOrder {
			c.consecOrderedDelivery++
			if c.consecOrderedDelivery >= 50 {
				c.consecOrderedDelivery = 0
				if c.reorderTolerance > 0 {
					c.reorderTolerance--
				}
			}
		}

		// Lite ACK with escalating interval:
		// Send when pktCount >= SELF_CLOCK_INTERVAL * lightACKCount.
		// lightACKCount increments after each lite ACK, resets on Full ACK.
		lc := int64(c.lightACKCount.Load())
		if lc > 0 && c.rcvPktCount.Load() >= int64(liteACKPeriod)*lc {
			c.sendLiteACK()
			c.lightACKCount.Add(1)
		}

		// Quick ACK for file mode: non-full-payload packets trigger immediate
		// Full ACK to speed up CC feedback.needsQuickACK.
		// Only for non-belated, non-retransmitted (in-order) packets.
		if !c.tsbpdEnabled && !p.Header.Retransmitted && len(p.Data) < c.payloadSize {
			c.sendFullACK()
		}

		c.signalReadReady()
	} else {
		// Belated/duplicate packet: was already ACK'd or out of buffer range.
		c.recvBelated.Add(1)
		c.recvBelatedBytes.Add(uint64(len(p.Data)))

		// FreshLoss: handle belated arrival with dynamic tolerance.
		if c.maxReorderTolerance > 0 {
			c.unlose(p)
		}

		// Track how late belated packets arrive: EWMA with factor 0.2
		//CountIIR: new_avg = old + (sample - old) * 0.2
		var deliveryTime clock.Timestamp
		if c.tsbpdTimer != nil {
			deliveryTime = c.tsbpdTimer.DeliveryTime(p.Header.Timestamp)
		}
		if !deliveryTime.IsZero() && now.After(deliveryTime) {
			lateness := int64(now.Sub(deliveryTime))
			for {
				old := c.recvBelatedTimeAvg.Load()
				var newAvg int64
				if old == 0 {
					newAvg = lateness
				} else {
					newAvg = old + (lateness-old)/5 // factor 0.2 = 1/5
				}
				if c.recvBelatedTimeAvg.CompareAndSwap(old, newAvg) {
					break
				}
			}
		}
		p.Release() // duplicate or out-of-range
	}
}

// handleFECPacket processes an incoming FEC control packet (MessageNumber==0).
// The packet is not inserted into the receive buffer. Recovered packets are
// inserted as if they arrived normally.
func (c *Conn) handleFECPacket(p packet.Packet, now clock.Timestamp) {
	c.peerActivity.Add(1)
	c.rcvFilterExtra.Add(1)

	recovered, lossReport, _ := c.fecReceiver.Receive(
		p.Header.SequenceNumber, p.Header.Timestamp,
		uint8(p.Header.Encryption), p.Header.MessageNumber, p.Data)

	p.Release()

	// Insert any recovered packets into the receive buffer
	for _, rp := range recovered {
		c.insertRecoveredPacket(rp, now)
		c.rcvFilterSupply.Add(1)
	}

	// Report irrecoverable losses via NAK (ARQ cooperation)
	if len(lossReport) > 0 {
		c.rcvFilterLoss.Add(uint64(len(lossReport)))
		c.sendNAKForSeqs(lossReport)
	}
}

// insertRecoveredPacket creates a packet from FEC-recovered data and inserts it
// into the receive buffer.
func (c *Conn) insertRecoveredPacket(rp filter.RecoveredPacket, now clock.Timestamp) {
	recovered := packet.New(c.remoteAddr)
	recovered.Header.IsControl = false
	recovered.Header.SequenceNumber = rp.SeqNo
	recovered.Header.Timestamp = rp.Timestamp
	recovered.Header.DestinationSocketID = c.socketID
	recovered.Header.Encryption = packet.PacketEncryption(rp.EncFlag)
	recovered.Header.MessageNumber = 1 // valid non-zero message number
	recovered.Header.PacketPosition = packet.PositionSingle
	recovered.Header.Retransmitted = true
	recovered.Data = make([]byte, len(rp.Payload))
	copy(recovered.Data, rp.Payload)

	// Decrypt if the recovered packet was encrypted.
	// Note: For GCM mode, FEC-recovered packets have XOR'd auth tags which won't
	// verify. CTR-mode decryption works because the ciphertext XOR property holds.
	if recovered.Header.Encryption != packet.EncryptionNone && c.cryptoCtx != nil {
		var header []byte
		if c.cryptoCtx.Mode() == crypto.CipherGCM {
			var buf [16]byte
			recovered.Header.Marshal(buf[:])
			header = buf[:]
		}
		result, err := c.cryptoCtx.DecryptPayload(recovered.Data, header, recovered.Header.Encryption, recovered.Header.SequenceNumber)
		if err != nil {
			recovered.Release()
			return
		}
		recovered.Data = result
	}

	result := c.recvBuf.Insert(recovered, now)
	if result.Inserted {
		c.recvPackets.Add(1)
		c.recvBytes.Add(uint64(len(recovered.Data)))
		c.signalReadReady()
	} else {
		recovered.Release()
	}
}

// sendNAKForSeqs sends a NAK for specific sequence numbers (used by FEC ARQ cooperation).
// Uses CIFNAK.MarshalCIF() for proper range encodingformat.
func (c *Conn) sendNAKForSeqs(seqs []uint32) {
	if len(seqs) == 0 {
		return
	}

	// Use CIFNAK for proper range encoding (contiguous seqs -> range pairs)
	cifNAK := packet.CIFNAK{LossList: seqs}
	nakData, err := cifNAK.MarshalCIF()
	if err != nil || len(nakData) == 0 {
		return
	}

	nak := packet.NewControl(c.remoteAddr, packet.CtrlTypeNAK, c.peerSocketID, 0)
	nak.Data = nakData
	c.m.Send(nak)
	nak.Release()
	c.sentNAKs.Add(1)
	c.recvLoss.Add(uint64(len(seqs)))
}

func (c *Conn) handleACK(p packet.Packet) {
	c.recvACKs.Add(1)
	c.lastACKRecv.Store(time.Now().UnixNano())
	c.rexmitCount.Store(1)
	var ack packet.CIFACK
	if err := p.UnmarshalCIF(&ack); err != nil {
		return
	}

	// Lite ACK: only 4 bytes (sequence number only).
	//: early return — advance ACK, adjust flow window,
	// skip ACKACK/RTT update/CC callback.
	isLiteACK := len(p.Data) == 4

	//: Validate ACK sequence.
	// Break connection if ACK'd sequence is beyond what we've sent.
	ackSeq := seq.Number(ack.LastACKPacketSequenceNumber)
	nextSend := c.sendBuf.NextSeq()
	if ackSeq.GreaterThan(nextSend) {
		c.setShutdownErr(errors.New("srt: ACK sequence beyond send range"))
		c.Close()
		return
	}

	// ACK up to the acknowledged sequence number
	ackd := c.sendBuf.ACK(ackSeq)
	if ackd > 0 {
		// ACK'd packets clear any outstanding losses in that range.
		// Subtract from sndLossCount (floor at 0).
		newLoss := c.sndLossCount.Add(-int64(ackd))
		if newLoss < 0 {
			c.sndLossCount.Store(0)
		}
		c.signalWriteReady()
	}

	if isLiteACK {
		//: Lite ACK adjusts flow window by subtracting
		// the number of newly ACK'd packets, resets response timer, and returns.
		// No ACKACK, no RTT update, no CC callback.
		if ackd > 0 {
			c.flowWindowSize.Add(-int32(ackd))
		}
		return
	}

	// --- Full ACK path below ---

	// Accumulate sender-busy duration on every ACK (behavior:
	// duration += now - counter; counter = now). When the buffer empties,
	// reset sndBusySince to 0 so idle time is excluded.
	now := c.clk.Now()
	if busySince := c.sndBusySince.Load(); busySince != 0 {
		elapsed := now.Sub(clock.Timestamp(busySince))
		c.sndDurationUs.Add(int64(elapsed))
		if c.sendBuf.Size() == 0 {
			c.sndBusySince.Store(0) // buffer drained — idle
		} else {
			c.sndBusySince.Store(int64(now)) // restart counter
		}
	}

	// Send ACKACK — throttled to one per SYN interval (10ms),
	// Also retransmit if the same ACK seqno arrives again (meaning our ACKACK was lost).
	ackSeqNoFromACK := p.Header.TypeSpecific
	nowNano := time.Now().UnixNano()
	lastAA := c.lastACKACKTime.Load()
	sinceLastAA := time.Duration(nowNano - lastAA)
	if sinceLastAA >= synInterval || ackSeqNoFromACK == c.lastACKACKSeq.Load() {
		ackack := packet.NewControl(c.remoteAddr, packet.CtrlTypeACKACK, c.peerSocketID, c.clk.Now().SRTTimestamp())
		ackack.Header.TypeSpecific = ackSeqNoFromACK
		c.m.Send(ackack)
		ackack.Release()
		c.sentACKACKs.Add(1)
		c.lastACKACKTime.Store(nowNano)
		c.lastACKACKSeq.Store(ackSeqNoFromACK)
	}

	// Update dynamic flow window from receiver's available buffer size.
	// Updated unconditionally — even 0 is valid (receiver buffer full).
	c.flowWindowSize.Store(int32(ack.AvailableBufferSize))

	//: IIR-8 smoothing of bandwidth and delivery rate.
	// smoothedVal = (old * 7 + new) / 8 — only update when peer reports non-zero.
	bw := ack.EstimatedLinkCapacity
	if bw > 0 {
		if old := c.smoothBW.Load(); old > 0 {
			bw = (old*7 + bw) / 8
		}
		c.smoothBW.Store(bw)
	} else {
		bw = c.smoothBW.Load()
	}

	dr := ack.PacketsReceivingRate
	if dr > 0 {
		if old := c.smoothDelivery.Load(); old > 0 {
			dr = (old*7 + dr) / 8
		}
		c.smoothDelivery.Store(dr)
	} else {
		dr = c.smoothDelivery.Load()
	}

	// Update congestion controller.
	// FileCC reads m_parent->SRTT() (sender-side EWMA RTT from ACKACK),
	// not the raw RTT from the ACK packet. Use our sender-side smoothed RTT.
	senderRTT := clock.Microseconds(c.rtt.Load())
	c.sendCC.OnACK(ack.LastACKPacketSequenceNumber, senderRTT, bw, dr)

	// Auto input rate: update CC with sampled rate
	c.updateAutoInputBW()
}

func (c *Conn) handleNAK(p packet.Packet) {
	c.recvNAKs.Add(1)
	var nak packet.CIFNAK
	if err := p.UnmarshalCIF(&nak); err != nil {
		return
	}

	c.lostPackets.Add(uint64(len(nak.LossList)))

	//: Validate NAK sequences.
	// Break connection if any NAK'd sequence is beyond what we've sent.
	nextSend := c.sendBuf.NextSeq()
	for _, lossSeq := range nak.LossList {
		if seq.Number(lossSeq).GreaterThan(nextSend) {
			c.setShutdownErr(errors.New("srt: NAK sequence beyond send range"))
			c.Close()
			return
		}
	}

	//: Check for NAK'd seqnos below the last ACK.
	// These packets are already ACK'd/dropped by the sender and can't be
	// retransmitted. Send DROPREQ so the receiver skips them.
	sndLastACK := c.sendBuf.StartSeq()
	var belowACKLo, belowACKHi int32 = -1, -1
	var validLosses []uint32
	for _, lossSeq := range nak.LossList {
		if seq.Number(lossSeq).LessThan(sndLastACK) {
			// Below ACK — track for DROPREQ
			if belowACKLo < 0 {
				belowACKLo = int32(lossSeq)
				belowACKHi = int32(lossSeq)
			} else {
				belowACKHi = int32(lossSeq)
			}
		} else {
			validLosses = append(validLosses, lossSeq)
		}
	}

	// Send DROPREQ for below-ACK losses
	if belowACKLo >= 0 {
		c.sendDropReq(uint32(belowACKLo), uint32(belowACKHi))
	}

	// Track outstanding loss count for FileCC's 2% threshold check.
	// uses m_parent->sndLossLength() which returns the total individual
	// packets in the persistent sender loss list. We approximate with an
	// atomic counter: add losses here, subtract on ACK/retransmit.
	if len(validLosses) > 0 {
		c.sndLossCount.Add(int64(len(validLosses)))
		if fcc, ok := c.sendCC.(interface{ SetSndLossLength(int) }); ok {
			cnt := int(c.sndLossCount.Load())
			if cnt < 0 {
				cnt = 0
			}
			fcc.SetSndLossLength(cnt)
		}
	}
	c.sendCC.OnNAK(nak.LossList)

	// Retransmit lost packets with timing gate to prevent re-retransmission
	// within one RTT.checkRexmitRightTime: only applies when
	// peer sends periodic NAK reports () and retransmitAlgo != 0.
	now := c.clk.Now()
	rtt := clock.Microseconds(c.rtt.Load())
	rttVar := clock.Microseconds(c.rttVar.Load())
	var retransmit []packet.Packet
	if c.peerNakReport && c.retransmitAlgo != 0 && rtt > 0 {
		retransmit = c.sendBuf.NAKTimed(validLosses, now, rtt, rttVar)
	} else {
		retransmit = c.sendBuf.NAK(validLosses)
	}
	for _, rp := range retransmit {
		// Rate-limit retransmissions if MaxRexmitBW is configured
		if c.rexmitShaper != nil && !c.rexmitShaper.allow(len(rp.Data)) {
			rp.Release()
			continue // skipped; peer will re-NAK
		}
		rp.Header.Addr = c.remoteAddr
		rp.Header.DestinationSocketID = c.peerSocketID
		// Preserve the original SRT timestamp from the send buffer clone.
		//packLostData → setDataPacketTS(tsOrigin): retransmitted
		// packets keep their original timestamp for correct TSBPD delivery timing.
		if err := c.encryptRetransmit(&rp); err != nil {
			rp.Release()
			continue
		}
		c.m.Send(rp)
		c.retransCount.Add(1)
		c.retransBytes.Add(uint64(len(rp.Data)))
		rp.Release()
	}
	// Retransmitted packets leave the loss list in
	if len(retransmit) > 0 {
		newLoss := c.sndLossCount.Add(-int64(len(retransmit)))
		if newLoss < 0 {
			c.sndLossCount.Store(0)
		}
	}

	// Auto input rate: update CC with sampled rate
	c.updateAutoInputBW()
}

// sendDropReq sends a DROPREQ control packet telling the receiver to skip the given range.
func (c *Conn) sendDropReq(firstSeq, lastSeq uint32) {
	dr := &packet.CIFDropReq{
		MsgID:      0,
		FirstSeqNo: firstSeq,
		LastSeqNo:  lastSeq,
	}
	data, err := dr.MarshalCIF()
	if err != nil {
		return
	}
	dp := packet.NewControl(c.remoteAddr, packet.CtrlTypeDropReq, c.peerSocketID, c.clk.Now().SRTTimestamp())
	dp.SetData(data)
	c.m.Send(dp)
	dp.Release()
}

func (c *Conn) handleACKACK(p packet.Packet) {
	c.recvACKACKs.Add(1)
	// ACKACK echoes the ACK sequence number in TypeSpecific.
	// RTT = now - time_when_ACK_was_sent
	ackSeqNo := p.Header.TypeSpecific
	v, ok := c.ackSendTime.LoadAndDelete(ackSeqNo)
	if !ok {
		return // unknown ACK sequence — stale or duplicate
	}

	info := v.(ackSendInfo)

	//: update (highest confirmed data seqno)
	// Used by sendFullACK to suppress redundant ACKs when no new data.
	if seq.Number(info.dataSeq).GreaterThan(seq.Number(c.rcvLastAckAck.Load())) {
		c.rcvLastAckAck.Store(info.dataSeq)
	}

	now := c.clk.Now()
	rtt := now.Sub(info.sendTime)
	if rtt > 0 && rtt < 10*clock.Second {
		oldRTT := clock.Microseconds(c.rtt.Load())
		if oldRTT == 0 {
			//: First RTT measurement — set directly
			// instead of EWMA from zero to avoid severe underestimation.
			c.rtt.Store(int64(rtt))
			c.rttVar.Store(int64(rtt / 2))
		} else {
			// EWMA: rtt = 7/8 * oldRTT + 1/8 * newRTT
			newRTT := (oldRTT*7 + rtt) / 8
			c.rtt.Store(int64(newRTT))

			// RTT variance: var = 3/4 * oldVar + 1/4 * |rtt - avgRTT|
			oldVar := clock.Microseconds(c.rttVar.Load())
			diff := rtt - oldRTT
			if diff < 0 {
				diff = -diff
			}
			newVar := (oldVar*3 + diff) / 4
			c.rttVar.Store(int64(newVar))
		}
	}

	//: TSBPD drift samples come from ACKACK timestamps,
	// not data packets. The ACKACK's timestamp reflects the sender's current
	// clock, making it ideal for drift estimation.
	if c.tsbpdEnabled && c.tsbpdTimer != nil {
		//: pass raw RTT from this ACKACK pair, not the
		// smoothed EWMA. The drift tracer needs instantaneous measurements
		// for responsive path-delay compensation.
		c.tsbpdTimer.OnACK(p.Header.Timestamp, now, int64(rtt))
	}
}

// checkSendDrop checks if the oldest unacked packet has been waiting
// too long (past TSBPD delay) and sends a DROPREQ to the receiver.
func (c *Conn) checkSendDrop() {
	if c.sendDropThresh <= 0 {
		return // sender-side drop disabled (SndDropDelay=-1)
	}
	now := c.clk.Now()
	oldest := c.sendBuf.OldestSendTime()
	if oldest.IsZero() || now.Sub(oldest) <= c.sendDropThresh {
		return
	}

	firstSeq := c.sendBuf.StartSeq()

	// Drop all packets from the head that exceed the threshold
	dropped := 0
	for {
		t := c.sendBuf.OldestSendTime()
		if t.IsZero() || now.Sub(t) <= c.sendDropThresh {
			break
		}
		c.sendBuf.DropUntil(c.sendBuf.StartSeq().Inc())
		dropped++
	}

	if dropped == 0 {
		return
	}

	// lastSeq is inclusive: firstSeq + dropped - 1
	lastSeq := firstSeq
	for i := 1; i < dropped; i++ {
		lastSeq = lastSeq.Inc()
	}

	c.sentDropped.Add(uint64(dropped))
	c.sentDroppedBytes.Add(uint64(dropped) * uint64(c.payloadSize))

	//: m_pSndLossList->removeUpTo(minlastack)
	// Clear outstanding loss count for dropped packets — they are no longer
	// candidates for retransmission. This keeps sndLossCount consistent
	// with the actual send buffer state.
	newLoss := c.sndLossCount.Add(-int64(dropped))
	if newLoss < 0 {
		c.sndLossCount.Store(0)
	}

	c.signalWriteReady()

	// Send DROPREQ to the receiver
	dr := &packet.CIFDropReq{
		MsgID:      0,
		FirstSeqNo: firstSeq.Value(),
		LastSeqNo:  lastSeq.Value(),
	}
	data, err := dr.MarshalCIF()
	if err != nil {
		return
	}
	p := packet.NewControl(c.remoteAddr, packet.CtrlTypeDropReq, c.peerSocketID, c.clk.Now().SRTTimestamp())
	p.SetData(data)
	c.m.Send(p)
	p.Release()
}

// encryptRetransmit re-encrypts a retransmit clone for GCM mode.
// For CTR mode the send buffer already stores encrypted data (in-place XOR
// modifies the shared buffer), so clones are already encrypted — this is a no-op.
// For GCM mode the send buffer stores plaintext (encryptGCM returns a new
// buffer), so retransmit clones must be freshly encrypted before sending.
// always re-encrypts retransmits because it stores plaintext in the send buffer.
func (c *Conn) encryptRetransmit(rp *packet.Packet) error {
	if c.cryptoCtx == nil || rp.Header.Encryption == packet.EncryptionNone {
		return nil
	}
	if c.cryptoCtx.Mode() != crypto.CipherGCM {
		return nil // CTR: already encrypted in the buffer
	}
	// GCM: re-encrypt plaintext clone. Zero the R-bit in the AAD header
	// so it matches what the receiver expects (receiver zeros R before verify).
	savedR := rp.Header.Retransmitted
	rp.Header.Retransmitted = false
	var buf [16]byte
	rp.Header.Marshal(buf[:])
	rp.Header.Retransmitted = savedR

	result, err := c.cryptoCtx.EncryptPayload(rp.Data, buf[:], rp.Header.Encryption, rp.Header.SequenceNumber)
	if err != nil {
		return err
	}
	rp.Data = result
	return nil
}

// retransmitAllInFlight retransmits all unacknowledged packets.
// Used for LATEREXMIT (file mode, loss list empty) and FASTREXMIT (live mode,
// peer has no periodic NAK) when RTO fires.
func (c *Conn) retransmitAllInFlight() {
	pkts := c.sendBuf.GetAllUnacked()
	for _, rp := range pkts {
		if c.rexmitShaper != nil && !c.rexmitShaper.allow(len(rp.Data)) {
			rp.Release()
			continue
		}
		rp.Header.Addr = c.remoteAddr
		rp.Header.DestinationSocketID = c.peerSocketID
		// Preserve original SRT timestamp (already in clone header).
		//: retransmits use setDataPacketTS(tsOrigin).
		if err := c.encryptRetransmit(&rp); err != nil {
			rp.Release()
			continue
		}
		c.m.Send(rp)
		c.retransCount.Add(1)
		c.retransBytes.Add(uint64(len(rp.Data)))
		rp.Release()
	}
}

func (c *Conn) handleDropReq(p packet.Packet) {
	//: skip DROPREQ if TLPKTDROP is not enabled.
	if !c.tlpktdropEnabled {
		return
	}

	if len(p.Data) < 12 {
		return
	}
	var dr packet.CIFDropReq
	if err := dr.UnmarshalCIF(p.Data); err != nil {
		return
	}

	//: When both TLPktDrop AND TsbPd are enabled, don't
	// drop from the recv buffer — TSBPD will handle it naturally as too-late.
	// Only drop from the buffer when either is disabled (file mode, etc.).
	if !c.tlpktdropEnabled || !c.tsbpdEnabled {
		lastPlusOne := seq.Number(dr.LastSeqNo).Inc()
		dropped := c.recvBuf.Drop(lastPlusOne)
		if dropped > 0 {
			c.recvDropped.Add(uint64(dropped))
			c.recvDroppedBytes.Add(uint64(dropped) * uint64(c.payloadSize))
		}
	}

	//: Signal read ready so TSBPD-waiting readers
	// can re-evaluate. When packets are dropped there will never be an ACK
	// for them, so any read blocked on TSBPD must be woken.
	c.signalReadReady()
}

// sendFullACK sends an ACK with RTT and optionally extended bandwidth fields.
// : Full ACK (28 bytes, with bandwidth/delivery rate) is sent
// when >= 10ms since last Full ACK. Otherwise a Small ACK (16 bytes, seq+RTT+RTTVar+Buffer)
// is sent. Both include the ACK sequence number for ACKACK-based RTT measurement.
func (c *Conn) sendFullACK() {
	ackSeq := c.recvBuf.ACKSequence()

	//: validate ACK doesn't exceed incseq().
	// MaxSeq is already highestReceived+1, so it equals incseq().
	maxSeq := c.recvBuf.MaxSeq()
	if maxSeq.LessThan(ackSeq) {
		ackSeq = maxSeq
	}

	//: check if periodic Full ACK is needed (10ms SYN interval).
	nowNano := time.Now().UnixNano()
	lastFull := c.lastFullACKTime.Load()
	needFullACK := time.Duration(nowNano-lastFull) >= synInterval

	//: force Full ACK when receiver buffer transitions from full to available.
	// This ensures the sender can resume sending after flow control blocked it.
	//,7215-7218: available = capacity - seqlen(startSeq, lastAck) + 1
	availSpace := c.recvBuf.AvailableSize(ackSeq)
	if c.bufferWasFull.Load() && availSpace > 0 {
		needFullACK = true
	}

	//: suppress ACK when peer has already confirmed this seqno
	// via ACKACK (no new data since confirmation), unless periodic Full ACK is due.
	// Using rcvLastAckAck (peer-confirmed) rather than lastACKSeq (last-sent) allows
	// retransmission of ACKs the peer hasn't confirmed yet.
	if ackSeq.Value() == c.rcvLastAckAck.Load() && !needFullACK {
		return
	}
	c.storeLastACKSeq(ackSeq)

	ackNo := c.ackSeqNo.Add(1)
	if ackNo == 0 {
		ackNo = c.ackSeqNo.Add(1) // skip 0 — reserved per SRT spec
	}

	ack := &packet.CIFACK{
		LastACKPacketSequenceNumber: ackSeq.Value(),
		RTT:                         uint32(c.rtt.Load()),
		RTTVariance:                 uint32(c.rttVar.Load()),
		AvailableBufferSize:         uint32(availSpace),
	}

	now := c.clk.Now()
	p := packet.NewControl(c.remoteAddr, packet.CtrlTypeACK, c.peerSocketID, now.SRTTimestamp())
	p.Header.TypeSpecific = ackNo

	// sends Full ACK (with extended fields) every 10ms; Small ACK otherwise.
	if needFullACK {
		// Full ACK: include bandwidth/delivery rate fields.
		//   ACKD_RCVSPEED  = getPktRcvSpeed(bytesps)  // delivery pkts/sec
		//   ACKD_BANDWIDTH = getBandwidth()            // probe link capacity pkts/sec
		//   ACKD_RCVRATE   = bytesps                   // delivery bytes/sec
		deliveryPktRate, deliveryBytesRate := c.sendCC.DeliveryRate()
		probePktRate := c.sendCC.EstimatedBandwidth()
		ack.PacketsReceivingRate = deliveryPktRate // ACKD_RCVSPEED
		ack.EstimatedLinkCapacity = probePktRate   // ACKD_BANDWIDTH
		ack.ReceivingRate = deliveryBytesRate      // ACKD_RCVRATE

		//: ACK size depends on peer SRT version.
		var ackData []byte
		switch {
		case c.peerSRTVersion == 0x010002:
			// v1.0.2: 32 bytes (ACKD_TOTAL_SIZE_VER102_ONLY) with extra XMRATE field
			xmRate := probePktRate * uint32(c.payloadSize)
			ackData, _ = ack.MarshalV102CIF(xmRate)
		case c.peerSRTVersion == 0 || c.peerSRTVersion < 0x010003:
			// Pre-v1.0.3 or unknown: 24 bytes (ACKD_TOTAL_SIZE_UDTBASE)
			ackData, _ = ack.MarshalUDTBaseCIF()
		default:
			// v1.0.3+ (normal case): 28 bytes (ACKD_TOTAL_SIZE_VER101)
			ackData, _ = ack.MarshalCIF()
		}
		p.SetData(ackData)

		c.lastFullACKTime.Store(nowNano)
		//: reset pkt count and lite ACK counter on Full ACK
		c.rcvPktCount.Store(0)
		c.lightACKCount.Store(1)
	} else {
		// Small ACK: only first 4 fields (16 bytes)
		data, _ := ack.MarshalSmallCIF()
		p.SetData(data)
	}

	c.m.Send(p)
	c.updateLastSndTime()
	p.Release()

	c.sentACKs.Add(1)

	// Record send time + data seqno for RTT measurement and ACKACK tracking
	c.ackSendTime.Store(ackNo, ackSendInfo{sendTime: now, dataSeq: ackSeq.Value()})

	//: track whether buffer is full for next ACK decision.
	c.bufferWasFull.Store(availSpace == 0)
}

// sendLiteACK sends a lightweight ACK with only the sequence number (4 bytes).
func (c *Conn) sendLiteACK() {
	ackSeq := c.recvBuf.ACKSequence()

	var data [4]byte
	binary.BigEndian.PutUint32(data[:], ackSeq.Value())

	p := packet.NewControl(c.remoteAddr, packet.CtrlTypeACK, c.peerSocketID, c.clk.Now().SRTTimestamp())
	p.SetData(data[:])
	c.m.Send(p)
	p.Release()
	c.sentACKs.Add(1)
}

// sendImmediateNAK sends a NAK for a newly detected gap [gapStart, gapEnd].
func (c *Conn) sendImmediateNAK(gapStart, gapEnd uint32) {
	s := seq.Number(gapStart)
	end := seq.Number(gapEnd)
	gapSize := int(s.Distance(end)) + 1
	if gapSize <= 0 {
		gapSize = 1
	}
	if gapSize > 10000 {
		gapSize = 10000
	}
	losses := make([]uint32, 0, gapSize)
	for {
		losses = append(losses, s.Value())
		if s == end {
			break
		}
		s = s.Inc()
		if len(losses) > 10000 {
			break // safety limit
		}
	}

	nak := &packet.CIFNAK{LossList: losses}
	p := packet.NewControl(c.remoteAddr, packet.CtrlTypeNAK, c.peerSocketID, c.clk.Now().SRTTimestamp())
	p.MarshalCIF(nak)
	c.m.Send(p)
	p.Release()
	c.sentNAKs.Add(1)
}

// sendPeriodicNAK sends a NAK for any gaps in the receive buffer.
func (c *Conn) sendPeriodicNAK() {
	losses := c.recvBuf.GenerateLossList()
	if len(losses) == 0 {
		return
	}

	nak := &packet.CIFNAK{LossList: losses}
	p := packet.NewControl(c.remoteAddr, packet.CtrlTypeNAK, c.peerSocketID, c.clk.Now().SRTTimestamp())
	p.MarshalCIF(nak)
	c.m.Send(p)
	p.Release()
	c.sentNAKs.Add(1)
}

// processFreshLoss scans the FreshLoss deque, collects entries with TTL <= 0
// into a NAK report, erases them, and decrements TTL on remaining entries.
// . Called only from recvLoop.
func (c *Conn) processFreshLoss() {
	// Phase 1: collect expired entries (TTL <= 0) from the front
	expiredEnd := 0
	for expiredEnd < len(c.freshLoss) && c.freshLoss[expiredEnd].ttl <= 0 {
		expiredEnd++
	}

	// Build NAK for expired entries
	if expiredEnd > 0 {
		var losses []uint32
		for i := 0; i < expiredEnd; i++ {
			e := c.freshLoss[i]
			s := seq.Number(e.seqLo)
			end := seq.Number(e.seqHi)
			for {
				losses = append(losses, s.Value())
				if s == end {
					break
				}
				s = s.Inc()
				if len(losses) > 10000 {
					break
				}
			}
		}
		// Remove expired entries
		c.freshLoss = append(c.freshLoss[:0], c.freshLoss[expiredEnd:]...)

		// Send NAK
		if len(losses) > 0 {
			nak := &packet.CIFNAK{LossList: losses}
			p := packet.NewControl(c.remoteAddr, packet.CtrlTypeNAK, c.peerSocketID, c.clk.Now().SRTTimestamp())
			p.MarshalCIF(nak)
			c.m.Send(p)
			p.Release()
			c.sentNAKs.Add(1)
		}
	}

	// Phase 2: decrement TTL on remaining entries
	for i := range c.freshLoss {
		c.freshLoss[i].ttl--
	}
}

// unlose handles a belated (out-of-order) packet arrival for FreshLoss.
// It removes the sequence from FreshLoss, dynamically adjusts reorder tolerance,
// and tracks consecutive early/ordered delivery counters.
// . Called only from recvLoop.
func (c *Conn) unlose(p packet.Packet) {
	sequence := p.Header.SequenceNumber
	wasReordered := !p.Header.Retransmitted

	hasIncreasedTolerance := false

	if wasReordered {
		// Calculate reorder distance
		maxSeq := c.maxRecvSeq.Load()
		if c.maxRecvSeqInit.Load() {
			seqDiff := seq.Number(maxSeq).Distance(seq.Number(sequence))
			if seqDiff < 0 {
				seqDiff = -seqDiff
			}
			dist := int(seqDiff)

			// Increase tolerance if reorder distance exceeds current tolerance
			if dist > c.reorderTolerance {
				newTol := dist
				if newTol > c.maxReorderTolerance {
					newTol = c.maxReorderTolerance
				}
				c.reorderTolerance = newTol
				hasIncreasedTolerance = true
			}
		}
	}

	if c.reorderTolerance == 0 {
		return
	}

	// Remove sequence from FreshLoss, capturing its TTL
	hadTTL := c.freshLossRemove(sequence)

	if wasReordered {
		c.consecOrderedDelivery = 0 // reset ordered counter

		if hasIncreasedTolerance {
			c.consecEarlyDelivery = 0 // reset on tolerance increase
		} else if hadTTL > 2 {
			// Packet arrived well before its TTL expired
			c.consecEarlyDelivery++
			if c.consecEarlyDelivery >= 10 {
				c.consecEarlyDelivery = 0
				if c.reorderTolerance > 0 {
					c.reorderTolerance--
				}
			}
		}
		// hadTTL <= 2: arrived just barely in time — no adjustment
	}
}

// freshLossRemove removes a single sequence from the FreshLoss deque.
// Returns the TTL the entry had when removed (0 if not found).
// from list.cpp:900.
func (c *Conn) freshLossRemove(sequence uint32) int {
	for i := 0; i < len(c.freshLoss); i++ {
		e := &c.freshLoss[i]
		lo := seq.Number(e.seqLo)
		hi := seq.Number(e.seqHi)
		s := seq.Number(sequence)

		distLo := lo.Distance(s)
		distHi := hi.Distance(s)

		if distLo < 0 || distHi > 0 {
			continue // not in this range
		}

		hadTTL := e.ttl

		if distLo == 0 && distHi == 0 {
			// Single-element range: delete
			c.freshLoss = append(c.freshLoss[:i], c.freshLoss[i+1:]...)
			return hadTTL
		}

		if distLo == 0 {
			// At the beginning: shrink from front
			e.seqLo = lo.Inc().Value()
			return hadTTL
		}

		if distHi == 0 {
			// At the end: shrink from back
			e.seqHi = hi.Dec().Value()
			return hadTTL
		}

		// In the middle: split into two ranges
		newEntry := freshLossEntry{
			seqLo: s.Inc().Value(),
			seqHi: e.seqHi,
			ttl:   e.ttl,
		}
		e.seqHi = s.Dec().Value()
		// Insert newEntry after current position
		c.freshLoss = append(c.freshLoss[:i+1], append([]freshLossEntry{newEntry}, c.freshLoss[i+1:]...)...)
		return hadTTL
	}
	return 0
}

// SendKeepAlive sends an immediate keepalive to the peer.
// Used by Group to notify the peer when a link is silenced to standby.
// sendBackup_CheckIdleTime: sends KEEPALIVE
// after sender buffer drains on a silenced link.
func (c *Conn) SendKeepAlive() {
	c.sendKeepAlive()
}

func (c *Conn) sendKeepAlive() {
	p := packet.NewControl(c.remoteAddr, packet.CtrlTypeKeepalive, c.peerSocketID, c.clk.Now().SRTTimestamp())
	c.m.Send(p)
	c.lastSndTime.Store(time.Now().UnixNano())
	p.Release()

	//internalKeepalive(): when we send a keepalive
	// (EXP timer fires with no data to send), also signal group idle state.
	// This ensures early IDLE recognition when both directions are quiet.
	if c.groupID != 0 {
		c.groupIdle.Store(true)
	}
}

// updateLastSndTime records the current time as the last send time.
// Used by the keepalive timer to avoid redundant keepalives during active send.
func (c *Conn) updateLastSndTime() {
	c.lastSndTime.Store(time.Now().UnixNano())
}

// ---- Key Rotation ----

// oppositeKey returns the other encryption key slot.
func oppositeKey(k packet.PacketEncryption) packet.PacketEncryption {
	if k == packet.EncryptionEven {
		return packet.EncryptionOdd
	}
	return packet.EncryptionEven
}

// srtMaxKMRetry is the maximum number of KMREQ retransmissions.
const srtMaxKMRetry = 10

// checkKeyRotation is called after each encrypted packet send.
// Three phases:
//  1. Pre-announce: generate new key, send KMREQ (retry via RTT-based timer)
//  2. Refresh: switch active key, mark old for decommission
//  3. Decommission: clear deprecated key after preAnnounce packets
func (c *Conn) checkKeyRotation() {
	c.kmPacketCount++

	// Pre-announce: generate new key and send KMREQ
	preAnnounceAt := c.kmRefreshRate - c.kmPreAnnounce
	if c.kmPacketCount == preAnnounceAt && !c.kmAnnounced {
		nextKey := oppositeKey(c.activeKey)
		if err := c.cryptoCtx.GenerateSEK(nextKey); err != nil {
			return
		}
		c.sendKMREQ(packet.EncryptionBoth)
		c.kmAnnounced = true
		c.kmConfirmed.Store(false)
		c.sndKmState.Store(1) // SRT_KM_S_SECURING
		c.kmRetryKey = nextKey
		c.kmRetryCount = srtMaxKMRetry
		c.kmLastSendTime = c.clk.Now()
	}

	// RTT-based KMREQ retry: every 1.5 × SRTT, max SRT_MAX_KMRETRY attempts.
	//: sendKeysToPeer uses (iSRTT * 3) / 2.
	if c.kmAnnounced && !c.kmConfirmed.Load() && c.kmRetryCount > 0 {
		rttUs := c.rtt.Load()
		if rttUs < 100000 {
			rttUs = 100000 // minimum 100ms between retries
		}
		retryInterval := clock.Microseconds(rttUs * 3 / 2)
		now := c.clk.Now()
		if now.Sub(c.kmLastSendTime) >= retryInterval {
			c.kmRetryCount--
			c.sendKMREQ(packet.EncryptionBoth)
			c.kmLastSendTime = now
		}
	}

	// Refresh: switch active key
	if c.kmPacketCount >= c.kmRefreshRate {
		c.activeKey = oppositeKey(c.activeKey)
		c.kmPacketCount = 0
		c.kmAnnounced = false
		c.kmDecommission = true
		c.kmSwitchCount = 0
	}

	// Decommission: clear deprecated key after preAnnounce packets post-switch.
	//: PostSwitch clears old SEK.
	if c.kmDecommission {
		c.kmSwitchCount++
		if c.kmSwitchCount >= c.kmPreAnnounce {
			oldKey := oppositeKey(c.activeKey)
			c.cryptoCtx.ClearSEK(oldKey)
			c.kmDecommission = false
		}
	}
}

// sendKMREQ sends a Key Material Request for the given key slot.
func (c *Conn) sendKMREQ(key packet.PacketEncryption) {
	if c.passphrase == "" {
		return
	}
	km := &packet.CIFKeyMaterial{}
	if err := c.cryptoCtx.MarshalKM(km, c.passphrase, key); err != nil {
		return
	}
	data, err := km.MarshalCIF()
	if err != nil {
		return
	}

	p := packet.NewControl(c.remoteAddr, packet.CtrlTypeUser, c.peerSocketID, c.clk.Now().SRTTimestamp())
	p.Header.SubType = packet.ExtTypeKMReq
	p.SetData(data)
	c.m.Send(p)
	p.Release()
	c.sentKM.Add(1)
}

// handleKMRequest processes a mid-stream KMREQ (key rotation from sender).
func (c *Conn) handleKMRequest(p packet.Packet) {
	c.recvKM.Add(1)
	if c.cryptoCtx == nil || c.passphrase == "" {
		//: no secret configured → NOSECRET(3)
		c.rcvKmState.Store(3) // SRT_KM_S_NOSECRET
		return
	}
	var km packet.CIFKeyMaterial
	if err := km.UnmarshalCIF(p.Data); err != nil {
		//: invalid KM message → BADSECRET(4)
		c.rcvKmState.Store(4) // SRT_KM_S_BADSECRET
		return
	}
	if err := c.cryptoCtx.UnmarshalKM(&km, c.passphrase); err != nil {
		//: unwrap failure → BADSECRET(4)
		// (or BADCRYPTOMODE(5) for cipher mismatch, but we map both to BADSECRET
		// since we don't distinguish at this level)
		c.rcvKmState.Store(4) // SRT_KM_S_BADSECRET
		c.sndKmState.Store(4)
		errResp := packet.NewControl(c.remoteAddr, packet.CtrlTypeUser, c.peerSocketID, c.clk.Now().SRTTimestamp())
		errResp.Header.SubType = packet.ExtTypeKMRsp
		errData := make([]byte, 4)
		binary.BigEndian.PutUint32(errData, 4) // SRT_KM_S_BADSECRET
		errResp.SetData(errData)
		c.m.Send(errResp)
		errResp.Release()
		return
	}

	// Send KMRSP echoing back the key material
	resp := &packet.CIFKeyMaterial{}
	if err := c.cryptoCtx.MarshalKM(resp, c.passphrase, km.KeyBasedEncryption); err != nil {
		return
	}
	data, err := resp.MarshalCIF()
	if err != nil {
		return
	}

	rp := packet.NewControl(c.remoteAddr, packet.CtrlTypeUser, c.peerSocketID, c.clk.Now().SRTTimestamp())
	rp.Header.SubType = packet.ExtTypeKMRsp
	rp.SetData(data)
	c.m.Send(rp)
	rp.Release()
}

// handleKMResponse processes a mid-stream KMRSP (confirmation of key rotation).
func (c *Conn) handleKMResponse(p packet.Packet) {
	c.recvKM.Add(1)

	//: Check for error response (single 32-bit word = KM state).
	// A 4-byte KMRSP contains only the error code (e.g., SRT_KM_S_BADSECRET=4).
	// The peer rejected our key — don't confirm.
	if len(p.Data) == 4 {
		kmState := int32(binary.BigEndian.Uint32(p.Data))
		//: error KMRSP sets both snd and rcv KM state
		if kmState >= 3 && kmState <= 5 {
			c.sndKmState.Store(kmState)
			c.rcvKmState.Store(kmState)
		}
		return
	}

	// The peer confirmed the new key — stop retrying KMREQ.
	// The key was already installed when we generated it in checkKeyRotation.
	c.kmConfirmed.Store(true)
	c.sndKmState.Store(2) // SRT_KM_S_SECURED
	c.rcvKmState.Store(2) // SRT_KM_S_SECURED
}

// ---- HSv4 post-handshake extension exchange ----

// sendHSv4Extensions sends HSREQ (and optionally KMREQ) via UMSG_EXT
// for HSv4 connections where the INITIATOR (sender) must initiate
// the SRT extension exchange after the basic UDT handshake completes.
func (c *Conn) sendHSv4Extensions(cfg Config) {
	// Build HSREQ with single latency value (HSv4 uses one 16-bit latency field)
	latency := cfg.peerLatencyMS()
	hsreq := handshake.BuildExtHSREQ(
		c.peerSocketID,
		handshake.SRTVersion,
		cfg.srtFlags(),
		latency,
		c.remoteAddr,
	)
	c.m.Send(hsreq)
	hsreq.Release()

	// If encryption is configured, send KMREQ
	if cfg.Passphrase != "" {
		keyLen := cfg.KeyLength
		if keyLen == 0 {
			keyLen = 16
		}
		cipherMode := crypto.CipherCTR
		if cfg.CryptoMode == 2 {
			cipherMode = crypto.CipherGCM
		}
		cryptoCtx, err := crypto.NewWithMode(keyLen, cipherMode)
		if err != nil {
			return
		}
		activeKey := packet.EncryptionEven
		km := &packet.CIFKeyMaterial{}
		if err := cryptoCtx.MarshalKM(km, cfg.Passphrase, activeKey); err != nil {
			return
		}
		kmreq := handshake.BuildExtKMREQ(c.peerSocketID, km, c.remoteAddr)
		c.m.Send(kmreq)
		kmreq.Release()

		// Install crypto context on the connection
		c.cryptoCtx = cryptoCtx
		c.activeKey = activeKey
		c.passphrase = cfg.Passphrase
		c.kmRefreshRate = cfg.KMRefreshRate
		c.kmPreAnnounce = cfg.KMPreAnnounce
		c.sndKmState.Store(1) // SECURING until KMRSP
	}
}

// handleHSREQ processes an incoming HSREQ from the peer (UMSG_EXT).
// The RESPONDER receives HSREQ, negotiates parameters, and sends back HSRSP.
func (c *Conn) handleHSREQ(p packet.Packet) {
	peerVersion, peerFlags, peerLatency, err := handshake.ParseExtHSREQ(p.Data)
	if err != nil {
		return
	}

	c.peerSRTVersion = peerVersion

	// Negotiate latency: use the larger of the two sides' values
	localLatency := uint16(c.tsbpdDelay.Duration().Milliseconds())
	if localLatency == 0 {
		localLatency = uint16(DefaultLatency.Milliseconds())
	}
	negotiatedLatency := peerLatency
	if localLatency > negotiatedLatency {
		negotiatedLatency = localLatency
	}

	// Enable TSBPD on receiver side with negotiated latency
	if peerFlags&packet.FlagTSBPDSend != 0 {
		c.tsbpdEnabled = true
		c.tsbpdDelay = clock.Microseconds(negotiatedLatency) * clock.Millisecond
		if c.tsbpdTimer == nil {
			now := c.clk.Now()
			c.tsbpdTimer = tsbpd.New(c.tsbpdDelay, now)
			if !c.driftTracer {
				c.tsbpdTimer.SetDriftEnabled(false)
			}
		}
	}

	// Negotiate TLPKTDROP
	if peerFlags&packet.FlagTLPktDrop != 0 {
		c.tlpktdropEnabled = true
	}

	// Negotiate periodic NAK
	c.peerNakReport = peerFlags&packet.FlagPeriodicNAK != 0

	// Send HSRSP back to peer
	respFlags := uint32(packet.FlagCrypt | packet.FlagRexmit)
	if c.tsbpdEnabled {
		respFlags |= packet.FlagTSBPDRecv
	}
	if c.tlpktdropEnabled {
		respFlags |= packet.FlagTLPktDrop
	}
	if c.periodicNAK {
		respFlags |= packet.FlagPeriodicNAK
	}

	hsrsp := handshake.BuildExtHSRSP(
		c.peerSocketID,
		handshake.SRTVersion,
		respFlags,
		negotiatedLatency,
		c.remoteAddr,
	)
	c.m.Send(hsrsp)
	hsrsp.Release()

	c.hsExtDone.Store(true)
}

// handleHSRSP processes an incoming HSRSP from the peer (UMSG_EXT).
// The INITIATOR receives HSRSP to confirm the negotiated parameters.
func (c *Conn) handleHSRSP(p packet.Packet) {
	peerVersion, peerFlags, negotiatedLatency, err := handshake.ParseExtHSREQ(p.Data)
	if err != nil {
		return
	}

	c.peerSRTVersion = peerVersion

	// The INITIATOR (sender) enables sender-side features based on negotiated flags
	if peerFlags&packet.FlagTSBPDRecv != 0 {
		// Peer will use TSBPD — set peer delay for sender-side drop timing
		c.peerTsbpdDelay = clock.Microseconds(negotiatedLatency) * clock.Millisecond
		c.recomputeSendDropThresh()
	}

	c.peerNakReport = peerFlags&packet.FlagPeriodicNAK != 0

	c.hsExtDone.Store(true)
}

// ---- Helper methods ----

func (c *Conn) loadLastACKSeq() seq.Number {
	return seq.Number(c.lastACKSeq.Load())
}

func (c *Conn) storeLastACKSeq(s seq.Number) {
	c.lastACKSeq.Store(uint32(s))
}

// flightSize returns the number of packets in flight (sent but not ACK'd).
// This is equivalent to nextSeq - startSeq on the send buffer.
func (c *Conn) flightSize() int {
	return c.sendBuf.Size()
}

// currentFlowWindow returns the current flow window size in packets.
// : perf->pktFlowWindow =.load()
// Uses the dynamic value from receiver's ACK (AvailableBufferSize), or
// the negotiated FC if no dynamic update has been received yet.
func (c *Conn) currentFlowWindow() int {
	if fws := int(c.flowWindowSize.Load()); fws > 0 {
		return fws
	}
	return c.fc
}

// nakInterval returns the NAK report interval, delegating to the CC algorithm.
// : base = RTT + 4*RTTVar, then CC adjusts
// (LiveCC divides by 2 via=2, FileCC leaves unchanged),
// then clamp to CC minimum (LiveCC: 20ms, FileCC: default 300ms).
func (c *Conn) nakInterval() time.Duration {
	rttUs := c.rtt.Load()
	rttVarUs := c.rttVar.Load()
	baseUs := rttUs + 4*rttVarUs

	// Delegate to CC for algorithm-specific adjustment
	adjustedUs := c.sendCC.UpdateNAKInterval(baseUs, 0, 0)

	interval := time.Duration(adjustedUs) * time.Microsecond
	if interval < c.minNAKInterval {
		interval = c.minNAKInterval
	}
	return interval
}

func (c *Conn) signalReadReady() {
	select {
	case c.readReady <- struct{}{}:
	default:
	}
	if wc := c.watchChans.Load(); wc != nil {
		select {
		case wc.readReady <- struct{}{}:
		default:
		}
	}
}

func (c *Conn) signalWriteReady() {
	select {
	case c.writeReady <- struct{}{}:
	default:
	}
	if wc := c.watchChans.Load(); wc != nil {
		select {
		case wc.writeReady <- struct{}{}:
		default:
		}
	}
}

// registerWatch allocates watch mirror channels and returns them.
// Only one Watcher may be registered at a time.
func (c *Conn) registerWatch() (readCh, writeCh <-chan struct{}) {
	wc := &watchChannels{
		readReady:  make(chan struct{}, 1),
		writeReady: make(chan struct{}, 1),
	}
	c.watchChans.Store(wc)
	return wc.readReady, wc.writeReady
}

// unregisterWatch clears watch mirror channels.
func (c *Conn) unregisterWatch() {
	c.watchChans.Store(nil)
}

func (c *Conn) readDeadlineTime() time.Time {
	if v := c.readDeadline.Load(); v != nil {
		return v.(time.Time)
	}
	return time.Time{}
}

func (c *Conn) writeDeadlineTime() time.Time {
	if v := c.writeDeadline.Load(); v != nil {
		return v.(time.Time)
	}
	return time.Time{}
}

func (c *Conn) setShutdownErr(err error) {
	c.shutdownMu.Lock()
	if c.shutdownErr == nil {
		c.shutdownErr = err
	}
	c.shutdownMu.Unlock()
}

func (c *Conn) getShutdownErr() error {
	c.shutdownMu.Lock()
	defer c.shutdownMu.Unlock()
	if c.shutdownErr != nil {
		return c.shutdownErr
	}
	return net.ErrClosed
}
