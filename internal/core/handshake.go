package core

import (
	"fmt"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/handshake"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
)

// connState tracks handshake progress.
type connState uint8

const (
	stateInduction  connState = iota // caller: induction sent, awaiting response
	stateConclusion                  // caller: conclusion sent, awaiting response
	stateConnected                   // data path active
	stateFailed                      // handshake failed; connection dead
)

// handshakeRetryInterval is the period between handshake retransmissions. UDP
// packets can be dropped, so each step retransmits until answered or the host's
// overall dial deadline expires.
const handshakeRetryInterval = 250 * clock.Millisecond

// SRT rejection codes (subset; mirror the public srt package's Rej* values).
const (
	rejRogue     = 1004 // incorrect data in handshake
	rejBadSecret = 1010 // wrong passphrase
	rejUnsecure  = 1011 // passphrase required or unexpected
)

// RejectError is the error surfaced (via a Failed event) when the peer rejects
// a connection with an SRT rejection code.
type RejectError struct {
	Code uint32
}

func (e RejectError) Error() string {
	return fmt.Sprintf("srt: connection rejected (code %d)", e.Code)
}

// DialConfig parameters a caller-side HSv5 handshake. The host generates the
// random socket ID and ISN (the core takes no entropy source) and supplies the
// data-path configuration to apply once the connection is established.
type DialConfig struct {
	CallerSocketID uint32     // random, nonzero
	CallerISN      seq.Number // random 31-bit initial sequence number
	MSS            uint32     // proposed MTU (0 -> 1500)
	FC             uint32     // proposed flow window in packets (0 -> 8192)
	RecvLatencyMS  uint16     // receive TSBPD latency, ms (0 -> 120)
	SendLatencyMS  uint16     // send TSBPD latency, ms (0 -> 120)
	Congestion     string     // "live" or "file" (empty -> "live")
	StreamID       string     // optional stream ID
	FilterConfig   string     // FEC packet filter, e.g. "fec,cols:10,rows:5" ("" = off)

	// Encryption. The host supplies a crypto context (it owns the entropy used
	// to generate the salt and keys); Passphrase wraps the key material in the
	// KMREQ. CryptoCtx nil means an unencrypted connection. KeyLength and
	// CryptoMode are hints the host uses to build CryptoCtx (see session.Dial).
	CryptoCtx     *crypto.Context
	Passphrase    string
	KeyLength     int    // AES key bytes: 16/24/32 (0 -> 16); used by the host
	CryptoMode    int    // 0/1 -> AES-CTR, 2 -> AES-GCM; used by the host
	KMRefreshRate uint64 // encrypted packets between key rotations (0 = disabled)
	KMPreAnnounce uint64 // packets before a switch to announce the next key
	// AllowUnencryptedFallback connects unencrypted if the listener returns no key
	// material (SRTO_ENFORCEDENCRYPTION=false). Off by default (encryption enforced).
	AllowUnencryptedFallback bool

	// Applied once the handshake completes.
	PayloadSize     int                // data payload per packet (0 -> MSS-44)
	BufferCapacity  int                // send/recv ring capacity (0 -> default)
	MaxBW           int64              // max send bandwidth bytes/sec (0 -> LiveCC default)
	Live            bool               // TSBPD playout (live mode)
	Message         bool               // message-mode framing (file API; ignored when Live)
	TLPktDrop       bool               // sender-side too-late packet drop (ignored unless Live)
	SndDropDelay    int                // extra ms added to the sender drop threshold
	LossMaxTTL      int                // reorder tolerance in packets (SRTO_LOSSMAXTTL; 0 = NAK gaps immediately)
	PeerIdleTimeout clock.Microseconds // dead-peer timeout (0 = disabled)

	// ForceHSv4 makes the caller use the legacy HSv4 handshake (UDT_DGRAM
	// CONCLUSION + post-handshake HSREQ/HSRSP over UMSG_EXT) regardless of the
	// peer's induction response. The caller also falls back to HSv4 automatically
	// when the peer answers induction with HSv4 (version 4, UDT marker).
	ForceHSv4 bool

	// Group membership (connection bonding). When GroupID is nonzero the caller
	// advertises this connection as a member of the group in its CONCLUSION; the
	// listener forms/joins a group keyed by GroupID. GroupType is 1=broadcast,
	// 2=backup; GroupWeight is the member priority (backup).
	GroupID     uint32
	GroupType   uint8
	GroupWeight uint16
}

// dialState holds the caller handshake parameters until the connection is
// established, after which Conn.dial is cleared.
type dialState struct {
	socketID  uint32
	isn       seq.Number
	mss       uint32
	fc        uint32
	recvLatMS uint16
	sendLatMS uint16
	cong      string
	streamID  string
	filterCfg string

	cookie uint32 // learned from the induction response

	cryptoCtx          *crypto.Context
	passphrase         string
	kmRefreshRate      uint64
	kmPreAnnounce      uint64
	allowUnencFallback bool

	payloadSize     int
	bufferCapacity  int
	maxBW           int64
	live            bool
	message         bool
	tlPktDrop       bool
	sndDropDelay    int
	lossMaxTTL      int
	peerIdleTimeout clock.Microseconds

	forceHSv4 bool // caller: force the legacy HSv4 handshake
	hsv4      bool // caller: HSv4 negotiated (forced or peer answered v4)

	groupID     uint32 // group membership advertised in the CONCLUSION (0 = none)
	groupType   uint8
	groupWeight uint16
}

// Dial creates a caller-side connection, emits the INDUCTION request, and arms
// the handshake retransmit timer. Drive it like any other core: feed responses
// via HandlePacket and fire TimerHandshake; it surfaces a Connected or Failed
// event when the handshake resolves. Only HSv5 is supported.
func Dial(dc DialConfig, now clock.Timestamp) *Conn {
	if dc.MSS == 0 {
		dc.MSS = 1500
	}
	if dc.FC == 0 {
		dc.FC = 8192
	}
	if dc.RecvLatencyMS == 0 {
		dc.RecvLatencyMS = 120
	}
	if dc.SendLatencyMS == 0 {
		dc.SendLatencyMS = 120
	}
	if dc.Congestion == "" {
		dc.Congestion = "live"
	}
	payloadSize := dc.PayloadSize
	if payloadSize <= 0 {
		payloadSize = int(dc.MSS) - 44 // SRT (16) + IPv4/UDP (28) overhead
	}
	c := &Conn{
		state: stateInduction,
		dial: &dialState{
			socketID:           dc.CallerSocketID,
			isn:                dc.CallerISN,
			mss:                dc.MSS,
			fc:                 dc.FC,
			recvLatMS:          dc.RecvLatencyMS,
			sendLatMS:          dc.SendLatencyMS,
			cong:               dc.Congestion,
			streamID:           dc.StreamID,
			filterCfg:          dc.FilterConfig,
			cryptoCtx:          dc.CryptoCtx,
			passphrase:         dc.Passphrase,
			kmRefreshRate:      dc.KMRefreshRate,
			kmPreAnnounce:      dc.KMPreAnnounce,
			allowUnencFallback: dc.AllowUnencryptedFallback,
			payloadSize:        payloadSize,
			bufferCapacity:     dc.BufferCapacity,
			maxBW:              dc.MaxBW,
			live:               dc.Live,
			message:            dc.Message,
			tlPktDrop:          dc.TLPktDrop,
			sndDropDelay:       dc.SndDropDelay,
			lossMaxTTL:         dc.LossMaxTTL,
			peerIdleTimeout:    dc.PeerIdleTimeout,
			forceHSv4:          dc.ForceHSv4,
			groupID:            dc.GroupID,
			groupType:          dc.GroupType,
			groupWeight:        dc.GroupWeight,
		},
	}
	c.sendInduction(now)
	return c
}

// sendInduction builds and emits the INDUCTION request and arms the retransmit
// timer. The packet leaves PeerIP as 0.0.0.0 (addr nil); the host fills the
// destination address — this keeps the core free of any net dependency.
func (c *Conn) sendInduction(now clock.Timestamp) {
	d := c.dial
	p := handshake.BuildInduction(d.socketID, d.isn.Value(), d.mss, d.fc, nil)
	c.outputs.push(SendPacket{Packet: p, Owned: true})
	c.outputs.push(SetTimer{ID: TimerHandshake, Deadline: now.Add(handshakeRetryInterval)})
}

// sendConclusion builds and emits the CONCLUSION request (echoing the cookie,
// carrying the HSREQ extension) and re-arms the retransmit timer.
func (c *Conn) sendConclusion(now clock.Timestamp) {
	d := c.dial
	var km *packet.CIFKeyMaterial
	if d.cryptoCtx != nil {
		km = &packet.CIFKeyMaterial{}
		if err := d.cryptoCtx.MarshalKM(km, d.passphrase, packet.EncryptionEven); err != nil {
			km = nil // fall through unencrypted; handleConclusionResponse will fail if KM was required
		}
	}
	p := handshake.BuildConclusion(
		d.socketID, d.isn.Value(), d.mss, d.fc, d.cookie,
		d.streamID, d.recvLatMS, d.sendLatMS,
		d.srtFlags(), // advertise our negotiated feature set
		d.cong,
		d.filterCfg,                           // FEC filter ("" = off)
		d.groupID, d.groupType, d.groupWeight, // group membership (0 = none)
		nil, // addr (host fills); PeerIP 0.0.0.0
		km,  // key material (nil = unencrypted)
	)
	c.outputs.push(SendPacket{Packet: p, Owned: true})
	c.outputs.push(SetTimer{ID: TimerHandshake, Deadline: now.Add(handshakeRetryInterval)})
}

// srtFlags computes the SRT feature flags this caller advertises in its
// CONCLUSION, reflecting the actual configuration rather than a fixed default:
// TSBPD in live mode, Crypt when encrypted, TLPKTDROP when enabled, periodic NAK
// except in file mode, retransmit always, and the byte-stream flag for stream
// mode (non-live, non-message).
func (d *dialState) srtFlags() uint32 {
	f := packet.FlagRexmit
	if d.live {
		f |= packet.FlagTSBPDSend | packet.FlagTSBPDRecv
	}
	if d.cryptoCtx != nil {
		f |= packet.FlagCrypt
	}
	if d.tlPktDrop {
		f |= packet.FlagTLPktDrop
	}
	if d.cong != "file" {
		f |= packet.FlagPeriodicNAK
	}
	if !d.live && !d.message {
		f |= packet.FlagStream
	}
	return f
}

// handleHandshake dispatches a received handshake packet by current state.
func (c *Conn) handleHandshake(now clock.Timestamp, p packet.Packet) {
	var hs packet.CIFHandshake
	if err := p.UnmarshalCIF(&hs); err != nil {
		return // malformed; a retransmit will follow
	}
	if hs.HandshakeType.IsRejection() {
		c.fail(RejectError{Code: uint32(hs.HandshakeType)})
		return
	}
	if c.rdv != nil {
		c.handleRendezvous(now, &hs, p.Header.Timestamp)
		return
	}
	switch c.state {
	case stateInduction:
		c.handleInductionResponse(now, &hs)
	case stateConclusion:
		c.handleConclusionResponse(now, &hs)
	}
	// Connected/failed: ignore stray handshake retransmissions.
}

// handleHandshakeTimer retransmits the current handshake step.
func (c *Conn) handleHandshakeTimer(now clock.Timestamp) {
	if c.rdv != nil {
		c.rendezvousRetransmit(now)
		return
	}
	switch c.state {
	case stateInduction:
		c.sendInduction(now)
	case stateConclusion:
		if c.dial.hsv4 {
			c.sendConclusionV4(now)
		} else {
			c.sendConclusion(now)
		}
	}
}

func (c *Conn) handleInductionResponse(now clock.Timestamp, hs *packet.CIFHandshake) {
	if hs.HandshakeType != packet.HandshakeTypeInduction {
		return
	}
	d := c.dial
	// HSv4: fall back when the peer answers with version 4 (UDT marker), or when
	// the caller is forced to HSv4. The SRT features are negotiated post-handshake
	// over UMSG_EXT instead of in the CONCLUSION.
	if d.forceHSv4 || (hs.Version == 4 && hs.ExtensionField == handshake.UDTV4Marker) {
		d.hsv4 = true
		d.cookie = hs.SynCookie
		c.state = stateConclusion
		c.sendConclusionV4(now)
		return
	}
	// Otherwise HSv5: require the SRT magic in the extension field.
	if hs.Version != 5 || hs.ExtensionField != handshake.SRTMagic {
		c.fail(fmt.Errorf("core: peer is not HSv5 SRT (version=%d extField=%#x)", hs.Version, hs.ExtensionField))
		return
	}
	d.cookie = hs.SynCookie
	c.state = stateConclusion
	c.sendConclusion(now)
}

func (c *Conn) handleConclusionResponse(now clock.Timestamp, hs *packet.CIFHandshake) {
	if c.dial.hsv4 {
		c.handleConclusionResponseV4(now, hs)
		return
	}
	if hs.HandshakeType != packet.HandshakeTypeConclusion {
		return // e.g. a duplicated induction response; keep waiting
	}
	if hs.InitialPacketSequenceNumber > uint32(seq.Max) {
		c.fail(fmt.Errorf("core: peer ISN %d out of range", hs.InitialPacketSequenceNumber))
		return
	}
	if hs.MaxFlowWindowSize < 2 {
		c.fail(fmt.Errorf("core: peer flow window %d too small", hs.MaxFlowWindowSize))
		return
	}

	d := c.dial
	recvLatMS := d.recvLatMS
	if hs.HasHS && hs.SRTHS != nil {
		recvLatMS = hs.SRTHS.RecvTSBPDDelay // negotiated value from HSRSP
	}
	fc := int(d.fc)
	if int(hs.MaxFlowWindowSize) < fc {
		fc = int(hs.MaxFlowWindowSize)
	}
	// FEC: the listener's echoed filter config is authoritative when present.
	filterCfg := d.filterCfg
	if hs.HasFilter && hs.FilterConfig != "" {
		filterCfg = hs.FilterConfig
	}

	// We requested encryption but the listener returned no key material. With the
	// fallback allowed (EnforcedEncryption=false) we connect unencrypted; otherwise
	// it is a hard mismatch.
	if d.cryptoCtx != nil && !hs.HasKM {
		if !d.allowUnencFallback {
			c.fail(fmt.Errorf("core: listener returned no key material (encryption mismatch)"))
			return
		}
		d.cryptoCtx = nil // fall back to unencrypted
	}

	c.outputs.push(ClearTimer{ID: TimerHandshake})
	c.establish(now, establishParams{
		PeerSocketID:    hs.SRTSocketID,
		PayloadSize:     d.payloadSize,
		SendISN:         d.isn,
		RecvISN:         seq.Number(hs.InitialPacketSequenceNumber),
		FlowWindow:      fc,
		BufferCapacity:  d.bufferCapacity,
		MaxBW:           d.maxBW,
		Live:            d.live,
		TsbpdDelay:      clock.Microseconds(recvLatMS) * 1000, // ms -> us
		Congestion:      d.cong,
		Message:         d.message,
		TLPktDrop:       d.tlPktDrop,
		SndDropDelay:    d.sndDropDelay,
		LossMaxTTL:      d.lossMaxTTL,
		PeerIdleTimeout: d.peerIdleTimeout,
		CryptoCtx:       d.cryptoCtx,
		ActiveKey:       packet.EncryptionEven,
		Passphrase:      d.passphrase,
		KMRefreshRate:   d.kmRefreshRate,
		KMPreAnnounce:   d.kmPreAnnounce,
		FilterConfig:    filterCfg,
	})
	c.dial = nil
	c.events.push(Connected{PeerSocketID: hs.SRTSocketID})
}

// handshakeRefused fails a connecting caller that received a SHUTDOWN (the way
// an HSv4 listener refuses a connection).
func (c *Conn) handshakeRefused() {
	c.fail(fmt.Errorf("srt: connection refused during handshake"))
}

// fail marks the handshake failed and surfaces a Failed event.
func (c *Conn) fail(err error) {
	c.state = stateFailed
	c.closed = true
	c.outputs.push(ClearTimer{ID: TimerHandshake})
	c.events.push(Failed{Err: err})
}
