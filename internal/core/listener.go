package core

import (
	"encoding/binary"
	"hash/fnv"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/handshake"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
)

// PeerID is an opaque identity for a remote peer. The host maps it to a network
// address; using a string keeps the listener core free of any net dependency.
// The SYN cookie is a keyed hash of this value.
type PeerID = string

// ListenerConfig parameters accepted connections.
type ListenerConfig struct {
	RecvLatencyMS   uint16
	SendLatencyMS   uint16
	Congestion      string             // "live" or "file" (empty -> "live")
	Live            bool               // TSBPD playout on accepted connections
	Message         bool               // message-mode framing on accepted connections (ignored when Live)
	TLPktDrop       bool               // sender-side too-late packet drop (ignored unless Live)
	SndDropDelay    int                // extra ms added to the sender drop threshold
	PeerIdleTimeout clock.Microseconds // dead-peer timeout on accepted connections (0 = disabled)
	MaxBW           int64
	PayloadSize     int
	BufferCapacity  int
	Passphrase      string // if set, accept encrypted callers (unwrap their KMREQ)
	KMRefreshRate   uint64 // encrypted packets between key rotations (0 = disabled)
	KMPreAnnounce   uint64 // packets before a switch to announce the next key
	FilterConfig    string // FEC packet filter to offer ("" = off)
}

// ListenerOutput is a datagram the listener asks the host to send to a peer.
// (Sealed; the host switches over it exhaustively.)
type ListenerOutput interface{ isListenerOutput() }

// SendTo asks the host to transmit Packet to Peer. The host attaches the
// destination address and releases the packet after sending.
type SendTo struct {
	Peer   PeerID
	Packet packet.Packet
}

func (SendTo) isListenerOutput() {}

// ListenerEvent is something the listener surfaces to the host.
type ListenerEvent interface{ isListenerEvent() }

// Accepted reports a newly established connection. The host registers SocketID
// with its demultiplexer (so the peer's data packets route to Conn) and drives
// Conn with its own session loop.
type Accepted struct {
	Conn     *Conn
	Peer     PeerID
	SocketID uint32 // listener-assigned socket ID for this connection
	StreamID string

	// Group membership (connection bonding). GroupID is nonzero when the caller
	// advertised group membership; members sharing a GroupID also share SharedISN
	// (the send sequence space) so the host can assemble them into one group.
	GroupID     uint32
	GroupType   uint8
	GroupWeight uint16
	SharedISN   seq.Number
}

func (Accepted) isListenerEvent() {}

// acceptedConn remembers the parameters of an accepted peer so a duplicate
// CONCLUSION (its response was lost) can be answered without re-accepting.
type acceptedConn struct {
	socketID  uint32
	isn       seq.Number
	mss       uint32
	fc        uint32
	recvLat   uint16
	sendLat   uint16
	filterCfg string                  // negotiated FEC filter, echoed in the response
	cryptoCtx *crypto.Context         // non-nil for encrypted callers
	kmKey     packet.PacketEncryption // key slot to echo in the KMRSP

	groupID     uint32 // group membership (0 = none)
	groupType   uint8
	groupWeight uint16
}

// Listener is the pure, Sans-I/O SRT listener state machine. Induction is
// stateless: the response is a keyed-hash SYN cookie of the peer, so a flood of
// induction requests costs nothing to remember. State begins at CONCLUSION,
// where the cookie is verified and a connection accepted.
type Listener struct {
	cfg          ListenerConfig
	cookieSecret uint64
	rng          func([]byte)                                                      // host entropy for socket IDs / ISNs
	newCtx       func(keyLen int, mode crypto.CipherMode) (*crypto.Context, error) // host crypto-context factory (may be nil)
	accepted     map[PeerID]acceptedConn
	groups       map[uint32]seq.Number // GroupID -> shared send ISN (bonding)

	outputs fifo[ListenerOutput]
	events  fifo[ListenerEvent]
}

// NewListener builds a listener. cookieSecret keys the SYN cookie (the host
// generates it randomly); rng supplies entropy for accepted socket IDs and ISNs.
// newCtx builds a fresh crypto context (the host owns this entropy); it may be
// nil when no passphrase is configured. The context's random keys are
// immediately overwritten by the caller's unwrapped key material, so the result
// is a deterministic function of the KMREQ and passphrase.
func NewListener(cfg ListenerConfig, cookieSecret uint64, rng func([]byte), newCtx func(keyLen int, mode crypto.CipherMode) (*crypto.Context, error)) *Listener {
	if cfg.RecvLatencyMS == 0 {
		cfg.RecvLatencyMS = 120
	}
	if cfg.SendLatencyMS == 0 {
		cfg.SendLatencyMS = 120
	}
	if cfg.Congestion == "" {
		cfg.Congestion = "live"
	}
	return &Listener{
		cfg:          cfg,
		cookieSecret: cookieSecret,
		rng:          rng,
		newCtx:       newCtx,
		accepted:     make(map[PeerID]acceptedConn),
		groups:       make(map[uint32]seq.Number),
	}
}

// PollOutput drains the next datagram to send; ok is false when none remain.
func (l *Listener) PollOutput() (ListenerOutput, bool) { return l.outputs.pop() }

// PollEvent drains the next accepted connection; ok is false when none remain.
func (l *Listener) PollEvent() (ListenerEvent, bool) { return l.events.pop() }

// HandlePacket feeds one received handshake datagram from peer into the listener.
func (l *Listener) HandlePacket(now clock.Timestamp, p packet.Packet, peer PeerID) {
	if !p.Header.IsControl || p.Header.ControlType != packet.CtrlTypeHandshake {
		return
	}
	var hs packet.CIFHandshake
	if err := p.UnmarshalCIF(&hs); err != nil {
		return
	}
	switch hs.HandshakeType {
	case packet.HandshakeTypeInduction:
		l.handleInduction(peer, &hs)
	case packet.HandshakeTypeConclusion:
		l.handleConclusion(now, peer, &hs)
	}
}

// cookie is a keyed hash of the peer identity — stateless anti-DoS protection.
func (l *Listener) cookie(peer PeerID) uint32 {
	h := fnv.New32a()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], l.cookieSecret)
	_, _ = h.Write(b[:])
	_, _ = h.Write([]byte(peer))
	c := h.Sum32()
	if c == 0 {
		c = 1
	}
	return c
}

// handleInduction replies with the HSv5 induction response (SRT magic + cookie).
// It stores nothing — the cookie is recomputed and verified at CONCLUSION.
func (l *Listener) handleInduction(peer PeerID, hs *packet.CIFHandshake) {
	resp := handshake.BuildInductionResponse(hs, l.cookie(peer), nil, nil, 0)
	l.outputs.push(SendTo{Peer: peer, Packet: resp})
}

// handleConclusion verifies the cookie, negotiates parameters, accepts the
// connection, and replies with the CONCLUSION response.
func (l *Listener) handleConclusion(now clock.Timestamp, peer PeerID, hs *packet.CIFHandshake) {
	if hs.SynCookie != l.cookie(peer) {
		return // missing/invalid cookie: drop silently (likely stale or spoofed)
	}
	// Duplicate CONCLUSION (our response was lost): resend, don't re-accept.
	if a, ok := l.accepted[peer]; ok {
		l.outputs.push(SendTo{Peer: peer, Packet: l.buildConclusionResponse(a, hs.SRTSocketID)})
		return
	}

	// An HSv5 SRT caller must carry the HSREQ extension with a sane version.
	if !hs.HasHS || hs.SRTHS == nil {
		l.reject(peer, hs.SRTSocketID, rejRogue)
		return
	}
	if hs.SRTHS.SRTVersion < 0x010300 {
		l.reject(peer, hs.SRTSocketID, rejRogue)
		return
	}

	recvLat, sendLat := l.cfg.RecvLatencyMS, l.cfg.SendLatencyMS
	if hs.SRTHS.RecvTSBPDDelay > recvLat { // negotiated latency = max of both sides
		recvLat = hs.SRTHS.RecvTSBPDDelay
	}
	if hs.SRTHS.SendTSBPDDelay > sendLat {
		sendLat = hs.SRTHS.SendTSBPDDelay
	}

	// Encryption negotiation. Reject mismatches with the appropriate code.
	var cryptoCtx *crypto.Context
	var kmKey packet.PacketEncryption
	hasKM := hs.HasKM && hs.SRTKM != nil
	switch {
	case l.cfg.Passphrase != "":
		if !hasKM { // listener requires encryption, caller offered none
			l.reject(peer, hs.SRTSocketID, rejUnsecure)
			return
		}
		if l.newCtx == nil {
			l.reject(peer, hs.SRTSocketID, rejUnsecure)
			return
		}
		keyLen := int(hs.SRTKM.KLen)
		if keyLen == 0 {
			keyLen = 16
		}
		// Match the caller's cipher (the KMREQ advertises it); default AES-CTR.
		mode := crypto.CipherCTR
		if hs.SRTKM.Cipher == uint8(crypto.CipherGCM) {
			mode = crypto.CipherGCM
		}
		ctx, err := l.newCtx(keyLen, mode)
		if err != nil || ctx.UnmarshalKM(hs.SRTKM, l.cfg.Passphrase) != nil {
			l.reject(peer, hs.SRTSocketID, rejBadSecret) // wrong passphrase
			return
		}
		cryptoCtx = ctx
		kmKey = hs.SRTKM.KeyBasedEncryption
	case hasKM: // caller wants encryption but the listener has no passphrase
		l.reject(peer, hs.SRTSocketID, rejUnsecure)
		return
	}

	// FEC: adopt the caller's filter config when offered (the host validated a
	// match against l.cfg.FilterConfig before this point if it cares).
	filterCfg := l.cfg.FilterConfig
	if hs.HasFilter && hs.FilterConfig != "" {
		filterCfg = hs.FilterConfig
	}

	a := acceptedConn{
		socketID:  l.randUint32() | 1, // nonzero
		isn:       seq.Number(l.randUint32() & uint32(seq.Max)),
		mss:       hs.MaxTransmissionUnitSize,
		fc:        hs.MaxFlowWindowSize,
		recvLat:   recvLat,
		sendLat:   sendLat,
		filterCfg: filterCfg,
		cryptoCtx: cryptoCtx,
		kmKey:     kmKey,
	}
	// Group bonding: all members sharing a GroupID also share the send sequence
	// space (so the receiver can deduplicate across links). The first member of a
	// group fixes the group's send ISN; later members adopt it.
	if hs.HasGroup && hs.GroupID != 0 {
		if shared, ok := l.groups[hs.GroupID]; ok {
			a.isn = shared
		} else {
			l.groups[hs.GroupID] = a.isn
		}
		a.groupID = hs.GroupID
		a.groupType = hs.GroupType
		a.groupWeight = hs.GroupWeight
	}
	l.accepted[peer] = a
	l.outputs.push(SendTo{Peer: peer, Packet: l.buildConclusionResponse(a, hs.SRTSocketID)})

	conn := &Conn{}
	conn.establish(now, establishParams{
		PeerSocketID:    hs.SRTSocketID,
		PayloadSize:     l.cfg.PayloadSize,
		SendISN:         a.isn,
		RecvISN:         seq.Number(hs.InitialPacketSequenceNumber),
		FlowWindow:      int(a.fc),
		BufferCapacity:  l.cfg.BufferCapacity,
		MaxBW:           l.cfg.MaxBW,
		Live:            l.cfg.Live,
		TsbpdDelay:      clock.Microseconds(recvLat) * 1000,
		Congestion:      l.cfg.Congestion,
		Message:         l.cfg.Message,
		TLPktDrop:       l.cfg.TLPktDrop,
		SndDropDelay:    l.cfg.SndDropDelay,
		PeerIdleTimeout: l.cfg.PeerIdleTimeout,
		CryptoCtx:       cryptoCtx,
		ActiveKey:       packet.EncryptionEven,
		Passphrase:      l.cfg.Passphrase,
		KMRefreshRate:   l.cfg.KMRefreshRate,
		KMPreAnnounce:   l.cfg.KMPreAnnounce,
		FilterConfig:    filterCfg,
	})
	l.events.push(Accepted{
		Conn: conn, Peer: peer, SocketID: a.socketID, StreamID: hs.StreamID,
		GroupID: a.groupID, GroupType: a.groupType, GroupWeight: a.groupWeight, SharedISN: a.isn,
	})
}

func (l *Listener) buildConclusionResponse(a acceptedConn, callerSocketID uint32) packet.Packet {
	var km *packet.CIFKeyMaterial
	if a.cryptoCtx != nil {
		km = &packet.CIFKeyMaterial{}
		if err := a.cryptoCtx.MarshalKM(km, l.cfg.Passphrase, a.kmKey); err != nil {
			km = nil
		}
	}
	return handshake.BuildConclusionResponse(
		a.socketID, a.isn.Value(),
		a.mss, a.fc,
		callerSocketID,
		a.recvLat, a.sendLat,
		0, // srtFlags 0 -> handshake defaults
		l.cfg.Congestion,
		a.filterCfg, // echo negotiated FEC filter
		0, 0, 0,     // no group
		nil, // addr (host fills); PeerIP 0.0.0.0
		km,  // key material echo (nil = unencrypted)
	)
}

// reject sends an HSv5 rejection handshake (HandshakeType set to a rejection
// code) to the caller, which surfaces it as a RejectError.
func (l *Listener) reject(peer PeerID, callerSocketID uint32, code uint32) {
	p := packet.NewControl(nil, packet.CtrlTypeHandshake, callerSocketID, 0)
	rej := &packet.CIFHandshake{
		Version:       5,
		HandshakeType: packet.HandshakeType(code),
		SRTSocketID:   0,
	}
	if err := p.MarshalCIF(rej); err != nil {
		p.Release()
		return
	}
	l.outputs.push(SendTo{Peer: peer, Packet: p})
}

func (l *Listener) randUint32() uint32 {
	var b [4]byte
	l.rng(b[:])
	return binary.BigEndian.Uint32(b[:])
}
