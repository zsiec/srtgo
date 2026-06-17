package core

import (
	"encoding/binary"
	"hash/fnv"

	"github.com/zsiec/srtgo/internal/clock"
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
	RecvLatencyMS  uint16
	SendLatencyMS  uint16
	Congestion     string // "live" or "file" (empty -> "live")
	Live           bool   // TSBPD playout on accepted connections
	MaxBW          int64
	PayloadSize    int
	BufferCapacity int
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
}

func (Accepted) isListenerEvent() {}

// acceptedConn remembers the parameters of an accepted peer so a duplicate
// CONCLUSION (its response was lost) can be answered without re-accepting.
type acceptedConn struct {
	socketID uint32
	isn      seq.Number
	mss      uint32
	fc       uint32
	recvLat  uint16
	sendLat  uint16
}

// Listener is the pure, Sans-I/O SRT listener state machine. Induction is
// stateless: the response is a keyed-hash SYN cookie of the peer, so a flood of
// induction requests costs nothing to remember. State begins at CONCLUSION,
// where the cookie is verified and a connection accepted.
type Listener struct {
	cfg          ListenerConfig
	cookieSecret uint64
	rng          func([]byte) // host-provided entropy for socket IDs / ISNs
	accepted     map[PeerID]acceptedConn

	outputs fifo[ListenerOutput]
	events  fifo[ListenerEvent]
}

// NewListener builds a listener. cookieSecret keys the SYN cookie (the host
// generates it randomly); rng supplies entropy for accepted socket IDs and ISNs.
func NewListener(cfg ListenerConfig, cookieSecret uint64, rng func([]byte)) *Listener {
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
		accepted:     make(map[PeerID]acceptedConn),
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
		return // missing/invalid cookie: drop
	}
	// Duplicate CONCLUSION (our response was lost): resend, don't re-accept.
	if a, ok := l.accepted[peer]; ok {
		l.outputs.push(SendTo{Peer: peer, Packet: l.buildConclusionResponse(a, hs.SRTSocketID)})
		return
	}

	recvLat, sendLat := l.cfg.RecvLatencyMS, l.cfg.SendLatencyMS
	if hs.HasHS && hs.SRTHS != nil { // negotiated latency = max of both sides
		if hs.SRTHS.RecvTSBPDDelay > recvLat {
			recvLat = hs.SRTHS.RecvTSBPDDelay
		}
		if hs.SRTHS.SendTSBPDDelay > sendLat {
			sendLat = hs.SRTHS.SendTSBPDDelay
		}
	}
	a := acceptedConn{
		socketID: l.randUint32() | 1, // nonzero
		isn:      seq.Number(l.randUint32() & uint32(seq.Max)),
		mss:      hs.MaxTransmissionUnitSize,
		fc:       hs.MaxFlowWindowSize,
		recvLat:  recvLat,
		sendLat:  sendLat,
	}
	l.accepted[peer] = a
	l.outputs.push(SendTo{Peer: peer, Packet: l.buildConclusionResponse(a, hs.SRTSocketID)})

	conn := &Conn{}
	conn.establish(now, establishParams{
		PeerSocketID:   hs.SRTSocketID,
		PayloadSize:    l.cfg.PayloadSize,
		SendISN:        a.isn,
		RecvISN:        seq.Number(hs.InitialPacketSequenceNumber),
		FlowWindow:     int(a.fc),
		BufferCapacity: l.cfg.BufferCapacity,
		MaxBW:          l.cfg.MaxBW,
		Live:           l.cfg.Live,
		TsbpdDelay:     clock.Microseconds(recvLat) * 1000,
	})
	l.events.push(Accepted{Conn: conn, Peer: peer, SocketID: a.socketID, StreamID: hs.StreamID})
}

func (l *Listener) buildConclusionResponse(a acceptedConn, callerSocketID uint32) packet.Packet {
	return handshake.BuildConclusionResponse(
		a.socketID, a.isn.Value(),
		a.mss, a.fc,
		callerSocketID,
		a.recvLat, a.sendLat,
		0, // srtFlags 0 -> handshake defaults
		l.cfg.Congestion,
		"",      // no FEC filter
		0, 0, 0, // no group
		nil, // addr (host fills); PeerIP 0.0.0.0
		nil, // no key material (unencrypted)
	)
}

func (l *Listener) randUint32() uint32 {
	var b [4]byte
	l.rng(b[:])
	return binary.BigEndian.Uint32(b[:])
}
