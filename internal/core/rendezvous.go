package core

import (
	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/handshake"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
)

// Rendezvous (simultaneous-open) HSv5 handshake. Both peers dial each other at
// once; a cookie contest assigns one the INITIATOR role (sends HSREQ first) and
// the other the RESPONDER (replies with HSRSP), then an AGREEMENT finalizes the
// connection. The decision logic (rdvCookieContest + rdvSwitchState) is a pure
// function of (state, received type, role, has-extensions), ported from the
// legacy driver; the rest builds/emits the response packets and, on reaching the
// connected state, hands off to the shared establish() data path.
//
// Encryption is supported: when a passphrase is configured, the INITIATOR
// generates the key material and sends it in a KMREQ; the RESPONDER adopts it
// (overwriting its own keys) and echoes a KMRSP, so both encrypt with the same
// AES key regardless of who wins the cookie contest.

const rejRdvCookie = 1005 // SRT_REJ_RDVCOOKIE: cookie collision

// rdvState is the rendezvous handshake phase.
type rdvState uint8

const (
	rdvWaving    rdvState = iota // sent WAVEHAND, awaiting peer's
	rdvAttention                 // received peer's WAVEHAND
	rdvFine                      // received a CONCLUSION while still waving
	rdvInitiated                 // responder sent CONCLUSION+HSRSP, awaiting AGREEMENT
	rdvConnected                 // handshake complete
)

// rdvSide is the role assigned by the cookie contest.
type rdvSide uint8

const (
	rdvDraw      rdvSide = iota // unresolved (cookie collision)
	rdvInitiator                // larger cookie -> sends HSREQ first
	rdvResponder                // smaller cookie -> replies with HSRSP
)

// rdvTransition is the result of a state machine step.
type rdvTransition struct {
	newState   rdvState
	rspType    packet.HandshakeType
	needsExt   bool // attach extensions to the response
	needsHSRSP bool // when needsExt: true -> HSRSP (responder), false -> HSREQ (initiator)
}

// rdvCookieContest determines INITIATOR/RESPONDER by comparing cookies (the
// backward-compatible contest from the reference implementation).
func rdvCookieContest(agentCookie, peerCookie uint32) rdvSide {
	agent := int32(agentCookie)
	peer := int32(peerCookie)
	contest := int64(agent) - int64(peer)
	if contest&0xFFFFFFFF == 0 {
		return rdvDraw
	}
	if contest&0x80000000 != 0 {
		revert := int64(peer) - int64(agent)
		if revert&0x80000000 != 0 && agent > peer {
			return rdvInitiator
		}
		return rdvResponder
	}
	return rdvInitiator
}

// rdvSwitchState is the pure rendezvous transition function.
func rdvSwitchState(state rdvState, recvType packet.HandshakeType, side rdvSide, hasExtFlags bool) rdvTransition {
	t := rdvTransition{}
	switch state {
	case rdvWaving:
		switch recvType {
		case packet.HandshakeTypeWavehand:
			t.newState = rdvAttention
			t.rspType = packet.HandshakeTypeConclusion
			t.needsExt = side == rdvInitiator
			return t
		case packet.HandshakeTypeConclusion:
			t.newState = rdvFine
			t.rspType = packet.HandshakeTypeConclusion
			t.needsExt = true
			t.needsHSRSP = side == rdvResponder
			return t
		}

	case rdvAttention:
		switch recvType {
		case packet.HandshakeTypeWavehand:
			t.newState = rdvAttention
			t.rspType = packet.HandshakeTypeConclusion
			t.needsExt = side == rdvInitiator
			return t
		case packet.HandshakeTypeConclusion:
			if side == rdvInitiator {
				if !hasExtFlags {
					t.newState = rdvAttention
					t.rspType = packet.HandshakeTypeConclusion
					t.needsExt = true
					return t
				}
				t.newState = rdvConnected
				t.rspType = packet.HandshakeTypeAgreement
				return t
			}
			if side == rdvResponder {
				if !hasExtFlags {
					t.newState = rdvAttention
					t.rspType = packet.HandshakeTypeConclusion
					return t
				}
				t.newState = rdvInitiated
				t.rspType = packet.HandshakeTypeConclusion
				t.needsExt = true
				t.needsHSRSP = true
				return t
			}
			t.newState = rdvWaving
			t.rspType = packet.HandshakeType(rejRdvCookie)
			return t
		case packet.HandshakeTypeAgreement:
			if side == rdvInitiator {
				t.newState = rdvConnected
				t.rspType = packet.HandshakeTypeDone
				return t
			}
			t.newState = rdvAttention
			t.rspType = packet.HandshakeTypeConclusion
			t.needsExt = true
			t.needsHSRSP = true
			return t
		}

	case rdvFine:
		switch recvType {
		case packet.HandshakeTypeConclusion:
			if side == rdvInitiator && hasExtFlags {
				t.newState = rdvConnected
				t.rspType = packet.HandshakeTypeAgreement
				return t
			}
			t.newState = rdvFine
			t.rspType = packet.HandshakeTypeConclusion
			t.needsExt = true
			t.needsHSRSP = side == rdvResponder
			return t
		case packet.HandshakeTypeAgreement:
			t.newState = rdvConnected
			t.rspType = packet.HandshakeTypeDone
			return t
		}

	case rdvInitiated:
		switch recvType {
		case packet.HandshakeTypeAgreement:
			t.newState = rdvConnected
			t.rspType = packet.HandshakeTypeDone
			return t
		case packet.HandshakeTypeConclusion:
			t.newState = rdvInitiated
			t.rspType = packet.HandshakeTypeConclusion
			t.needsExt = true
			t.needsHSRSP = true
			return t
		}

	case rdvConnected:
		t.newState = rdvConnected
		t.rspType = packet.HandshakeTypeDone
		return t
	}

	t.newState = rdvWaving
	t.rspType = packet.HandshakeType(rejRogue)
	return t
}

// RendezvousConfig parameters a rendezvous dial. The host supplies the random
// socket ID, ISN, and cookie (the core takes no entropy source) plus the
// data-path configuration applied once connected.
type RendezvousConfig struct {
	SocketID      uint32     // random, nonzero
	ISN           seq.Number // random 31-bit initial sequence number
	Cookie        uint32     // random cookie for the contest
	MSS           uint32     // proposed MTU (0 -> 1500)
	FC            uint32     // proposed flow window (0 -> 8192)
	RecvLatencyMS uint16     // receive TSBPD latency, ms (0 -> 120)
	SendLatencyMS uint16     // send TSBPD latency, ms (0 -> 120)
	Congestion    string     // "live" or "file" (empty -> "live")
	StreamID      string
	FilterConfig  string

	PayloadSize     int
	BufferCapacity  int
	MaxBW           int64
	Live            bool
	Message         bool
	PeerIdleTimeout clock.Microseconds

	// Encryption. The host builds CryptoCtx (it owns the entropy for the salt and
	// keys); Passphrase wraps/unwraps the key material. When set, the rendezvous
	// initiator (larger cookie) sends its key material in a KMREQ and the responder
	// adopts it; both then encrypt with the shared key. Nil CryptoCtx = unencrypted.
	CryptoCtx  *crypto.Context
	Passphrase string
	KeyLength  int // AES key bytes (advertised PBKEYLEN); 0 -> 16
	CryptoMode int // 0/1 -> AES-CTR, 2 -> AES-GCM
}

// rdvDial holds rendezvous handshake state until the connection establishes.
type rdvDial struct {
	socketID  uint32
	isn       seq.Number
	mss, fc   uint32
	cookie    uint32
	recvLatMS uint16
	sendLatMS uint16
	cong      string
	streamID  string
	filterCfg string

	maxBW           int64
	live            bool
	message         bool
	payloadSize     int
	bufferCapacity  int
	peerIdleTimeout clock.Microseconds

	cryptoCtx  *crypto.Context
	passphrase string
	keyLength  int
	kmKey      packet.PacketEncryption // active key slot once negotiated (0 = none)
	kmAdopted  bool                    // responder has adopted the initiator's key material

	rstate rdvState
	side   rdvSide

	peerSocketID uint32
	peerISN      uint32
	peerFC       uint32

	negRecv, negSend uint16
	negotiated       bool

	lastTrans rdvTransition // last emitted transition (for retransmission)
	haveTrans bool          // false until the first transition (retransmit WAVEHAND)
}

// DialRendezvous starts a rendezvous handshake: it emits the initial WAVEHAND and
// arms the retransmit timer. Drive it like any other core (HandlePacket /
// TimerHandshake); it surfaces Connected or Failed when the handshake resolves.
func DialRendezvous(rc RendezvousConfig, now clock.Timestamp) *Conn {
	if rc.MSS == 0 {
		rc.MSS = 1500
	}
	if rc.FC == 0 {
		rc.FC = 8192
	}
	if rc.RecvLatencyMS == 0 {
		rc.RecvLatencyMS = 120
	}
	if rc.SendLatencyMS == 0 {
		rc.SendLatencyMS = 120
	}
	if rc.Congestion == "" {
		rc.Congestion = "live"
	}
	payloadSize := rc.PayloadSize
	if payloadSize <= 0 {
		payloadSize = int(rc.MSS) - 44
	}
	c := &Conn{
		state: stateInduction, // a non-connected state; c.rdv drives dispatch
		rdv: &rdvDial{
			socketID:        rc.SocketID,
			isn:             rc.ISN,
			mss:             rc.MSS,
			fc:              rc.FC,
			cookie:          rc.Cookie,
			recvLatMS:       rc.RecvLatencyMS,
			sendLatMS:       rc.SendLatencyMS,
			cong:            rc.Congestion,
			streamID:        rc.StreamID,
			filterCfg:       rc.FilterConfig,
			maxBW:           rc.MaxBW,
			live:            rc.Live,
			message:         rc.Message,
			payloadSize:     payloadSize,
			bufferCapacity:  rc.BufferCapacity,
			peerIdleTimeout: rc.PeerIdleTimeout,
			cryptoCtx:       rc.CryptoCtx,
			passphrase:      rc.Passphrase,
			keyLength:       rc.KeyLength,
			rstate:          rdvWaving,
			side:            rdvDraw,
		},
	}
	c.sendWavehand()
	c.outputs.push(SetTimer{ID: TimerHandshake, Deadline: now.Add(handshakeRetryInterval)})
	return c
}

// sendWavehand emits the rendezvous WAVEHAND (addr nil; the host fills it).
func (c *Conn) sendWavehand() {
	d := c.rdv
	p := handshake.BuildWavehand(d.socketID, d.isn.Value(), d.mss, d.fc, d.cookie, 0, nil)
	c.outputs.push(SendPacket{Packet: p, Owned: true})
}

// handleRendezvous advances the rendezvous state machine on a received handshake.
func (c *Conn) handleRendezvous(now clock.Timestamp, hs *packet.CIFHandshake, _ uint32) {
	d := c.rdv

	if d.peerSocketID == 0 && hs.SRTSocketID != 0 {
		d.peerSocketID = hs.SRTSocketID
		d.peerISN = hs.InitialPacketSequenceNumber
		d.peerFC = hs.MaxFlowWindowSize
	}

	// Resolve the role once both cookies are known.
	if d.side == rdvDraw && hs.SynCookie != 0 {
		d.side = rdvCookieContest(d.cookie, hs.SynCookie)
		if d.side == rdvDraw {
			c.fail(RejectError{Code: rejRdvCookie})
			return
		}
	}

	hasExtFlags := hs.HandshakeType == packet.HandshakeTypeConclusion && hs.ExtensionField != 0
	if hasExtFlags && hs.HasHS && hs.SRTHS != nil && !d.negotiated {
		d.negRecv, d.negSend = handshake.NegotiateLatency(
			d.recvLatMS, d.sendLatMS, hs.SRTHS.RecvTSBPDDelay, hs.SRTHS.SendTSBPDDelay)
		d.negotiated = true
	}
	// Encryption: the responder adopts the initiator's key material from its KMREQ
	// (overwriting its own generated keys) so both encrypt with the same key. The
	// initiator keeps its own keys and ignores the responder's echoed KMRSP.
	if hasExtFlags && hs.HasKM && hs.SRTKM != nil && d.cryptoCtx != nil &&
		d.side == rdvResponder && !d.kmAdopted {
		if err := d.cryptoCtx.UnmarshalKM(hs.SRTKM, d.passphrase); err != nil {
			c.fail(RejectError{Code: rejBadSecret})
			return
		}
		d.kmKey = hs.SRTKM.KeyBasedEncryption
		d.kmAdopted = true
	}

	trans := rdvSwitchState(d.rstate, hs.HandshakeType, d.side, hasExtFlags)
	if trans.rspType.IsRejection() {
		c.fail(RejectError{Code: uint32(trans.rspType)})
		return
	}
	d.rstate = trans.newState
	d.lastTrans = trans
	d.haveTrans = true

	c.rendezvousEmit(trans)
	if d.rstate == rdvConnected {
		c.rendezvousEstablish(now)
		return
	}
	c.outputs.push(SetTimer{ID: TimerHandshake, Deadline: now.Add(handshakeRetryInterval)})
}

// rendezvousEmit builds and queues the response packet for a transition.
func (c *Conn) rendezvousEmit(trans rdvTransition) {
	d := c.rdv
	switch trans.rspType {
	case packet.HandshakeTypeConclusion:
		isRequest := !trans.needsHSRSP // initiator sends HSREQ, responder HSRSP
		// Encryption: include key material in the extended CONCLUSION. The
		// initiator generates fresh keys (EncryptionEven) in its KMREQ; the
		// responder echoes the keys it adopted in its KMRSP. Both marshal from the
		// shared crypto context.
		var km *packet.CIFKeyMaterial
		keyLen := 0
		if trans.needsExt && d.cryptoCtx != nil {
			slot := d.kmKey
			if slot == 0 {
				slot = packet.EncryptionEven
				if d.side == rdvInitiator {
					d.kmKey = slot
				}
			}
			km = &packet.CIFKeyMaterial{}
			if err := d.cryptoCtx.MarshalKM(km, d.passphrase, slot); err != nil {
				km = nil
			} else if keyLen = d.keyLength; keyLen == 0 {
				keyLen = 16
			}
		}
		p := handshake.BuildRendezvousConclusion(
			d.socketID, d.isn.Value(), d.mss, d.fc, d.peerSocketID, d.cookie,
			isRequest, d.recvLatMS, d.sendLatMS, 0, d.cong, d.filterCfg,
			0, 0, 0, d.streamID, nil, km, trans.needsExt, keyLen)
		c.outputs.push(SendPacket{Packet: p, Owned: true})
	case packet.HandshakeTypeAgreement:
		p := handshake.BuildAgreement(d.socketID, d.isn.Value(), d.mss, d.fc, d.peerSocketID, nil)
		c.outputs.push(SendPacket{Packet: p, Owned: true})
	case packet.HandshakeTypeDone:
		// no packet to send
	}
}

// rendezvousRetransmit re-sends the last rendezvous response on the handshake
// timer until the handshake resolves.
func (c *Conn) rendezvousRetransmit(now clock.Timestamp) {
	if c.rdv.haveTrans {
		c.rendezvousEmit(c.rdv.lastTrans)
	} else {
		c.sendWavehand()
	}
	c.outputs.push(SetTimer{ID: TimerHandshake, Deadline: now.Add(handshakeRetryInterval)})
}

// rendezvousEstablish brings the rendezvous connection into the data path.
func (c *Conn) rendezvousEstablish(now clock.Timestamp) {
	d := c.rdv
	c.outputs.push(ClearTimer{ID: TimerHandshake})

	recvLat := d.negRecv
	if recvLat == 0 {
		recvLat = d.recvLatMS
	}
	fc := int(d.fc)
	if d.peerFC > 0 && int(d.peerFC) < fc {
		fc = int(d.peerFC)
	}
	peerID := d.peerSocketID
	activeKey := d.kmKey
	if activeKey == 0 {
		activeKey = packet.EncryptionEven
	}
	c.establish(now, establishParams{
		PeerSocketID:    peerID,
		PayloadSize:     d.payloadSize,
		SendISN:         d.isn,
		RecvISN:         seq.Number(d.peerISN),
		FlowWindow:      fc,
		BufferCapacity:  d.bufferCapacity,
		MaxBW:           d.maxBW,
		Live:            d.live,
		TsbpdDelay:      clock.Microseconds(recvLat) * 1000,
		Message:         d.message,
		PeerIdleTimeout: d.peerIdleTimeout,
		CryptoCtx:       d.cryptoCtx, // nil = unencrypted
		ActiveKey:       activeKey,
		Passphrase:      d.passphrase,
	})
	c.rdv = nil
	c.events.push(Connected{PeerSocketID: peerID})
}
