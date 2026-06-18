package core

import (
	"fmt"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/handshake"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
)

// Legacy HSv4 caller fallback. HSv4 (the UDT-style handshake) carries no SRT
// extensions in the CONCLUSION; the connection comes up as a plain reliable
// datagram link and the SRT features (TSBPD latency, etc.) are negotiated after
// connect via UMSG_EXT HSREQ/HSRSP. The caller is the initiator: it sends the
// v4 CONCLUSION, establishes on the response, then advertises its parameters
// with an HSREQ. Encryption is supported post-handshake: the caller establishes
// encrypted, shares its key in a retransmitted KMREQ, and holds Connected until
// the peer's KMRSP confirms it (so no plaintext leaks); the receiver awaits the
// KMREQ with decryption gated until the keys install. See initHSv4KM.

// sendConclusionV4 emits the HSv4 (UDT_DGRAM) CONCLUSION and arms the retransmit
// timer. It echoes the listener's cookie from the induction response.
func (c *Conn) sendConclusionV4(now clock.Timestamp) {
	d := c.dial
	p := handshake.BuildConclusionV4(d.socketID, d.isn.Value(), d.mss, d.fc, d.cookie, nil)
	c.outputs.push(SendPacket{Packet: p, Owned: true})
	c.outputs.push(SetTimer{ID: TimerHandshake, Deadline: now.Add(handshakeRetryInterval)})
}

// handleConclusionResponseV4 completes the HSv4 handshake: it validates the
// response, establishes the data path as a reliable datagram link (no TSBPD in
// the handshake), and advertises the caller's SRT parameters via an HSREQ.
func (c *Conn) handleConclusionResponseV4(now clock.Timestamp, hs *packet.CIFHandshake) {
	if hs.HandshakeType != packet.HandshakeTypeConclusion {
		return // duplicate induction response; keep waiting
	}
	if hs.InitialPacketSequenceNumber > uint32(seq.Max) {
		c.fail(fmt.Errorf("core: peer ISN %d out of range (v4)", hs.InitialPacketSequenceNumber))
		return
	}
	if hs.MaxFlowWindowSize < 2 {
		c.fail(fmt.Errorf("core: peer flow window %d too small (v4)", hs.MaxFlowWindowSize))
		return
	}

	d := c.dial
	fc := int(d.fc)
	if int(hs.MaxFlowWindowSize) < fc {
		fc = int(hs.MaxFlowWindowSize)
	}
	peerID := hs.SRTSocketID

	encrypted := d.cryptoCtx != nil

	c.outputs.push(ClearTimer{ID: TimerHandshake})
	c.establish(now, establishParams{
		PeerSocketID:     peerID,
		PayloadSize:      d.payloadSize,
		SendISN:          d.isn,
		RecvISN:          seq.Number(hs.InitialPacketSequenceNumber),
		FlowWindow:       fc,
		BufferCapacity:   d.bufferCapacity,
		MaxBW:            d.maxBW,
		Live:             false, // HSv4: no TSBPD until the post-handshake HSREQ
		Message:          true,  // UDT_DGRAM message framing
		DisableNAKReport: d.disableNAKReport,
		PeerNakReport:    true, // HSv4 CONCLUSION carries no SRT flags; assume yes (EXP covers us)
		PeerIdleTimeout:  d.peerIdleTimeout,
		CryptoCtx:        d.cryptoCtx, // nil => unencrypted (the common HSv4 case)
		ActiveKey:        packet.EncryptionEven,
		Passphrase:       d.passphrase,
	})

	// Initiator (sender): advertise our SRT version/flags/latency so the peer can
	// enable TSBPD on its receive side and reply with an HSRSP.
	hsreq := handshake.BuildExtHSREQ(peerID, handshake.SRTVersion, 0, d.recvLatMS, nil)
	c.outputs.push(SendPacket{Packet: hsreq, Owned: true})

	c.dial = nil
	if encrypted {
		// Encrypted HSv4: share our key material via a (retransmitted) KMREQ and
		// hold Connected until the peer confirms it with a KMRSP, so no plaintext
		// data leaks before encryption is in place on both ends.
		c.hsv4DeferConnect = true
		c.initHSv4KM(now)
		return
	}
	c.events.push(Connected{PeerSocketID: peerID})
}

// initHSv4KM starts the encrypted-HSv4 key exchange from the caller (sender):
// it announces the active-slot key in a KMREQ and arms the retransmit timer,
// reusing the key-rotation machinery. The connection stays un-Connected until the
// peer's KMRSP confirms the key (handleKMResponse).
func (c *Conn) initHSv4KM(now clock.Timestamp) {
	c.kmAnnounced = true
	c.kmConfirmed = false
	c.kmRetryKey = c.activeKey
	c.kmRetryCount = srtMaxKMRetry
	c.sndKmState = kmStateSecuring
	c.sendKMREQ(now, c.activeKey)
	c.outputs.push(SetTimer{ID: TimerKMRefresh, Deadline: now.Add(c.kmRetryInterval())})
}

// handleHSv4HSREQ is the responder (listener/receiver) side of the post-handshake
// SRT extension exchange: it records the initiator's advertised latency and
// replies with an HSRSP carrying our SRT version. Informational in this
// implementation — HSv4 runs as a reliable message link without TSBPD.
func (c *Conn) handleHSv4HSREQ(p packet.Packet) {
	_, _, latency, err := handshake.ParseExtHSREQ(p.Data)
	if err != nil {
		return
	}
	if latency > 0 {
		c.negotiatedLatency = clock.Microseconds(latency) * clock.Millisecond
	}
	rsp := handshake.BuildExtHSRSP(c.peerSocketID, handshake.SRTVersion, 0, latency, nil)
	c.outputs.push(SendPacket{Packet: rsp, Owned: true})
}

// handleHSv4HSRSP records the peer's negotiated latency from the post-handshake
// HSRSP. For a sender it is informational (surfaced in Stats.NegotiatedLatency).
func (c *Conn) handleHSv4HSRSP(p packet.Packet) {
	_, _, latency, err := handshake.ParseExtHSREQ(p.Data)
	if err != nil {
		return
	}
	if latency > 0 {
		c.negotiatedLatency = clock.Microseconds(latency) * clock.Millisecond
	}
}
