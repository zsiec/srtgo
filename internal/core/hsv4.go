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
// with an HSREQ. Encrypted HSv4 (post-handshake KMREQ/KMRSP) is not implemented.

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

	c.outputs.push(ClearTimer{ID: TimerHandshake})
	c.establish(now, establishParams{
		PeerSocketID:    peerID,
		PayloadSize:     d.payloadSize,
		SendISN:         d.isn,
		RecvISN:         seq.Number(hs.InitialPacketSequenceNumber),
		FlowWindow:      fc,
		BufferCapacity:  d.bufferCapacity,
		MaxBW:           d.maxBW,
		Live:            false, // HSv4: no TSBPD until the post-handshake HSREQ
		Message:         true,  // UDT_DGRAM message framing
		PeerIdleTimeout: d.peerIdleTimeout,
	})

	// Initiator (sender): advertise our SRT version/flags/latency so the peer can
	// enable TSBPD on its receive side and reply with an HSRSP.
	hsreq := handshake.BuildExtHSREQ(peerID, handshake.SRTVersion, 0, d.recvLatMS, nil)
	c.outputs.push(SendPacket{Packet: hsreq, Owned: true})

	c.dial = nil
	c.events.push(Connected{PeerSocketID: peerID})
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
