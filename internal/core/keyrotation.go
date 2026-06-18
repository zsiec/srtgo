package core

import (
	"encoding/binary"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/packet"
)

// Mid-stream key rotation (SRT KM refresh). An encrypted connection periodically
// rotates its stream encryption key between the two key slots (even/odd) carried
// by the data packet's encryption flag. The sender pre-announces the next key
// over a KMREQ control message (retried until the receiver echoes a KMRSP),
// switches the active slot at the refresh boundary, and decommissions the old
// key a while later. The receiver installs the announced key when it arrives, so
// data encrypted with either slot decrypts seamlessly across the switch.
//
// All randomness lives in the (host-created) crypto context, exactly as for the
// initial SEKs; the core only sequences the rotation and marshals/unmarshals the
// wrapped key material — it reads no clock and spawns nothing.

// KM states (mirror of SRT_KM_STATE).
const (
	kmStateUnsecured = 0
	kmStateSecuring  = 1
	kmStateSecured   = 2
	kmStateNoSecret  = 3
	kmStateBadSecret = 4
)

// srtMaxKMRetry caps KMREQ retransmissions before the sender gives up.
const srtMaxKMRetry = 10

// oppositeKey returns the other encryption key slot.
func oppositeKey(k packet.PacketEncryption) packet.PacketEncryption {
	if k == packet.EncryptionEven {
		return packet.EncryptionOdd
	}
	return packet.EncryptionEven
}

// kmRetryInterval is the spacing between KMREQ retransmissions: 1.5 × RTT, with a
// 100ms floor (matching libsrt's sendKeysToPeer cadence).
func (c *Conn) kmRetryInterval() clock.Microseconds {
	rtt := c.rtt
	if rtt < 100*clock.Millisecond {
		rtt = 100 * clock.Millisecond
	}
	return rtt * 3 / 2
}

// checkKeyRotation advances the rotation state machine once per encrypted send.
func (c *Conn) checkKeyRotation(now clock.Timestamp) {
	c.kmPacketCount++

	// Pre-announce: generate the next-slot key and announce it via KMREQ.
	if !c.kmAnnounced && c.kmPacketCount >= c.kmRefreshRate-c.kmPreAnnounce {
		nextKey := oppositeKey(c.activeKey)
		if err := c.cryptoCtx.GenerateSEK(nextKey); err != nil {
			return
		}
		c.kmAnnounced = true
		c.kmConfirmed = false
		c.kmRetryKey = nextKey
		c.kmRetryCount = srtMaxKMRetry
		c.sndKmState = kmStateSecuring
		c.sendKMREQ(now, nextKey)
		c.outputs.push(SetTimer{ID: TimerKMRefresh, Deadline: now.Add(c.kmRetryInterval())})
	}

	// Refresh: switch the active slot to the (now-announced) next key.
	if c.kmPacketCount >= c.kmRefreshRate {
		c.activeKey = oppositeKey(c.activeKey)
		c.kmPacketCount = 0
		c.kmAnnounced = false
		c.kmDecommission = true
		c.kmSwitchCount = 0
	}

	// Decommission: clear the deprecated key a pre-announce window after the switch.
	if c.kmDecommission {
		c.kmSwitchCount++
		if c.kmSwitchCount >= c.kmPreAnnounce {
			c.cryptoCtx.ClearSEK(oppositeKey(c.activeKey))
			c.kmDecommission = false
		}
	}
}

// retryKMREQ fires on TimerKMRefresh: resend the pending KMREQ until the peer
// confirms it (KMRSP) or the retry budget is exhausted.
func (c *Conn) retryKMREQ(now clock.Timestamp) {
	if !c.kmAnnounced || c.kmConfirmed || c.kmRetryCount <= 0 {
		return // confirmed or given up — let the timer lapse
	}
	c.kmRetryCount--
	c.sendKMREQ(now, c.kmRetryKey)
	if c.kmRetryCount > 0 {
		c.outputs.push(SetTimer{ID: TimerKMRefresh, Deadline: now.Add(c.kmRetryInterval())})
	}
}

// sendKMREQ emits a KMREQ control message announcing the wrapped key for the slot.
func (c *Conn) sendKMREQ(now clock.Timestamp, key packet.PacketEncryption) {
	if c.cryptoCtx == nil || c.passphrase == "" {
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
	p := packet.NewControl(nil, packet.CtrlTypeUser, c.peerSocketID, c.wireTS(now))
	p.Header.SubType = packet.ExtTypeKMReq
	p.SetData(data)
	c.outputs.push(SendPacket{Packet: p, Owned: true})
	c.sentKM++
}

// handleKMRequest installs a peer-announced rotation key and echoes a KMRSP so
// the sender knows the new key is in place. A bad/unconfigured secret is reported
// back as an error KMRSP (a single state word) rather than a key echo.
func (c *Conn) handleKMRequest(now clock.Timestamp, p packet.Packet) {
	c.recvKM++
	if c.cryptoCtx == nil || c.passphrase == "" {
		c.rcvKmState = kmStateNoSecret
		return
	}
	var km packet.CIFKeyMaterial
	if err := km.UnmarshalCIF(p.Data); err != nil {
		c.rcvKmState = kmStateBadSecret
		return
	}
	if err := c.cryptoCtx.UnmarshalKM(&km, c.passphrase); err != nil {
		c.rcvKmState = kmStateBadSecret
		c.sndKmState = kmStateBadSecret
		c.sendKMError(now, kmStateBadSecret)
		return
	}
	c.rcvKmState = kmStateSecured

	// Echo the key material back as the KMRSP confirmation.
	resp := &packet.CIFKeyMaterial{}
	if err := c.cryptoCtx.MarshalKM(resp, c.passphrase, km.KeyBasedEncryption); err != nil {
		return
	}
	data, err := resp.MarshalCIF()
	if err != nil {
		return
	}
	rp := packet.NewControl(nil, packet.CtrlTypeUser, c.peerSocketID, c.wireTS(now))
	rp.Header.SubType = packet.ExtTypeKMRsp
	rp.SetData(data)
	c.outputs.push(SendPacket{Packet: rp, Owned: true})
	c.sentKM++
}

// sendKMError emits a short (single state word) KMRSP rejecting a KMREQ.
func (c *Conn) sendKMError(now clock.Timestamp, state int32) {
	rp := packet.NewControl(nil, packet.CtrlTypeUser, c.peerSocketID, c.wireTS(now))
	rp.Header.SubType = packet.ExtTypeKMRsp
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(state))
	rp.SetData(b[:])
	c.outputs.push(SendPacket{Packet: rp, Owned: true})
	c.sentKM++
}

// handleKMResponse processes a KMRSP. A 4-byte body is an error state; anything
// else confirms the rotation, so the sender stops retransmitting the KMREQ.
func (c *Conn) handleKMResponse(p packet.Packet) {
	c.recvKM++
	if len(p.Data) == 4 {
		state := int32(binary.BigEndian.Uint32(p.Data))
		if state >= kmStateNoSecret && state <= kmStateBadSecret {
			c.sndKmState = state
			c.rcvKmState = state
		}
		return
	}
	c.kmConfirmed = true
	c.sndKmState = kmStateSecured
	c.rcvKmState = kmStateSecured
	c.outputs.push(ClearTimer{ID: TimerKMRefresh})
}
