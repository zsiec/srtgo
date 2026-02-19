package srt

import (
	"encoding/binary"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/handshake"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/tsbpd"
)

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
		kmreq, err := handshake.BuildExtKMREQ(c.peerSocketID, km, c.remoteAddr)
		if err != nil {
			return
		}
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
		c.tsbpdEnabled.Store(true)
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
		c.tlpktdropEnabled.Store(true)
	}

	// Negotiate periodic NAK
	c.peerNakReport = peerFlags&packet.FlagPeriodicNAK != 0

	// Send HSRSP back to peer
	respFlags := uint32(packet.FlagCrypt | packet.FlagRexmit)
	if c.tsbpdEnabled.Load() {
		respFlags |= packet.FlagTSBPDRecv
	}
	if c.tlpktdropEnabled.Load() {
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
