package srt

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/handshake"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
)

// rdvState represents the rendezvous handshake state machine states.
type rdvState int

const (
	rdvWaving    rdvState = iota // Initial: no contact from peer
	rdvAttention                 // Received peer's WAVEAHAND
	rdvFine                      // Received peer's CONCLUSION while in WAVING
	rdvInitiated                 // RESPONDER received CONCLUSION+HSREQ in ATTENTION
	rdvConnected                 // Final connected state
)

func (s rdvState) String() string {
	switch s {
	case rdvWaving:
		return "WAVING"
	case rdvAttention:
		return "ATTENTION"
	case rdvFine:
		return "FINE"
	case rdvInitiated:
		return "INITIATED"
	case rdvConnected:
		return "CONNECTED"
	default:
		return "INVALID"
	}
}

// rdvSide represents the role assigned by the cookie contest.
type rdvSide int

const (
	rdvDraw      rdvSide = iota // Unresolved (cookie collision)
	rdvInitiator                // Larger cookie → sends HSREQ first
	rdvResponder                // Smaller cookie → sends HSRSP in response
)

// rdvTransition is the result of a state machine transition.
type rdvTransition struct {
	newState   rdvState
	rspType    packet.HandshakeType
	needsExt   bool // attach extensions to the response
	needsHSRSP bool // true=HSRSP, false=HSREQ (only relevant when needsExt=true)
}

// rdvCookieContest determines INITIATOR/RESPONDER by comparing cookies.
// rdvCookieContest determines INITIATOR/RESPONDER by comparing cookies
// using backward-compatible contest logic.
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

// rdvSwitchState implements the rendezvous state machine transition function.
// It is a pure function: given the current state, received packet type,
// role (side), and whether the received CONCLUSION had extension flags,
// it returns the transition result.
func rdvSwitchState(state rdvState, recvType packet.HandshakeType, side rdvSide, hasExtFlags bool) rdvTransition {
	t := rdvTransition{}

	switch state {
	case rdvWaving:
		switch recvType {
		case packet.HandshakeTypeWavehand:
			t.newState = rdvAttention
			t.rspType = packet.HandshakeTypeConclusion
			if side == rdvInitiator {
				t.needsExt = true
			}
			return t

		case packet.HandshakeTypeConclusion:
			t.newState = rdvFine
			t.rspType = packet.HandshakeTypeConclusion
			t.needsExt = true
			if side == rdvResponder {
				t.needsHSRSP = true
			}
			return t
		}

	case rdvAttention:
		switch recvType {
		case packet.HandshakeTypeWavehand:
			// Peer missed our CONCLUSION, resend
			t.newState = rdvAttention
			t.rspType = packet.HandshakeTypeConclusion
			if side == rdvInitiator {
				t.needsExt = true
			}
			return t

		case packet.HandshakeTypeConclusion:
			if side == rdvInitiator {
				if !hasExtFlags {
					// Empty CONCLUSION — peer hasn't sent HSRSP yet, keep waiting
					t.newState = rdvAttention
					t.rspType = packet.HandshakeTypeConclusion
					t.needsExt = true
					return t
				}
				// CONCLUSION+HSRSP — we're done
				t.newState = rdvConnected
				t.rspType = packet.HandshakeTypeAgreement
				return t
			}
			if side == rdvResponder {
				if !hasExtFlags {
					// Empty CONCLUSION — peer hasn't sent HSREQ yet, keep waiting
					t.newState = rdvAttention
					t.rspType = packet.HandshakeTypeConclusion
					return t
				}
				// CONCLUSION+HSREQ — respond with HSRSP
				t.newState = rdvInitiated
				t.rspType = packet.HandshakeTypeConclusion
				t.needsExt = true
				t.needsHSRSP = true
				return t
			}
			// DRAW — should not reach here (cookie contest already resolved)
			t.newState = rdvWaving
			t.rspType = packet.HandshakeType(RejRdvCookie)
			return t

		case packet.HandshakeTypeAgreement:
			if side == rdvInitiator {
				// Peer already sent AGREEMENT — we're connected
				t.newState = rdvConnected
				t.rspType = packet.HandshakeTypeDone
				return t
			}
			// RESPONDER got AGREEMENT but hasn't completed exchange — resend CONCLUSION+HSRSP
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
				// CONCLUSION+HSRSP — we're done
				t.newState = rdvConnected
				t.rspType = packet.HandshakeTypeAgreement
				return t
			}
			// Repeated CONCLUSION or RESPONDER awaiting AGREEMENT — resend our CONCLUSION
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
			// Peer missed our CONCLUSION+HSRSP, resend
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

	// Invalid transition — reject
	t.newState = rdvWaving
	t.rspType = packet.HandshakeType(RejRogue)
	return t
}

// DialRendezvous connects to a peer using rendezvous mode.
// Both peers call DialRendezvous with the other's address.
// localAddr is the address to bind to; remoteAddr is the peer's address.
func DialRendezvous(localAddr, remoteAddr string, cfg Config) (*Conn, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	localUDP, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("srt: resolve local address: %w", err)
	}

	remoteUDP, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("srt: resolve remote address: %w", err)
	}

	conn, err := listenUDP("udp", localUDP, cfg)
	if err != nil {
		return nil, fmt.Errorf("srt: bind UDP: %w", err)
	}

	return dialRendezvous(conn, remoteUDP, cfg, nil)
}

// dialRendezvous performs the rendezvous handshake over an existing PacketConn.
func dialRendezvous(conn net.PacketConn, remoteAddr net.Addr, cfg Config, clk clock.Clock) (*Conn, error) {
	if clk == nil {
		clk = clock.NewRealClock()
	}

	m := mux.New(conn, cfg.MSS)

	socketID, err := handshake.GenerateSocketID()
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("srt: generate socket ID: %w", err)
	}

	isn, err := handshake.GenerateISN()
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("srt: generate ISN: %w", err)
	}

	cookie, err := handshake.GenerateRandomCookie()
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("srt: generate cookie: %w", err)
	}

	recvCh := m.Register(socketID)

	deadline := time.NewTimer(cfg.ConnTimeout)
	defer deadline.Stop()

	// Build initial WAVEHAND
	keyLength := cfg.KeyLength
	if keyLength == 0 && cfg.Passphrase != "" {
		keyLength = 16 // AES-128 default
	}
	wavehand := handshake.BuildWavehand(socketID, isn, uint32(cfg.MSS), uint32(cfg.FC), cookie, keyLength, remoteAddr)

	// Send initial WAVEHAND
	if err := m.Send(wavehand); err != nil {
		wavehand.Release()
		m.Close()
		return nil, fmt.Errorf("srt: send wavehand: %w", err)
	}
	wavehand.Release()

	retry := time.NewTicker(handshakeRetryInterval)
	defer retry.Stop()

	state := rdvWaving
	side := rdvDraw

	var peerSocketID, peerISN, peerMSS, peerFC uint32
	var peerSRTVersion uint32
	var peerNakReport bool
	var peerStartTime uint32 // peer's timestamp for TSBPD timebase

	// Crypto state
	var cryptoCtx *crypto.Context
	var km *packet.CIFKeyMaterial
	activeKey := packet.EncryptionEven
	var peerKM *packet.CIFKeyMaterial

	// Negotiated parameters — set once we have peer's HS data
	var negotiatedRecv, negotiatedSend uint16
	var negotiated bool

	// Current outgoing packet builder (for retransmission)
	var lastRspBuilder func() packet.Packet

	// Default: retransmit WAVEHAND
	lastRspBuilder = func() packet.Packet {
		return handshake.BuildWavehand(socketID, isn, uint32(cfg.MSS), uint32(cfg.FC), cookie, keyLength, remoteAddr)
	}

	// processPacket handles a received handshake packet and returns
	// the connection when the state machine reaches CONNECTED.
	processPacket := func(p packet.Packet) (*Conn, error) {
		// During handshake, non-handshake packets may arrive. In rendezvous
		// mode, a SHUTDOWN means reject; other non-handshake packets are
		// silently ignored.
		if !p.Header.IsControl || p.Header.ControlType != packet.CtrlTypeHandshake {
			if p.Header.IsControl && p.Header.ControlType == packet.CtrlTypeShutdown {
				p.Release()
				m.Close()
				return nil, errors.New("srt: peer sent shutdown during handshake")
			}
			p.Release()
			return nil, nil // ignore non-handshake packets
		}

		var hs packet.CIFHandshake
		if err := p.UnmarshalCIF(&hs); err != nil {
			p.Release()
			return nil, nil // ignore malformed packets
		}

		if hs.HandshakeType.IsRejection() {
			p.Release()
			m.Close()
			return nil, fmt.Errorf("srt: connection rejected (code %d)", uint32(hs.HandshakeType))
		}

		// Extract peer info on first valid handshake
		if peerSocketID == 0 && hs.SRTSocketID != 0 {
			peerSocketID = hs.SRTSocketID
			peerISN = hs.InitialPacketSequenceNumber
			peerMSS = hs.MaxTransmissionUnitSize
			peerFC = hs.MaxFlowWindowSize
		}

		// Adopt peer's PBKEYLEN if we have a passphrase but no explicit key length configured.
		// EncryptionField encodes PBKEYLEN as keyLen>>3 (2=128, 3=192, 4=256).
		if hs.EncryptionField >= 2 && hs.EncryptionField <= 4 && keyLength == 0 && cfg.Passphrase != "" {
			keyLength = int(hs.EncryptionField) << 3 // 2->16, 3->24, 4->32
		}

		// Run cookie contest once
		if side == rdvDraw && hs.SynCookie != 0 {
			side = rdvCookieContest(cookie, hs.SynCookie)
			if side == rdvDraw {
				p.Release()
				m.Close()
				return nil, errors.New("srt: rendezvous cookie collision (try again)")
			}
		}

		// Determine if received CONCLUSION has extension flags
		hasExtFlags := hs.HandshakeType == packet.HandshakeTypeConclusion && hs.ExtensionField != 0

		// Process HSREQ/HSRSP from peer's CONCLUSION
		if hs.HandshakeType == packet.HandshakeTypeConclusion && hasExtFlags {
			if hs.HasHS && hs.SRTHS != nil {
				peerSRTVersion = hs.SRTHS.SRTVersion
				peerNakReport = hs.SRTHS.SRTFlags&packet.FlagPeriodicNAK != 0

				if cfg.MinVersion > 0 && hs.SRTHS.SRTVersion < cfg.MinVersion {
					p.Release()
					m.Close()
					return nil, fmt.Errorf("srt: peer SRT version 0x%06X below MinVersion 0x%06X",
						hs.SRTHS.SRTVersion, cfg.MinVersion)
				}

				// HSv5 extensions require SRT version >= 1.3.0.
				if hs.SRTHS.SRTVersion < 0x010300 {
					p.Release()
					m.Close()
					return nil, fmt.Errorf("srt: HSv5 peer reported SRT version 0x%06X < 1.3.0 (rogue)", hs.SRTHS.SRTVersion)
				}

				if !negotiated {
					// Negotiate latencies (same as caller-listener)
					negotiatedRecv, negotiatedSend = handshake.NegotiateLatency(
						cfg.recvLatencyMS(), cfg.peerLatencyMS(),
						hs.SRTHS.RecvTSBPDDelay, hs.SRTHS.SendTSBPDDelay,
					)
					negotiated = true
				}
			}

			// Handle peer's KMREQ (we are RESPONDER)
			if hs.HasKM && hs.SRTKM != nil && hs.IsRequest && cryptoCtx == nil {
				peerKM = hs.SRTKM
				if cfg.Passphrase != "" {
					kl := cfg.KeyLength
					if kl == 0 {
						kl = 16
					}
					ctx, err := crypto.New(kl)
					if err != nil {
						p.Release()
						m.Close()
						return nil, fmt.Errorf("srt: create crypto context: %w", err)
					}
					if err := ctx.UnmarshalKM(peerKM, cfg.Passphrase); err != nil {
						p.Release()
						m.Close()
						return nil, fmt.Errorf("srt: decrypt key material: %w", err)
					}
					cryptoCtx = ctx
					activeKey = peerKM.KeyBasedEncryption

					// Build KMRSP
					km = &packet.CIFKeyMaterial{}
					if err := cryptoCtx.MarshalKM(km, cfg.Passphrase, activeKey); err != nil {
						p.Release()
						m.Close()
						return nil, fmt.Errorf("srt: marshal KMRSP: %w", err)
					}
				}
			}

			// Handle peer's KMRSP (we are INITIATOR)
			if hs.HasKM && hs.SRTKM != nil && !hs.IsRequest {
				// Peer acknowledged our encryption — nothing to extract,
				// we already have the crypto context.
			}
		}

		// Capture peer timestamp for TSBPD timebase before releasing
		peerStartTime = p.Header.Timestamp

		// Run state machine
		trans := rdvSwitchState(state, hs.HandshakeType, side, hasExtFlags)
		p.Release()

		if trans.rspType.IsRejection() {
			m.Close()
			return nil, fmt.Errorf("srt: rendezvous handshake failed (state=%s, code=%d)", state, uint32(trans.rspType))
		}

		state = trans.newState

		// Build response packet
		switch trans.rspType {
		case packet.HandshakeTypeConclusion:
			// Prepare INITIATOR crypto on first CONCLUSION with extensions
			if trans.needsExt && !trans.needsHSRSP && cryptoCtx == nil && cfg.Passphrase != "" {
				kl := cfg.KeyLength
				if kl == 0 {
					kl = 16
				}
				cipherMode := crypto.CipherCTR
				if cfg.CryptoMode == 2 {
					cipherMode = crypto.CipherGCM
				}
				ctx, err := crypto.NewWithMode(kl, cipherMode)
				if err != nil {
					m.Close()
					return nil, fmt.Errorf("srt: create crypto context: %w", err)
				}
				cryptoCtx = ctx
				km = &packet.CIFKeyMaterial{}
				if err := cryptoCtx.MarshalKM(km, cfg.Passphrase, activeKey); err != nil {
					m.Close()
					return nil, fmt.Errorf("srt: marshal KMREQ: %w", err)
				}
			}

			var conclusionKM *packet.CIFKeyMaterial
			if trans.needsExt {
				conclusionKM = km
			}

			var rLatency, sLatency uint16
			if trans.needsHSRSP && negotiated {
				rLatency = negotiatedRecv
				sLatency = negotiatedSend
			} else {
				rLatency = cfg.recvLatencyMS()
				sLatency = cfg.peerLatencyMS()
			}

			builder := func() packet.Packet {
				return handshake.BuildRendezvousConclusion(
					socketID, isn,
					uint32(cfg.MSS), uint32(cfg.FC),
					peerSocketID, cookie,
					!trans.needsHSRSP, // isRequest=true for HSREQ (INITIATOR)
					rLatency, sLatency,
					cfg.srtFlags(),
					cfg.congestionString(),
					cfg.PacketFilter,
					0, 0, 0, // group params (not used for rendezvous yet)
					cfg.StreamID,
					remoteAddr,
					conclusionKM,
					trans.needsExt,
					keyLength,
				)
			}
			lastRspBuilder = builder

			rsp := builder()
			m.Send(rsp)
			rsp.Release()

		case packet.HandshakeTypeAgreement:
			builder := func() packet.Packet {
				return handshake.BuildAgreement(socketID, isn, uint32(cfg.MSS), uint32(cfg.FC), peerSocketID, remoteAddr)
			}
			lastRspBuilder = builder

			rsp := builder()
			m.Send(rsp)
			rsp.Release()

		case packet.HandshakeTypeDone:
			// No response needed
		}

		// Check if connected
		if state == rdvConnected {
			// Use negotiated values if available, fall back to config
			if !negotiated {
				negotiatedRecv = cfg.latencyMS()
				negotiatedSend = cfg.latencyMS()
			}

			negotiatedMSS := handshake.NegotiateMSS(uint32(cfg.MSS), peerMSS)
			negotiatedFC := int(peerFC)
			if cfg.FC < negotiatedFC {
				negotiatedFC = cfg.FC
			}
			payloadSize := int(negotiatedMSS) - 44
			if cfg.PayloadSize > 0 && cfg.PayloadSize < payloadSize {
				payloadSize = cfg.PayloadSize
			}

			tsbpdDelay := time.Duration(negotiatedRecv) * time.Millisecond

			c := newConn(ConnConfig{
				LocalAddr:           m.LocalAddr(),
				RemoteAddr:          remoteAddr,
				SocketID:            socketID,
				PeerSocketID:        peerSocketID,
				StreamID:            cfg.StreamID,
				IsServer:            false,
				Mux:                 m,
				OwnsMux:             true,
				RecvChan:            recvCh,
				Clock:               clk,
				SendISN:             seq.Number(isn),
				RecvISN:             seq.Number(peerISN),
				SendBufSize:         cfg.SendBufSize,
				RecvBufSize:         cfg.RecvBufSize,
				MaxBW:               cfg.MaxBW,
				TsbpdDelay:          tsbpdDelay,
				FC:                  negotiatedFC,
				PayloadSize:         payloadSize,
				CryptoCtx:           cryptoCtx,
				ActiveKey:           activeKey,
				Linger:              cfg.Linger,
				PeerIdleTimeout:     cfg.PeerIdleTimeout,
				Passphrase:          cfg.Passphrase,
				KMRefreshRate:       cfg.KMRefreshRate,
				KMPreAnnounce:       cfg.KMPreAnnounce,
				MessageAPI:          cfg.messageAPIEnabled(),
				Congestion:          cfg.Congestion,
				NAKReport:           cfg.NAKReport == nil || *cfg.NAKReport,
				PeerNakReport:       peerNakReport,
				RetransmitAlgo:      cfg.retransmitAlgo(),
				LossMaxTTL:          cfg.LossMaxTTL,
				SndDropDelay:        cfg.SndDropDelay,
				InputBW:             cfg.InputBW,
				MinInputBW:          cfg.MinInputBW,
				OverheadBW:          cfg.OverheadBW,
				DriftTracer:         cfg.driftTracerEnabled(),
				PeerSRTVersion:      peerSRTVersion,
				PeerStartTime:       peerStartTime, // peer's timestamp for TSBPD timebase
				PacketFilter:        cfg.PacketFilter,
				SndSyn:              cfg.sndSynEnabled(),
				RcvSyn:              cfg.rcvSynEnabled(),
				MaxRexmitBW:         cfg.MaxRexmitBW,
				MinVersion:          cfg.MinVersion,
				EnforcedEncryption:  cfg.EnforcedEncryption == nil || *cfg.EnforcedEncryption,
				GroupConnectEnabled: cfg.GroupConnect,
				Logger:              cfg.Logger,
			})

			return c, nil
		}

		return nil, nil
	}

	for {
		select {
		case p := <-m.Handshake:
			// Packets with dest=0 (WAVEHAND from peer before they know our socketID)
			c, err := processPacket(p)
			if err != nil {
				return nil, err
			}
			if c != nil {
				return c, nil
			}

		case p := <-recvCh:
			// Packets addressed to our socketID (CONCLUSION/AGREEMENT from peer)
			c, err := processPacket(p)
			if err != nil {
				return nil, err
			}
			if c != nil {
				return c, nil
			}

		case <-retry.C:
			// Retransmit current packet
			if lastRspBuilder != nil {
				rsp := lastRspBuilder()
				m.Send(rsp)
				rsp.Release()
			}

		case <-deadline.C:
			m.Close()
			return nil, errors.New("srt: rendezvous handshake timeout")
		}
	}
}
