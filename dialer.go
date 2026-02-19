package srt

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/filter"
	"github.com/zsiec/srtgo/internal/handshake"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
)

// handshakeRetryInterval is the period between handshake retransmissions.
// UDP packets can be dropped by the OS, so the caller retransmits until
// a response arrives or the overall connection timeout expires.
const handshakeRetryInterval = 250 * time.Millisecond

// Dial connects to an SRT listener at the given address.
//
// The handshake follows a 4-step process:
//  1. Caller sends INDUCTION (v4, no cookie)
//  2. Listener responds with INDUCTION response (v5, SYN cookie, SRT magic)
//  3. Caller sends CONCLUSION (v5, echoed cookie, extensions)
//  4. Listener responds with CONCLUSION response (v5, negotiated parameters)
//
// Each handshake step retransmits periodically until a response is received
// or the connection timeout expires.
func Dial(addr string, cfg Config) (*Conn, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("srt: resolve address: %w", err)
	}

	// Bind to any local port
	localAddr, _ := net.ResolveUDPAddr("udp", ":0")
	conn, err := listenUDP("udp", localAddr, cfg)
	if err != nil {
		return nil, fmt.Errorf("srt: bind UDP: %w", err)
	}

	return dial(conn, udpAddr, cfg, nil)
}

// dial performs the 4-step handshake over an existing PacketConn.
func dial(conn net.PacketConn, remoteAddr net.Addr, cfg Config, clk clock.Clock) (*Conn, error) {
	if clk == nil {
		clk = clock.NewRealClock()
	}

	m := mux.New(conn, cfg.MSS)

	callerSocketID, err := handshake.GenerateSocketID()
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("srt: generate socket ID: %w", err)
	}

	callerISN, err := handshake.GenerateISN()
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("srt: generate ISN: %w", err)
	}

	// Register with mux before sending anything so we can receive responses.
	// The listener's INDUCTION response uses destID=callerSocketID.
	recvCh := m.Register(callerSocketID)

	deadline := time.NewTimer(cfg.ConnTimeout)
	defer deadline.Stop()

	// Step 1+2: Send INDUCTION, wait for response (with retransmission)
	indResult, err := dialInduction(m, recvCh, deadline.C, callerSocketID, callerISN, cfg, remoteAddr)
	if err != nil {
		m.Close()
		return nil, err
	}

	if indResult.isHSv4 {
		// HSv4 peer: send v4 CONCLUSION, then do post-handshake extension exchange
		return dialConclusionV4(m, recvCh, deadline.C, callerSocketID, callerISN, cfg,
			indResult.cookie, indResult.listenerMSS, indResult.listenerFC, remoteAddr, clk)
	}

	// Step 3+4: Send CONCLUSION, wait for response (with retransmission)
	return dialConclusion(m, recvCh, deadline.C, callerSocketID, callerISN, cfg,
		indResult.cookie, indResult.listenerMSS, indResult.listenerFC, remoteAddr, clk)
}

// inductionResult holds the outcome of dialInduction.
type inductionResult struct {
	cookie      uint32
	listenerMSS uint32
	listenerFC  uint32
	isHSv4      bool // true if peer responded with HSv4 (no SRT magic)
}

// dialInduction sends INDUCTION and waits for the response, retransmitting periodically.
func dialInduction(
	m *mux.Mux, recvCh <-chan packet.Packet, timeout <-chan time.Time,
	callerSocketID, callerISN uint32, cfg Config, remoteAddr net.Addr,
) (*inductionResult, error) {
	sendInduction := func() error {
		indPkt := handshake.BuildInduction(callerSocketID, callerISN, uint32(cfg.MSS), uint32(cfg.FC), remoteAddr)
		sendErr := m.Send(indPkt)
		indPkt.Release()
		return sendErr
	}

	// Initial send
	if err := sendInduction(); err != nil {
		return nil, fmt.Errorf("srt: send induction: %w", err)
	}

	retry := time.NewTicker(handshakeRetryInterval)
	defer retry.Stop()

	for {
		select {
		case resp := <-recvCh:
			// During handshake, non-handshake packets may arrive. Handle gracefully:
			// - SHUTDOWN: reject the connection
			// - Other non-handshake packets: ignore and keep waiting
			if !resp.Header.IsControl || resp.Header.ControlType != packet.CtrlTypeHandshake {
				if resp.Header.IsControl && resp.Header.ControlType == packet.CtrlTypeShutdown {
					resp.Release()
					return nil, errors.New("srt: peer sent shutdown during handshake")
				}
				resp.Release()
				continue
			}

			var hs packet.CIFHandshake
			if err := resp.UnmarshalCIF(&hs); err != nil {
				resp.Release()
				return nil, fmt.Errorf("srt: unmarshal induction response: %w", err)
			}

			if hs.HandshakeType.IsRejection() {
				resp.Release()
				return nil, fmt.Errorf("srt: connection rejected (code %d)", uint32(hs.HandshakeType))
			}

			if hs.HandshakeType != packet.HandshakeTypeInduction {
				resp.Release()
				return nil, fmt.Errorf("srt: unexpected handshake type: %v", hs.HandshakeType)
			}

			result := &inductionResult{
				cookie:      hs.SynCookie,
				listenerMSS: hs.MaxTransmissionUnitSize,
				listenerFC:  hs.MaxFlowWindowSize,
			}

			if hs.ExtensionField != handshake.SRTMagic {
				// Check if this is an HSv4 peer (v4, ExtensionField = UDT_DGRAM marker)
				if hs.Version == 4 && hs.ExtensionField == handshake.UDTV4Marker {
					result.isHSv4 = true
					resp.Release()
					return result, nil
				}
				resp.Release()
				return nil, fmt.Errorf("srt: listener did not return SRT magic (got ExtensionField=%#04x, want %#04x; not an SRT endpoint?)", hs.ExtensionField, handshake.SRTMagic)
			}

			// Read advertised PBKEYLEN from EncryptionField.
			// enc_flags 2=AES-128, 3=AES-192, 4=AES-256. If our KeyLength is 0
			// (not set), adopt the listener's advertised key length.
			if hs.EncryptionField >= 2 && hs.EncryptionField <= 4 && cfg.KeyLength == 0 && cfg.Passphrase != "" {
				cfg.KeyLength = int(hs.EncryptionField) << 3 // 2->16, 3->24, 4->32
			}

			resp.Release()
			return result, nil

		case <-retry.C:
			// Retransmit — UDP packet may have been dropped
			sendInduction()

		case <-timeout:
			return nil, errors.New("srt: handshake timeout (induction)")
		}
	}
}

// dialConclusion sends CONCLUSION and waits for the response, retransmitting periodically.
func dialConclusion(
	m *mux.Mux, recvCh <-chan packet.Packet, timeout <-chan time.Time,
	callerSocketID, callerISN uint32, cfg Config,
	cookie, listenerMSS, listenerFC uint32,
	remoteAddr net.Addr, clk clock.Clock,
) (*Conn, error) {
	// Build encryption key material if passphrase is configured.
	var cryptoCtx *crypto.Context
	var km *packet.CIFKeyMaterial
	activeKey := packet.EncryptionEven

	if cfg.Passphrase != "" {
		keyLen := cfg.KeyLength
		if keyLen == 0 {
			keyLen = 16 // AES-128 default
		}
		var err error
		cipherMode := crypto.CipherCTR
		if cfg.CryptoMode == 2 {
			cipherMode = crypto.CipherGCM
		}
		cryptoCtx, err = crypto.NewWithMode(keyLen, cipherMode)
		if err != nil {
			m.Close()
			return nil, fmt.Errorf("srt: create crypto context: %w", err)
		}
		km = &packet.CIFKeyMaterial{}
		if err := cryptoCtx.MarshalKM(km, cfg.Passphrase, activeKey); err != nil {
			m.Close()
			return nil, fmt.Errorf("srt: marshal key material: %w", err)
		}
	}

	sendConclusion := func() error {
		conclPkt := handshake.BuildConclusion(
			callerSocketID, callerISN,
			uint32(cfg.MSS), uint32(cfg.FC),
			cookie,
			cfg.StreamID,
			cfg.recvLatencyMS(), cfg.peerLatencyMS(),
			cfg.srtFlags(),
			cfg.congestionString(),
			cfg.PacketFilter,
			0, 0, 0, // group params (not used for non-group connections)
			remoteAddr,
			km,
		)
		sendErr := m.Send(conclPkt)
		conclPkt.Release()
		return sendErr
	}

	// Initial send
	if err := sendConclusion(); err != nil {
		m.Close()
		return nil, fmt.Errorf("srt: send conclusion: %w", err)
	}

	retry := time.NewTicker(handshakeRetryInterval)
	defer retry.Stop()

	for {
		select {
		case resp := <-recvCh:
			// During handshake, non-handshake packets may arrive. Handle gracefully:
			// - SHUTDOWN: reject the connection
			// - Other non-handshake packets: ignore and keep waiting
			if !resp.Header.IsControl || resp.Header.ControlType != packet.CtrlTypeHandshake {
				if resp.Header.IsControl && resp.Header.ControlType == packet.CtrlTypeShutdown {
					resp.Release()
					m.Close()
					return nil, errors.New("srt: peer sent shutdown during handshake")
				}
				resp.Release()
				continue
			}

			var hs packet.CIFHandshake
			if err := resp.UnmarshalCIF(&hs); err != nil {
				resp.Release()
				m.Close()
				return nil, fmt.Errorf("srt: unmarshal conclusion response: %w", err)
			}

			if hs.HandshakeType.IsRejection() {
				resp.Release()
				m.Close()
				return nil, fmt.Errorf("srt: connection rejected (code %d)", uint32(hs.HandshakeType))
			}

			if hs.HandshakeType != packet.HandshakeTypeConclusion {
				resp.Release()
				// Could be a duplicate induction response — ignore and keep waiting
				continue
			}

			// Validate ISN range and FC.
			// ISN must be a valid 31-bit sequence number (< 0x7FFFFFFF).
			// FlightFlagSize (FC) must be >= 2.
			if hs.InitialPacketSequenceNumber > uint32(seq.Max) {
				resp.Release()
				m.Close()
				return nil, fmt.Errorf("srt: peer ISN %d out of valid range", hs.InitialPacketSequenceNumber)
			}
			if hs.MaxFlowWindowSize < 2 {
				resp.Release()
				m.Close()
				return nil, fmt.Errorf("srt: peer flow window size %d too small (minimum 2)", hs.MaxFlowWindowSize)
			}

			// Validate peer's SRT version against MinVersion.
			if hs.HasHS && hs.SRTHS != nil && cfg.MinVersion > 0 {
				if hs.SRTHS.SRTVersion < cfg.MinVersion {
					resp.Release()
					m.Close()
					return nil, fmt.Errorf("srt: peer SRT version 0x%06X below MinVersion 0x%06X", hs.SRTHS.SRTVersion, cfg.MinVersion)
				}
			}

			// HSv5 extensions must have SRT version >= 1.3.0.
			// A rogue listener sending HSv5 with a pre-HSv5 version field is rejected.
			if hs.HasHS && hs.SRTHS != nil && hs.SRTHS.SRTVersion < 0x010300 {
				resp.Release()
				m.Close()
				return nil, fmt.Errorf("srt: HSv5 peer reported SRT version 0x%06X < 1.3.0 (rogue)", hs.SRTHS.SRTVersion)
			}

			// Validate encryption: if we sent KMREQ, the listener must respond with KMRSP
			enforcedEncryption := cfg.EnforcedEncryption == nil || *cfg.EnforcedEncryption
			if cryptoCtx != nil && !hs.HasKM {
				if enforcedEncryption {
					resp.Release()
					m.Close()
					return nil, errors.New("srt: listener did not respond with key material (encryption mismatch)")
				}
				// EnforcedEncryption=false: fall back to unencrypted
				cryptoCtx = nil
			}

			// Extract negotiated parameters
			var negotiatedRecv, negotiatedSend uint16
			var peerNakReport bool
			if hs.HasHS && hs.SRTHS != nil {
				negotiatedRecv = hs.SRTHS.RecvTSBPDDelay
				negotiatedSend = hs.SRTHS.SendTSBPDDelay
				peerNakReport = hs.SRTHS.SRTFlags&packet.FlagPeriodicNAK != 0
				// Note: HSRSP does not include FlagStream. The listener
				// validates stream/message mode match and rejects on mismatch,
				// so the caller trusts its local config.
			} else {
				negotiatedRecv = cfg.latencyMS()
				negotiatedSend = cfg.latencyMS()
			}
			peerTsbpdDelay := time.Duration(negotiatedSend) * time.Millisecond

			negotiatedMSS := handshake.NegotiateMSS(uint32(cfg.MSS), listenerMSS)
			negotiatedFC := int(listenerFC)
			if cfg.FC < negotiatedFC {
				negotiatedFC = cfg.FC
			}

			// MSS - 44 bytes (IP 20 + UDP 8 + SRT header 16)
			payloadSize := int(negotiatedMSS) - 44
			if cfg.PayloadSize > 0 && cfg.PayloadSize < payloadSize {
				payloadSize = cfg.PayloadSize
			}

			tsbpdDelay := time.Duration(negotiatedRecv) * time.Millisecond

			resp.Release()

			// Extract peer SRT version for ACK size negotiation
			var peerSRTVersion uint32
			if hs.HasHS && hs.SRTHS != nil {
				peerSRTVersion = hs.SRTHS.SRTVersion
			}

			// FEC filter negotiation: if both sides sent filter config, they must match
			negotiatedFilter := cfg.PacketFilter
			if hs.HasFilter && hs.FilterConfig != "" {
				if cfg.PacketFilter != "" {
					localFEC, _ := filter.ParseConfig(cfg.PacketFilter)
					peerFEC, _ := filter.ParseConfig(hs.FilterConfig)
					if _, err := filter.NegotiateConfig(localFEC, peerFEC); err != nil {
						m.Close()
						return nil, fmt.Errorf("srt: FEC negotiation failed: %w", err)
					}
				}
				negotiatedFilter = hs.FilterConfig
			}

			c := newConn(ConnConfig{
				LocalAddr:           m.LocalAddr(),
				RemoteAddr:          remoteAddr,
				SocketID:            callerSocketID,
				PeerSocketID:        hs.SRTSocketID,
				StreamID:            cfg.StreamID,
				IsServer:            false,
				Mux:                 m,
				OwnsMux:             true,
				RecvChan:            recvCh,
				Clock:               clk,
				SendISN:             seq.Number(callerISN),
				RecvISN:             seq.Number(hs.InitialPacketSequenceNumber),
				SendBufSize:         cfg.SendBufSize,
				RecvBufSize:         cfg.RecvBufSize,
				MaxBW:               cfg.MaxBW,
				TsbpdDelay:          tsbpdDelay,
				PeerTsbpdDelay:      peerTsbpdDelay,
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
				PeerStartTime:       resp.Header.Timestamp, // peer's timestamp for TSBPD timebase
				PacketFilter:        negotiatedFilter,
				PeerGroupID:         hs.GroupID, // store peer's group ID if present
				SndSyn:              cfg.sndSynEnabled(),
				RcvSyn:              cfg.rcvSynEnabled(),
				MaxRexmitBW:         cfg.MaxRexmitBW,
				MinVersion:          cfg.MinVersion,
				EnforcedEncryption:  cfg.EnforcedEncryption == nil || *cfg.EnforcedEncryption,
				GroupConnectEnabled: cfg.GroupConnect,
				Logger:              cfg.Logger,
			})

			return c, nil

		case <-retry.C:
			// Retransmit — UDP packet may have been dropped
			sendConclusion()

		case <-timeout:
			m.Close()
			return nil, errors.New("srt: handshake timeout (conclusion)")
		}
	}
}

// dialConclusionV4 handles the HSv4 CONCLUSION handshake and post-handshake extension exchange.
// HSv4 CONCLUSION has no SRT extensions; HSREQ/KMREQ are sent as UMSG_EXT after connection.
func dialConclusionV4(
	m *mux.Mux, recvCh <-chan packet.Packet, timeout <-chan time.Time,
	callerSocketID, callerISN uint32, cfg Config,
	cookie, listenerMSS, listenerFC uint32,
	remoteAddr net.Addr, clk clock.Clock,
) (*Conn, error) {
	sendConclusion := func() error {
		conclPkt := handshake.BuildConclusionV4(
			callerSocketID, callerISN,
			uint32(cfg.MSS), uint32(cfg.FC),
			cookie, remoteAddr,
		)
		sendErr := m.Send(conclPkt)
		conclPkt.Release()
		return sendErr
	}

	// Initial send
	if err := sendConclusion(); err != nil {
		m.Close()
		return nil, fmt.Errorf("srt: send v4 conclusion: %w", err)
	}

	retry := time.NewTicker(handshakeRetryInterval)
	defer retry.Stop()

	for {
		select {
		case resp := <-recvCh:
			if !resp.Header.IsControl || resp.Header.ControlType != packet.CtrlTypeHandshake {
				if resp.Header.IsControl && resp.Header.ControlType == packet.CtrlTypeShutdown {
					resp.Release()
					m.Close()
					return nil, errors.New("srt: peer sent shutdown during handshake")
				}
				resp.Release()
				continue
			}

			var hs packet.CIFHandshake
			if err := resp.UnmarshalCIF(&hs); err != nil {
				resp.Release()
				m.Close()
				return nil, fmt.Errorf("srt: unmarshal v4 conclusion response: %w", err)
			}

			if hs.HandshakeType.IsRejection() {
				resp.Release()
				m.Close()
				return nil, fmt.Errorf("srt: connection rejected (code %d)", uint32(hs.HandshakeType))
			}

			if hs.HandshakeType != packet.HandshakeTypeConclusion {
				resp.Release()
				continue // ignore non-conclusion (e.g. duplicate induction)
			}

			if hs.InitialPacketSequenceNumber > uint32(seq.Max) {
				resp.Release()
				m.Close()
				return nil, fmt.Errorf("srt: peer ISN %d out of valid range", hs.InitialPacketSequenceNumber)
			}
			if hs.MaxFlowWindowSize < 2 {
				resp.Release()
				m.Close()
				return nil, fmt.Errorf("srt: peer flow window size %d too small (minimum 2)", hs.MaxFlowWindowSize)
			}

			negotiatedMSS := handshake.NegotiateMSS(uint32(cfg.MSS), listenerMSS)
			negotiatedFC := int(listenerFC)
			if cfg.FC < negotiatedFC {
				negotiatedFC = cfg.FC
			}
			payloadSize := int(negotiatedMSS) - 44
			if cfg.PayloadSize > 0 && cfg.PayloadSize < payloadSize {
				payloadSize = cfg.PayloadSize
			}

			resp.Release()

			// HSv4: no TSBPD, no encryption in handshake. Extensions come via UMSG_EXT.
			// Determine if we are the INITIATOR (sender) that sends HSREQ first.
			isInitiator := cfg.Sender != nil && *cfg.Sender

			c := newConn(ConnConfig{
				LocalAddr:           m.LocalAddr(),
				RemoteAddr:          remoteAddr,
				SocketID:            callerSocketID,
				PeerSocketID:        hs.SRTSocketID,
				StreamID:            "",
				IsServer:            false,
				Mux:                 m,
				OwnsMux:             true,
				RecvChan:            recvCh,
				Clock:               clk,
				SendISN:             seq.Number(callerISN),
				RecvISN:             seq.Number(hs.InitialPacketSequenceNumber),
				SendBufSize:         cfg.SendBufSize,
				RecvBufSize:         cfg.RecvBufSize,
				MaxBW:               cfg.MaxBW,
				TsbpdDelay:          0, // not set until HSREQ/HSRSP exchange
				FC:                  negotiatedFC,
				PayloadSize:         payloadSize,
				Linger:              cfg.Linger,
				PeerIdleTimeout:     cfg.PeerIdleTimeout,
				MessageAPI:          true, // UDT_DGRAM
				Congestion:          "",   // default live
				NAKReport:           cfg.NAKReport == nil || *cfg.NAKReport,
				RetransmitAlgo:      cfg.retransmitAlgo(),
				LossMaxTTL:          cfg.LossMaxTTL,
				SndDropDelay:        cfg.SndDropDelay,
				InputBW:             cfg.InputBW,
				MinInputBW:          cfg.MinInputBW,
				OverheadBW:          cfg.OverheadBW,
				DriftTracer:         cfg.driftTracerEnabled(),
				SndSyn:              cfg.sndSynEnabled(),
				RcvSyn:              cfg.rcvSynEnabled(),
				MaxRexmitBW:         cfg.MaxRexmitBW,
				MinVersion:          cfg.MinVersion,
				EnforcedEncryption:  cfg.EnforcedEncryption == nil || *cfg.EnforcedEncryption,
				GroupConnectEnabled: cfg.GroupConnect,
				Logger:              cfg.Logger,
			})

			// Store HSv4 state on the connection for post-handshake exchange
			c.hsVersion = 4
			c.isInitiator = isInitiator

			// If we are the INITIATOR (sender), send HSREQ (and KMREQ if encrypted)
			// via UMSG_EXT. The receiver will reply with HSRSP/KMRSP.
			if isInitiator {
				go c.sendHSv4Extensions(cfg)
			}

			return c, nil

		case <-retry.C:
			sendConclusion()

		case <-timeout:
			m.Close()
			return nil, errors.New("srt: handshake timeout (v4 conclusion)")
		}
	}
}
