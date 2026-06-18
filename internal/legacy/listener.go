package legacy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/filter"
	"github.com/zsiec/srtgo/internal/handshake"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
)

// Listener internal constants.
const (
	listenerBacklog    = 128              // buffered channel capacity for accepted connections
	concludedRetention = 10 * time.Second // how long to cache concluded handshake responses
)

// AcceptFunc is called for each incoming connection during the handshake.
// It receives the connection request with the stream ID and peer address,
// and returns whether to accept the connection.
type AcceptFunc func(req ConnRequest) bool

// ConnRequest provides information about an incoming connection.
type ConnRequest struct {
	// StreamID is the stream identifier from the caller's handshake.
	StreamID string
	// RemoteAddr is the caller's address.
	RemoteAddr net.Addr
	// HSVersion is the handshake version (4 or 5).
	HSVersion uint32
	// GroupID is the peer's group ID (0 = not a group connection).
	GroupID uint32
	// GroupType is the group type (1=broadcast, 2=backup).
	GroupType uint8
}

// Listener accepts incoming SRT connections.
//
// Incoming handshakes are processed through a two-phase state machine:
//   - INDUCTION: Caller sends initial packet, listener responds with SYN cookie
//   - CONCLUSION: Caller echoes cookie with extensions, listener validates and accepts
//
// A context controls the listener lifecycle. Canceling the context closes the
// listener and all pending handshakes.
type Listener struct {
	m      *mux.Mux
	cfg    Config
	cookie *handshake.SYNCookie
	clk    clock.Clock

	// Pending connections: callerSocketID -> pendingConn
	pending   map[uint32]*pendingConn
	pendingMu sync.Mutex

	// Concluded handshakes: callerSocketID -> cached response packet.
	// Used to resend conclusion response if the caller retransmits.
	concluded   map[uint32]*concludedConn
	concludedMu sync.Mutex

	// Accepted connections ready for the application
	backlog chan *Conn

	// Accept callbacks
	acceptFn       AcceptFunc
	acceptRejectFn AcceptRejectFunc
	acceptMu       sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// pendingConn tracks a connection during the handshake.
type pendingConn struct {
	callerAddr     net.Addr
	callerSocketID uint32
	callerISN      seq.Number
	callerMSS      uint32
	callerFC       uint32
	streamID       string
	recvLatency    uint16
	sendLatency    uint16
	createdAt      time.Time
}

// concludedConn caches a conclusion response so it can be resent
// if the caller retransmits its CONCLUSION (first response may have been lost).
type concludedConn struct {
	response  packet.Packet
	createdAt time.Time
}

// Listen creates an SRT listener on the given address.
func Listen(addr string, cfg Config) (*Listener, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("srt: resolve address: %w", err)
	}

	conn, err := listenUDP("udp", udpAddr, cfg)
	if err != nil {
		return nil, fmt.Errorf("srt: listen UDP: %w", err)
	}

	return newListener(conn, cfg, nil)
}

// newListener creates a Listener from an existing PacketConn.
// Exported for testing; production code should use Listen.
func newListener(conn net.PacketConn, cfg Config, clk clock.Clock) (*Listener, error) {
	if clk == nil {
		clk = clock.NewRealClock()
	}

	cookie, err := handshake.NewSYNCookie(conn.LocalAddr().String())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("srt: create SYN cookie: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := mux.New(conn, cfg.MSS)

	l := &Listener{
		m:         m,
		cfg:       cfg,
		cookie:    cookie,
		clk:       clk,
		pending:   make(map[uint32]*pendingConn),
		concluded: make(map[uint32]*concludedConn),
		backlog:   make(chan *Conn, listenerBacklog),
		ctx:       ctx,
		cancel:    cancel,
	}

	l.wg.Add(1)
	go l.handshakeLoop()

	return l, nil
}

// Accept waits for and returns the next incoming connection.
// It blocks until a connection is available or the listener is closed.
func (l *Listener) Accept() (*Conn, error) {
	select {
	case c := <-l.backlog:
		return c, nil
	case <-l.ctx.Done():
		return nil, ErrListenerClosed
	}
}

// SetAcceptFunc sets a callback that is invoked for each incoming connection.
// If the callback returns false, the connection is rejected with RejPeer.
// Must be called before any connections arrive.
//
// Deprecated: Use SetAcceptRejectFunc for finer-grained rejection codes.
func (l *Listener) SetAcceptFunc(fn AcceptFunc) {
	l.acceptMu.Lock()
	l.acceptFn = fn
	l.acceptMu.Unlock()
}

// SetAcceptRejectFunc sets a callback for incoming connections that can return
// a specific rejection code. Return 0 to accept, or a rejection code
// (e.g., RejPeer, or user-defined codes >= RejUserDefined) to reject.
// Takes precedence over SetAcceptFunc if both are set.
func (l *Listener) SetAcceptRejectFunc(fn AcceptRejectFunc) {
	l.acceptMu.Lock()
	l.acceptRejectFn = fn
	l.acceptMu.Unlock()
}

// Close stops the listener and releases resources.
func (l *Listener) Close() error {
	l.cancel()
	err := l.m.Close()
	l.wg.Wait()
	return err
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.m.LocalAddr()
}

// handshakeLoop processes incoming handshake packets from the mux.
func (l *Listener) handshakeLoop() {
	defer l.wg.Done()

	// Periodically clean up stale pending connections
	cleanupTicker := time.NewTicker(1 * time.Second)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-l.ctx.Done():
			return

		case p := <-l.m.Handshake:
			l.handleHandshake(p)

		case <-cleanupTicker.C:
			l.cleanupPending()
		}
	}
}

func (l *Listener) handleHandshake(p packet.Packet) {
	var hs packet.CIFHandshake
	if err := p.UnmarshalCIF(&hs); err != nil {
		p.Release()
		return
	}

	switch hs.HandshakeType {
	case packet.HandshakeTypeInduction:
		l.handleInduction(p, &hs)
	case packet.HandshakeTypeConclusion:
		l.handleConclusion(p, &hs)
	default:
		p.Release()
	}
}

func (l *Listener) handleInduction(p packet.Packet, hs *packet.CIFHandshake) {
	callerAddr := p.Header.Addr

	logf(l.cfg.Logger, LogDebug, LogHandshake, 0, "induction from %s (socketID=%d)", callerAddr, hs.SRTSocketID)

	// Generate SYN cookie for this caller
	cookie := l.cookie.Generate(callerAddr.String())

	// Send induction response with cookie, advertising PBKEYLEN if encryption is configured.
	// PBKEYLEN is encoded in EncryptionField.
	resp := handshake.BuildInductionResponse(hs, cookie, l.m.LocalAddr(), callerAddr, l.cfg.KeyLength)
	l.m.Send(resp)
	resp.Release()
	p.Release()
}

func (l *Listener) handleConclusion(p packet.Packet, hs *packet.CIFHandshake) {
	callerAddr := p.Header.Addr

	// Verify SYN cookie
	if !l.cookie.Verify(callerAddr.String(), hs.SynCookie) {
		// Invalid cookie — reject
		l.sendRejection(callerAddr, hs, RejRdvCookie)
		p.Release()
		return
	}

	// Validate handshake version: accept v4 (with UDT_DGRAM check) and v5, reject all others.
	if hs.Version == 4 {
		l.handleConclusionV4(p, hs)
		return
	} else if hs.Version != 5 {
		l.sendRejection(callerAddr, hs, RejVersion)
		p.Release()
		return
	}

	// HSv5 CONCLUSION requires ExtensionField != 0
	// (must have at least HS_EXT_HSREQ). Reject with RejRogue if missing.
	if hs.ExtensionField == 0 {
		l.sendRejection(callerAddr, hs, RejRogue)
		p.Release()
		return
	}

	// HSv5 requires SRT version >= 1.3.0 (SRT_VERSION_FEAT_HSv5).
	// Reject with RejRogue if peer claims HSv5 but has too-old SRT version.
	if hs.HasHS && hs.SRTHS != nil {
		if hs.SRTHS.SRTVersion < 0x010300 {
			l.sendRejection(callerAddr, hs, RejRogue)
			p.Release()
			return
		}
	}

	// Reject if peer version < MinVersion.
	if hs.HasHS && hs.SRTHS != nil && l.cfg.MinVersion > 0 {
		if hs.SRTHS.SRTVersion < l.cfg.MinVersion {
			l.sendRejection(callerAddr, hs, RejVersion)
			p.Release()
			return
		}
	}

	if hs.MaxTransmissionUnitSize < MinMSS || hs.MaxTransmissionUnitSize > MaxMSS {
		l.sendRejection(callerAddr, hs, RejRogue)
		p.Release()
		return
	}

	// Validate ISN range and FC.
	// ISN must be a valid 31-bit sequence number (< 0x7FFFFFFF).
	// FlightFlagSize (FC) must be >= 2.
	if hs.InitialPacketSequenceNumber > uint32(seq.Max) || hs.MaxFlowWindowSize < 2 {
		l.sendRejection(callerAddr, hs, RejRogue)
		p.Release()
		return
	}

	// Validate SRT extension flags.
	// The ONLY flag-based rejection is message API vs stream mode mismatch.
	// All other flags (TSBPD, TLPKTDROP, NAKReport, Rexmit) are recorded as peer capabilities
	// and negotiated, never rejected.
	peerMessageAPI := true // default: message mode (no FlagStream)
	var peerFlags uint32
	if hs.HasHS && hs.SRTHS != nil {
		peerFlags = hs.SRTHS.SRTFlags
		peerMessageAPI = peerFlags&packet.FlagStream == 0
	}
	// Both sides must agree on message vs stream mode.
	if peerMessageAPI != l.cfg.messageAPIEnabled() {
		l.sendRejection(callerAddr, hs, RejMessageAPI)
		p.Release()
		return
	}

	// Group extension: reject if peer sends group extension but listener doesn't allow it.
	if hs.HasGroup && !l.cfg.GroupConnect {
		l.sendRejection(callerAddr, hs, RejGroup)
		p.Release()
		return
	}

	// Reject GroupBalancing (not implemented).
	if hs.HasGroup && hs.GroupType == uint8(GroupBalancing) {
		l.sendRejection(callerAddr, hs, RejGroup)
		p.Release()
		return
	}

	// Congestion type mismatch rejection: reject if peer's congestion
	// controller doesn't match the listener's configured type.
	peerCongestion := "live"
	if hs.HasCongestion && hs.CongestionType != "" {
		peerCongestion = hs.CongestionType
	}
	if peerCongestion != l.cfg.congestionString() {
		l.sendRejection(callerAddr, hs, RejCongestion)
		p.Release()
		return
	}
	// Check for duplicate conclusion — resend cached response if available
	l.concludedMu.Lock()
	if cc, exists := l.concluded[hs.SRTSocketID]; exists {
		l.concludedMu.Unlock()
		resp := cc.response.Clone()
		l.m.Send(resp)
		resp.Release()
		p.Release()
		return
	}
	l.concludedMu.Unlock()

	// Extract latency from SRT extension
	var callerRecvLatency, callerSendLatency uint16
	if hs.HasHS && hs.SRTHS != nil {
		callerRecvLatency = hs.SRTHS.RecvTSBPDDelay
		callerSendLatency = hs.SRTHS.SendTSBPDDelay
	}

	// Extract stream ID
	streamID := ""
	if hs.HasSID {
		streamID = hs.StreamID
	}

	// Call accept callback if set. AcceptRejectFunc takes precedence.
	l.acceptMu.RLock()
	fn := l.acceptFn
	rejectFn := l.acceptRejectFn
	l.acceptMu.RUnlock()
	req := ConnRequest{
		StreamID:   streamID,
		RemoteAddr: callerAddr,
		HSVersion:  hs.Version,
	}
	if hs.HasGroup {
		req.GroupID = hs.GroupID
		req.GroupType = hs.GroupType
	}
	if rejectFn != nil {
		if rejCode := rejectFn(req); rejCode != 0 {
			l.sendRejection(callerAddr, hs, rejCode)
			p.Release()
			return
		}
	} else if fn != nil {
		if !fn(req) {
			l.sendRejection(callerAddr, hs, RejPeer)
			p.Release()
			return
		}
	}

	// Negotiate parameters
	negotiatedRecv, negotiatedSend := handshake.NegotiateLatency(
		callerRecvLatency, callerSendLatency,
		l.cfg.recvLatencyMS(), l.cfg.peerLatencyMS(),
	)
	negotiatedMSS := handshake.NegotiateMSS(hs.MaxTransmissionUnitSize, uint32(l.cfg.MSS))

	// Verify effective payload size is usable
	if int(negotiatedMSS)-packet.WireHeaderSize < 32 {
		l.sendRejection(callerAddr, hs, RejRogue)
		p.Release()
		return
	}

	// Handle encryption key material
	var cryptoCtx *crypto.Context
	var activeKey packet.PacketEncryption
	var kmResp *packet.CIFKeyMaterial

	enforcedEncryption := l.cfg.EnforcedEncryption == nil || *l.cfg.EnforcedEncryption

	if hs.HasKM && hs.SRTKM != nil {
		// Caller wants encryption
		if l.cfg.Passphrase == "" {
			if enforcedEncryption {
				// Listener has no passphrase — reject
				l.sendRejection(callerAddr, hs, RejUnsecure)
				p.Release()
				return
			}
			// EnforcedEncryption=false: allow unencrypted connection
		} else {
			keyLen := l.cfg.KeyLength
			if keyLen == 0 {
				keyLen = 16
			}
			var err error
			cryptoCtx, err = crypto.New(keyLen)
			if err != nil {
				p.Release()
				return
			}
			if err := cryptoCtx.UnmarshalKM(hs.SRTKM, l.cfg.Passphrase); err != nil {
				if enforcedEncryption {
					l.sendRejection(callerAddr, hs, RejBadSecret)
					p.Release()
					return
				}
				// EnforcedEncryption=false: fall back to unencrypted
				cryptoCtx = nil
			}
			if cryptoCtx != nil {
				activeKey = hs.SRTKM.KeyBasedEncryption

				// Build KMRSP echoing back the key material
				kmResp = &packet.CIFKeyMaterial{}
				if err := cryptoCtx.MarshalKM(kmResp, l.cfg.Passphrase, activeKey); err != nil {
					p.Release()
					return
				}
			}
		}
	} else if l.cfg.Passphrase != "" {
		if enforcedEncryption {
			// Listener requires encryption but caller didn't send KM — reject
			l.sendRejection(callerAddr, hs, RejUnsecure)
			p.Release()
			return
		}
		// EnforcedEncryption=false: allow unencrypted connection
	}

	// Generate listener socket ID.
	// ISN: per C++ SRT, the listener echoes the caller's ISN (used as send ISN
	// for both sides). The caller verifies this echo as a security check.
	listenerSocketID, err := handshake.GenerateSocketID()
	if err != nil {
		p.Release()
		return
	}
	callerISN := hs.InitialPacketSequenceNumber

	// Register with mux to receive packets for this connection
	recvCh := l.m.Register(listenerSocketID)

	// FEC filter negotiation
	negotiatedFilter := l.cfg.PacketFilter
	if hs.HasFilter && hs.FilterConfig != "" {
		if l.cfg.PacketFilter != "" {
			localFEC, _ := filter.ParseConfig(l.cfg.PacketFilter)
			peerFEC, peerErr := filter.ParseConfig(hs.FilterConfig)
			if peerErr != nil {
				l.sendRejection(callerAddr, hs, RejFilter)
				p.Release()
				return
			}
			if _, err := filter.NegotiateConfig(localFEC, peerFEC); err != nil {
				l.sendRejection(callerAddr, hs, RejFilter)
				p.Release()
				return
			}
		}
		negotiatedFilter = hs.FilterConfig
	}

	// Extract group params from peer's handshake (mirror back if GroupConnect enabled).
	var respGroupID uint32
	var respGroupType uint8
	var respGroupWeight uint16
	if hs.HasGroup && l.cfg.GroupConnect {
		respGroupID = hs.GroupID
		respGroupType = hs.GroupType
		respGroupWeight = hs.GroupWeight
	}

	// Conditionally negotiate REXMIT flag — only echo it back if the peer set it in HSREQ.
	// Clear TLPKTDROP if peer version is <= 1.0.7 and NAKReport is enabled
	// (NAK is so efficient that TLPKTDROP is not needed, and was buggy in early
	// versions with low-latency TSBPD).
	hsrspFlags := l.cfg.srtFlags()
	if peerFlags&packet.FlagRexmit == 0 {
		hsrspFlags &^= packet.FlagRexmit
	}
	if hs.HasHS && hs.SRTHS != nil {
		peerVersion := hs.SRTHS.SRTVersion
		nakEnabled := l.cfg.NAKReport == nil || *l.cfg.NAKReport
		if nakEnabled && peerVersion <= 0x010007 { // SrtVersion(1, 0, 7)
			hsrspFlags &^= packet.FlagTLPktDrop
		}
	}

	// Build and send conclusion response.
	// HSRSP does NOT include FlagStream — stream/message mode
	// is validated from the caller's HSREQ only.
	resp := handshake.BuildConclusionResponse(
		listenerSocketID, callerISN,
		negotiatedMSS, uint32(l.cfg.FC),
		hs.SRTSocketID,
		negotiatedRecv, negotiatedSend,
		hsrspFlags,
		l.cfg.congestionString(),
		negotiatedFilter,
		respGroupID, respGroupType, respGroupWeight,
		callerAddr,
		kmResp,
	)
	l.m.Send(resp)

	// Cache the response for retransmission on duplicate CONCLUSION
	l.concludedMu.Lock()
	l.concluded[hs.SRTSocketID] = &concludedConn{
		response:  resp, // keep ownership — don't Release
		createdAt: time.Now(),
	}
	l.concludedMu.Unlock()

	// Create the connection
	tsbpdDelay := time.Duration(negotiatedRecv) * time.Millisecond

	// MSS - 44 bytes (IP 20 + UDP 8 + SRT header 16)
	payloadSize := int(negotiatedMSS) - 44
	if l.cfg.PayloadSize > 0 && l.cfg.PayloadSize < payloadSize {
		payloadSize = l.cfg.PayloadSize
	}

	// Negotiate FC: use the smaller of local and peer flow window
	negotiatedFC := l.cfg.FC
	if int(hs.MaxFlowWindowSize) < negotiatedFC {
		negotiatedFC = int(hs.MaxFlowWindowSize)
	}

	// Extract peer SRT version for ACK size negotiation
	var peerSRTVersion uint32
	if hs.HasHS && hs.SRTHS != nil {
		peerSRTVersion = hs.SRTHS.SRTVersion
	}

	c := newConn(ConnConfig{
		LocalAddr:           l.m.LocalAddr(),
		RemoteAddr:          callerAddr,
		SocketID:            listenerSocketID,
		PeerSocketID:        hs.SRTSocketID,
		StreamID:            streamID,
		IsServer:            true,
		Mux:                 l.m,
		RecvChan:            recvCh,
		Clock:               l.clk,
		SendISN:             seq.Number(callerISN),
		RecvISN:             seq.Number(callerISN),
		SendBufSize:         l.cfg.SendBufSize,
		RecvBufSize:         l.cfg.RecvBufSize,
		MaxBW:               l.cfg.MaxBW,
		TsbpdDelay:          tsbpdDelay,
		PeerTsbpdDelay:      time.Duration(negotiatedSend) * time.Millisecond,
		FC:                  negotiatedFC,
		PayloadSize:         payloadSize,
		CryptoCtx:           cryptoCtx,
		ActiveKey:           activeKey,
		Linger:              l.cfg.Linger,
		PeerIdleTimeout:     l.cfg.PeerIdleTimeout,
		Passphrase:          l.cfg.Passphrase,
		KMRefreshRate:       l.cfg.KMRefreshRate,
		KMPreAnnounce:       l.cfg.KMPreAnnounce,
		MessageAPI:          l.cfg.messageAPIEnabled(),
		Congestion:          l.cfg.Congestion,
		NAKReport:           l.cfg.NAKReport == nil || *l.cfg.NAKReport,
		PeerNakReport:       peerFlags&packet.FlagPeriodicNAK != 0,
		RetransmitAlgo:      l.cfg.retransmitAlgo(),
		LossMaxTTL:          l.cfg.LossMaxTTL,
		SndDropDelay:        l.cfg.SndDropDelay,
		InputBW:             l.cfg.InputBW,
		MinInputBW:          l.cfg.MinInputBW,
		OverheadBW:          l.cfg.OverheadBW,
		DriftTracer:         l.cfg.driftTracerEnabled(),
		PeerSRTVersion:      peerSRTVersion,
		PeerStartTime:       p.Header.Timestamp, // peer's timestamp for TSBPD timebase
		PacketFilter:        negotiatedFilter,
		GroupID:             respGroupID,
		PeerGroupID:         hs.GroupID, // store peer's group ID if present
		GroupType:           respGroupType,
		GroupWeight:         respGroupWeight,
		SndSyn:              l.cfg.sndSynEnabled(),
		RcvSyn:              l.cfg.rcvSynEnabled(),
		MaxRexmitBW:         l.cfg.MaxRexmitBW,
		MinVersion:          l.cfg.MinVersion,
		EnforcedEncryption:  l.cfg.EnforcedEncryption == nil || *l.cfg.EnforcedEncryption,
		GroupConnectEnabled: l.cfg.GroupConnect,
		Logger:              l.cfg.Logger,
	})

	// Enqueue for Accept
	select {
	case l.backlog <- c:
		logf(l.cfg.Logger, LogNote, LogHandshake, listenerSocketID,
			"accepted connection from %s (peer=%d, streamID=%q)", callerAddr, hs.SRTSocketID, streamID)
	default:
		// Backlog full — send rejection and close
		l.sendRejection(callerAddr, hs, RejBacklog)
		c.Close()
	}

	p.Release()
}

// handleConclusionV4 processes an HSv4 CONCLUSION handshake.
// HSv4 requires type == UDT_DGRAM (= 2). The connection is established without
// SRT extensions (no TSBPD, no encryption, no stream ID, no congestion type
// negotiation). The peer may later send HSREQ and KMREQ as UMSG_EXT control
// messages (not yet supported).
func (l *Listener) handleConclusionV4(p packet.Packet, hs *packet.CIFHandshake) {
	callerAddr := p.Header.Addr

	// Validate type == UDT_DGRAM.
	// In wire format, type = (EncryptionField << 16) | ExtensionField.
	// UDT_DGRAM = 2, so EncryptionField=0 and ExtensionField=2.
	if hs.EncryptionField != 0 || hs.ExtensionField != 2 {
		l.sendRejection(callerAddr, hs, RejRogue)
		p.Release()
		return
	}

	// If MinVersion >= 1.3.0 (SRT_VERSION_FEAT_HSv5),
	// reject HSv4 clients since they can't support required features.
	if l.cfg.MinVersion >= 0x010300 {
		l.sendRejection(callerAddr, hs, RejVersion)
		p.Release()
		return
	}

	if hs.MaxTransmissionUnitSize < MinMSS || hs.MaxTransmissionUnitSize > MaxMSS {
		l.sendRejection(callerAddr, hs, RejRogue)
		p.Release()
		return
	}

	// Validate ISN range and FC.
	if hs.InitialPacketSequenceNumber > uint32(seq.Max) || hs.MaxFlowWindowSize < 2 {
		l.sendRejection(callerAddr, hs, RejRogue)
		p.Release()
		return
	}

	// Check for duplicate conclusion — resend cached response
	l.concludedMu.Lock()
	if cc, exists := l.concluded[hs.SRTSocketID]; exists {
		l.concludedMu.Unlock()
		resp := cc.response.Clone()
		l.m.Send(resp)
		resp.Release()
		p.Release()
		return
	}
	l.concludedMu.Unlock()

	// Call accept callback (no stream ID for v4)
	l.acceptMu.RLock()
	fnV4 := l.acceptFn
	rejectFnV4 := l.acceptRejectFn
	l.acceptMu.RUnlock()
	reqV4 := ConnRequest{
		StreamID:   "",
		RemoteAddr: callerAddr,
		HSVersion:  hs.Version,
	}
	if rejectFnV4 != nil {
		if rejCode := rejectFnV4(reqV4); rejCode != 0 {
			l.sendRejection(callerAddr, hs, rejCode)
			p.Release()
			return
		}
	} else if fnV4 != nil {
		if !fnV4(reqV4) {
			l.sendRejection(callerAddr, hs, RejPeer)
			p.Release()
			return
		}
	}

	negotiatedMSS := handshake.NegotiateMSS(hs.MaxTransmissionUnitSize, uint32(l.cfg.MSS))
	if int(negotiatedMSS)-packet.WireHeaderSize < 32 {
		l.sendRejection(callerAddr, hs, RejRogue)
		p.Release()
		return
	}

	listenerSocketID, err := handshake.GenerateSocketID()
	if err != nil {
		p.Release()
		return
	}
	callerISNv4 := hs.InitialPacketSequenceNumber

	recvCh := l.m.Register(listenerSocketID)

	// Build and send HSv4 conclusion response (no extensions).
	// Echo caller's ISN per C++ SRT security check.
	resp := handshake.BuildConclusionResponseV4(
		listenerSocketID, callerISNv4,
		negotiatedMSS, uint32(l.cfg.FC),
		hs.SRTSocketID,
		callerAddr,
	)
	l.m.Send(resp)

	l.concludedMu.Lock()
	l.concluded[hs.SRTSocketID] = &concludedConn{
		response:  resp,
		createdAt: time.Now(),
	}
	l.concludedMu.Unlock()

	payloadSize := int(negotiatedMSS) - 44
	if l.cfg.PayloadSize > 0 && l.cfg.PayloadSize < payloadSize {
		payloadSize = l.cfg.PayloadSize
	}
	negotiatedFC := l.cfg.FC
	if int(hs.MaxFlowWindowSize) < negotiatedFC {
		negotiatedFC = int(hs.MaxFlowWindowSize)
	}

	// HSv4: no TSBPD, no encryption, no TLPKTDROP, no stream ID.
	c := newConn(ConnConfig{
		LocalAddr:           l.m.LocalAddr(),
		RemoteAddr:          callerAddr,
		SocketID:            listenerSocketID,
		PeerSocketID:        hs.SRTSocketID,
		StreamID:            "",
		IsServer:            true,
		Mux:                 l.m,
		RecvChan:            recvCh,
		Clock:               l.clk,
		SendISN:             seq.Number(callerISNv4),
		RecvISN:             seq.Number(callerISNv4),
		SendBufSize:         l.cfg.SendBufSize,
		RecvBufSize:         l.cfg.RecvBufSize,
		MaxBW:               l.cfg.MaxBW,
		TsbpdDelay:          0, // HSv4: no TSBPD until HSREQ via UMSG_EXT
		FC:                  negotiatedFC,
		PayloadSize:         payloadSize,
		Linger:              l.cfg.Linger,
		PeerIdleTimeout:     l.cfg.PeerIdleTimeout,
		MessageAPI:          true, // UDT_DGRAM
		Congestion:          "",   // default live
		NAKReport:           l.cfg.NAKReport == nil || *l.cfg.NAKReport,
		PeerNakReport:       false, // HSv4: no SRT flags available
		RetransmitAlgo:      l.cfg.retransmitAlgo(),
		LossMaxTTL:          l.cfg.LossMaxTTL,
		SndDropDelay:        l.cfg.SndDropDelay,
		InputBW:             l.cfg.InputBW,
		MinInputBW:          l.cfg.MinInputBW,
		OverheadBW:          l.cfg.OverheadBW,
		DriftTracer:         l.cfg.driftTracerEnabled(),
		SndSyn:              l.cfg.sndSynEnabled(),
		RcvSyn:              l.cfg.rcvSynEnabled(),
		MaxRexmitBW:         l.cfg.MaxRexmitBW,
		MinVersion:          l.cfg.MinVersion,
		EnforcedEncryption:  l.cfg.EnforcedEncryption == nil || *l.cfg.EnforcedEncryption,
		GroupConnectEnabled: l.cfg.GroupConnect,
		Logger:              l.cfg.Logger,
	})

	select {
	case l.backlog <- c:
	default:
		l.sendRejection(callerAddr, hs, RejBacklog)
		c.Close()
	}

	p.Release()
}

func (l *Listener) sendRejection(callerAddr net.Addr, hs *packet.CIFHandshake, rejType packet.HandshakeType) {
	logf(l.cfg.Logger, LogWarning, LogHandshake, 0,
		"rejecting %s (peer=%d, reason=%v)", callerAddr, hs.SRTSocketID, rejType)

	if hs.Version < 5 {
		// HSv4 clients do not interpret the error handshake response correctly.
		// Send a SHUTDOWN control packet instead so the peer knows to abort
		// the connection.
		shutdownPkt := packet.NewControl(callerAddr, packet.CtrlTypeShutdown, hs.SRTSocketID, 0)
		l.m.Send(shutdownPkt)
		shutdownPkt.Release()
		return
	}

	// HSv5: send error handshake with rejection code
	resp := packet.NewControl(callerAddr, packet.CtrlTypeHandshake, hs.SRTSocketID, 0)

	rejHS := &packet.CIFHandshake{
		Version:       5,
		HandshakeType: rejType,
		SRTSocketID:   0,
	}
	resp.MarshalCIF(rejHS)
	l.m.Send(resp)
	resp.Release()
}

func (l *Listener) cleanupPending() {
	l.pendingMu.Lock()
	now := time.Now()
	for id, pc := range l.pending {
		if now.Sub(pc.createdAt) > l.cfg.ConnTimeout {
			delete(l.pending, id)
		}
	}
	l.pendingMu.Unlock()

	// Also clean up stale concluded responses (keep for concludedRetention to handle retransmits)
	l.concludedMu.Lock()
	for id, cc := range l.concluded {
		if now.Sub(cc.createdAt) > concludedRetention {
			cc.response.Release()
			delete(l.concluded, id)
		}
	}
	l.concludedMu.Unlock()
}
