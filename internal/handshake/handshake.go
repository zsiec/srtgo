// Package handshake implements the SRT connection handshake state machine.
//
// The SRT handshake follows a two-phase process for caller-listener connections:
//
//  1. INDUCTION: Caller sends initial handshake, Listener responds with SYN cookie
//  2. CONCLUSION: Caller echoes cookie with extensions, Listener accepts/rejects
//
// Extensions exchanged during CONCLUSION include:
//   - HSREQ/HSRSP: SRT version, feature flags, TSBPD delays
//   - KMREQ/KMRSP: Key material for encryption
//   - SID: Stream ID for routing/authorization
package handshake

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/zsiec/srtgo/internal/packet"
)

// SRT protocol constants
const (
	SRTVersion  uint32 = 0x010504 // SRT v1.5.4 (implements the 1.5.4 AES-GCM nonce + GCM153 back-compat)
	SRTMagic    uint16 = 0x4A17   // Magic number in listener INDUCTION response
	UDTV4Marker uint16 = 2        // ExtensionField value for UDT v4 DGRAM
)

// SRT feature flags (for HSREQ/HSRSP SRTFlags field)
const (
	defaultFlags = packet.FlagTSBPDSend | packet.FlagTSBPDRecv |
		packet.FlagCrypt | packet.FlagTLPktDrop |
		packet.FlagPeriodicNAK | packet.FlagRexmit
)

// SYNCookie generates and validates SYN cookies for listener-side
// protection against spoofed handshakes.
type SYNCookie struct {
	mu      sync.Mutex
	secret1 string
	secret2 string
	addr    string
}

// NewSYNCookie creates a SYN cookie generator for the given listener address.
func NewSYNCookie(listenerAddr string) (*SYNCookie, error) {
	sc := &SYNCookie{addr: listenerAddr}
	if err := sc.refreshSecrets(); err != nil {
		return nil, err
	}
	return sc, nil
}

// Generate creates a SYN cookie for the given source address.
func (sc *SYNCookie) Generate(srcAddr string) uint32 {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	counter := time.Now().Unix() >> 6
	return sc.compute(srcAddr, counter)
}

// Verify checks if a SYN cookie is valid for the given source address.
// It accepts cookies from the current or previous time window.
func (sc *SYNCookie) Verify(srcAddr string, cookie uint32) bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	counter := time.Now().Unix() >> 6
	if sc.compute(srcAddr, counter) == cookie {
		return true
	}
	// Also accept previous window
	return sc.compute(srcAddr, counter-1) == cookie
}

func (sc *SYNCookie) compute(srcAddr string, counter int64) uint32 {
	h := md5.New()
	h.Write([]byte(sc.secret1))
	h.Write([]byte(sc.addr))
	h.Write([]byte(srcAddr))
	h.Write([]byte(sc.secret2))
	h.Write([]byte(strconv.FormatInt(counter, 10)))
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum[:4])
}

func (sc *SYNCookie) refreshSecrets() error {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("handshake: generating secrets: %w", err)
	}
	sc.secret1 = fmt.Sprintf("%x", buf[:16])
	sc.secret2 = fmt.Sprintf("%x", buf[16:])
	return nil
}

// GenerateSocketID creates a random SRT socket ID.
func GenerateSocketID() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("handshake: generating socket ID: %w", err)
	}
	id := binary.BigEndian.Uint32(buf[:])
	if id == 0 {
		id = 1 // 0 is reserved for handshake packets
	}
	return id, nil
}

// GenerateISN creates a random Initial Sequence Number (31-bit).
func GenerateISN() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("handshake: generating ISN: %w", err)
	}
	return binary.BigEndian.Uint32(buf[:]) & 0x7FFFFFFF, nil
}

// BuildInduction creates the caller's initial INDUCTION handshake.
func BuildInduction(callerSocketID, isn uint32, mss, fc uint32, addr net.Addr) packet.Packet {
	p := packet.NewControl(addr, packet.CtrlTypeHandshake, 0, 0)

	hs := &packet.CIFHandshake{
		Version:                     4,
		EncryptionField:             0,
		ExtensionField:              UDTV4Marker,
		InitialPacketSequenceNumber: isn,
		MaxTransmissionUnitSize:     mss,
		MaxFlowWindowSize:           fc,
		HandshakeType:               packet.HandshakeTypeInduction,
		SRTSocketID:                 callerSocketID,
		SynCookie:                   0,
		PeerIP:                      extractIP(addr),
	}

	p.MarshalCIF(hs)
	return p
}

// BuildInductionResponse creates the listener's INDUCTION response with SYN cookie.
// keyLength is the configured PBKEYLEN in bytes (0, 16, 24, or 32).
// PBKEYLEN is advertised in EncryptionField as keyLen >> 3 (2=AES-128, 3=AES-192, 4=AES-256).
func BuildInductionResponse(callerHS *packet.CIFHandshake, cookie uint32, listenerAddr net.Addr, callerAddr net.Addr, keyLength int) packet.Packet {
	p := packet.NewControl(callerAddr, packet.CtrlTypeHandshake, callerHS.SRTSocketID, 0)

	// Encode PBKEYLEN as enc_flags: keyLen/8 (16->2, 24->3, 32->4, 0->0)
	var encField uint16
	if keyLength > 0 {
		encField = uint16(keyLength >> 3)
	}

	hs := &packet.CIFHandshake{
		Version:                     5,
		EncryptionField:             encField,
		ExtensionField:              SRTMagic,
		InitialPacketSequenceNumber: callerHS.InitialPacketSequenceNumber,
		MaxTransmissionUnitSize:     callerHS.MaxTransmissionUnitSize,
		MaxFlowWindowSize:           callerHS.MaxFlowWindowSize,
		HandshakeType:               packet.HandshakeTypeInduction,
		SRTSocketID:                 0, // listener doesn't reveal its ID yet
		SynCookie:                   cookie,
		PeerIP:                      extractIP(listenerAddr),
	}

	p.MarshalCIF(hs)
	return p
}

// BuildConclusion creates the caller's CONCLUSION handshake with extensions.
// If km is non-nil, it includes the KMREQ extension for encryption negotiation.
// srtFlags controls the SRT feature flags (use 0 for defaultFlags).
// congestionType is "live" or "file".
// filterConfig is the FEC filter config string (empty = no FEC).
func BuildConclusion(
	callerSocketID, isn uint32,
	mss, fc uint32,
	cookie uint32,
	streamID string,
	recvLatency, sendLatency uint16,
	srtFlags uint32,
	congestionType string,
	filterConfig string,
	groupID uint32, groupType uint8, groupWeight uint16,
	addr net.Addr,
	km *packet.CIFKeyMaterial,
) packet.Packet {
	if srtFlags == 0 {
		srtFlags = defaultFlags
	}
	p := packet.NewControl(addr, packet.CtrlTypeHandshake, 0, 0)

	hs := &packet.CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: isn,
		MaxTransmissionUnitSize:     mss,
		MaxFlowWindowSize:           fc,
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 callerSocketID,
		SynCookie:                   cookie,
		PeerIP:                      extractIP(addr),

		IsRequest: true,
		HasHS:     true,
		SRTHS: &packet.CIFHandshakeExtension{
			SRTVersion:     SRTVersion,
			SRTFlags:       srtFlags,
			RecvTSBPDDelay: recvLatency,
			SendTSBPDDelay: sendLatency,
		},
	}

	if streamID != "" {
		hs.HasSID = true
		hs.StreamID = streamID
	}

	hs.HasCongestion = true
	if congestionType == "" {
		congestionType = "live"
	}
	hs.CongestionType = congestionType

	if filterConfig != "" {
		hs.HasFilter = true
		hs.FilterConfig = filterConfig
	}

	if groupID != 0 {
		hs.HasGroup = true
		hs.GroupID = groupID
		hs.GroupType = groupType
		hs.GroupWeight = groupWeight
	}

	if km != nil {
		hs.HasKM = true
		hs.SRTKM = km
	}

	p.MarshalCIF(hs)
	return p
}

// BuildConclusionResponse creates the listener's CONCLUSION response.
// If km is non-nil, it includes the KMRSP extension echoing the encryption parameters.
// srtFlags controls the SRT feature flags (use 0 for defaultFlags).
// congestionType is "live" or "file".
// filterConfig is the negotiated FEC filter config string (empty = no FEC).
func BuildConclusionResponse(
	listenerSocketID, isn uint32,
	mss, fc uint32,
	callerSocketID uint32,
	recvLatency, sendLatency uint16,
	srtFlags uint32,
	congestionType string,
	filterConfig string,
	groupID uint32, groupType uint8, groupWeight uint16,
	callerAddr net.Addr,
	km *packet.CIFKeyMaterial,
) packet.Packet {
	if srtFlags == 0 {
		srtFlags = defaultFlags
	}
	p := packet.NewControl(callerAddr, packet.CtrlTypeHandshake, callerSocketID, 0)

	hs := &packet.CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: isn,
		MaxTransmissionUnitSize:     mss,
		MaxFlowWindowSize:           fc,
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 listenerSocketID,
		SynCookie:                   0, // cleared for response
		PeerIP:                      extractIP(callerAddr),

		IsRequest: false,
		HasHS:     true,
		SRTHS: &packet.CIFHandshakeExtension{
			SRTVersion:     SRTVersion,
			SRTFlags:       srtFlags,
			RecvTSBPDDelay: recvLatency,
			SendTSBPDDelay: sendLatency,
		},
	}

	hs.HasCongestion = true
	if congestionType == "" {
		congestionType = "live"
	}
	hs.CongestionType = congestionType

	if filterConfig != "" {
		hs.HasFilter = true
		hs.FilterConfig = filterConfig
	}

	if groupID != 0 {
		hs.HasGroup = true
		hs.GroupID = groupID
		hs.GroupType = groupType
		hs.GroupWeight = groupWeight
	}

	if km != nil {
		hs.HasKM = true
		hs.SRTKM = km
	}

	p.MarshalCIF(hs)
	return p
}

// BuildConclusionResponseV4 creates the listener's HSv4 CONCLUSION response.
// HSv4 has no SRT extensions — basic UDT handshake only with type = UDT_DGRAM.
// When peer is v4, response uses version=4, type=UDT_DGRAM, no extensions.
func BuildConclusionResponseV4(
	listenerSocketID, isn uint32,
	mss, fc uint32,
	callerSocketID uint32,
	callerAddr net.Addr,
) packet.Packet {
	p := packet.NewControl(callerAddr, packet.CtrlTypeHandshake, callerSocketID, 0)

	hs := &packet.CIFHandshake{
		Version:                     4,
		InitialPacketSequenceNumber: isn,
		MaxTransmissionUnitSize:     mss,
		MaxFlowWindowSize:           fc,
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 listenerSocketID,
		SynCookie:                   0,
		PeerIP:                      extractIP(callerAddr),
		// Version=4 triggers MarshalCIF to set EncryptionField=0, ExtensionField=2 (UDT_DGRAM)
		// No extensions: HasHS=false, HasKM=false, HasSID=false, HasCongestion=false
	}

	p.MarshalCIF(hs)
	return p
}

// NegotiateLatency returns the negotiated latency values.
// SRT uses the maximum of both sides' requested latencies.
func NegotiateLatency(callerRecv, callerSend, listenerRecv, listenerSend uint16) (recv, send uint16) {
	recv = callerRecv
	if listenerRecv > recv {
		recv = listenerRecv
	}
	send = callerSend
	if listenerSend > send {
		send = listenerSend
	}
	return recv, send
}

// NegotiateMSS returns the smaller of the two MSS values.
func NegotiateMSS(callerMSS, listenerMSS uint32) uint32 {
	if callerMSS < listenerMSS {
		return callerMSS
	}
	return listenerMSS
}

// GenerateRandomCookie creates a random non-zero cookie for rendezvous handshake.
func GenerateRandomCookie() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("handshake: generating cookie: %w", err)
	}
	c := binary.BigEndian.Uint32(buf[:])
	if c == 0 {
		c = 1
	}
	return c, nil
}

// BuildWavehand creates a WAVEHAND handshake packet for rendezvous mode.
// version=5, type=WAVEAHAND, cookie=random,
// EncryptionField=PBKEYLEN encoded, ExtensionField=0 (no SRT magic).
func BuildWavehand(socketID, isn, mss, fc, cookie uint32, keyLength int, addr net.Addr) packet.Packet {
	p := packet.NewControl(addr, packet.CtrlTypeHandshake, 0, 0)

	var encField uint16
	if keyLength > 0 {
		encField = uint16(keyLength >> 3)
	}

	hs := &packet.CIFHandshake{
		Version:                     5,
		EncryptionField:             encField,
		ExtensionField:              0,
		InitialPacketSequenceNumber: isn,
		MaxTransmissionUnitSize:     mss,
		MaxFlowWindowSize:           fc,
		HandshakeType:               packet.HandshakeTypeWavehand,
		SRTSocketID:                 socketID,
		SynCookie:                   cookie,
		PeerIP:                      extractIP(addr),
	}

	p.MarshalCIF(hs)
	return p
}

// BuildAgreement creates an AGREEMENT packet to finalize rendezvous.
// Sent by INITIATOR to confirm connection. No extensions.
func BuildAgreement(socketID, isn, mss, fc, peerSocketID uint32, addr net.Addr) packet.Packet {
	p := packet.NewControl(addr, packet.CtrlTypeHandshake, peerSocketID, 0)

	hs := &packet.CIFHandshake{
		Version:                     5,
		EncryptionField:             0,
		ExtensionField:              0,
		InitialPacketSequenceNumber: isn,
		MaxTransmissionUnitSize:     mss,
		MaxFlowWindowSize:           fc,
		HandshakeType:               packet.HandshakeTypeAgreement,
		SRTSocketID:                 socketID,
		SynCookie:                   0,
		PeerIP:                      extractIP(addr),
	}

	p.MarshalCIF(hs)
	return p
}

// BuildRendezvousConclusion creates a CONCLUSION for rendezvous mode.
// Unlike BuildConclusion, this sets DestinationSocketID to the peer's socketID.
// isRequest=true sends HSREQ/KMREQ (INITIATOR), isRequest=false sends HSRSP/KMRSP (RESPONDER).
// hasExt controls whether extensions are included at all.
// keyLength is the configured PBKEYLEN in bytes (0, 16, 24, or 32).
// PBKEYLEN is advertised in EncryptionField regardless of handshake stage,
// because in rendezvous mode CONCLUSION may be the first message ever received by a party.
// filterConfig is the FEC filter config string (empty = no FEC).
func BuildRendezvousConclusion(
	socketID, isn uint32,
	mss, fc uint32,
	peerSocketID uint32,
	cookie uint32,
	isRequest bool,
	recvLatency, sendLatency uint16,
	srtFlags uint32,
	congestionType string,
	filterConfig string,
	groupID uint32, groupType uint8, groupWeight uint16,
	streamID string,
	addr net.Addr,
	km *packet.CIFKeyMaterial,
	hasExt bool,
	keyLength int,
) packet.Packet {
	if srtFlags == 0 {
		srtFlags = defaultFlags
	}
	p := packet.NewControl(addr, packet.CtrlTypeHandshake, peerSocketID, 0)

	// Encode PBKEYLEN as enc_flags: keyLen/8 (16->2, 24->3, 32->4, 0->0)
	// Always advertise PBKEYLEN in EncryptionField.
	var encField uint16
	if keyLength > 0 {
		encField = uint16(keyLength >> 3)
	}

	hs := &packet.CIFHandshake{
		Version:                     5,
		EncryptionField:             encField,
		InitialPacketSequenceNumber: isn,
		MaxTransmissionUnitSize:     mss,
		MaxFlowWindowSize:           fc,
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 socketID,
		SynCookie:                   cookie,
		PeerIP:                      extractIP(addr),
		IsRequest:                   isRequest,
	}

	if hasExt {
		hs.HasHS = true
		hs.SRTHS = &packet.CIFHandshakeExtension{
			SRTVersion:     SRTVersion,
			SRTFlags:       srtFlags,
			RecvTSBPDDelay: recvLatency,
			SendTSBPDDelay: sendLatency,
		}

		if streamID != "" {
			hs.HasSID = true
			hs.StreamID = streamID
		}

		hs.HasCongestion = true
		if congestionType == "" {
			congestionType = "live"
		}
		hs.CongestionType = congestionType

		if filterConfig != "" {
			hs.HasFilter = true
			hs.FilterConfig = filterConfig
		}

		if groupID != 0 {
			hs.HasGroup = true
			hs.GroupID = groupID
			hs.GroupType = groupType
			hs.GroupWeight = groupWeight
		}

		if km != nil {
			hs.HasKM = true
			hs.SRTKM = km
		}
	}

	p.MarshalCIF(hs)
	return p
}

// BuildConclusionV4 creates the caller's HSv4 CONCLUSION handshake.
// HSv4 has no SRT extensions — basic UDT handshake with type = UDT_DGRAM.
func BuildConclusionV4(
	callerSocketID, isn uint32,
	mss, fc uint32,
	cookie uint32,
	addr net.Addr,
) packet.Packet {
	p := packet.NewControl(addr, packet.CtrlTypeHandshake, 0, 0)

	hs := &packet.CIFHandshake{
		Version:                     4,
		EncryptionField:             0,
		ExtensionField:              UDTV4Marker,
		InitialPacketSequenceNumber: isn,
		MaxTransmissionUnitSize:     mss,
		MaxFlowWindowSize:           fc,
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 callerSocketID,
		SynCookie:                   cookie,
		PeerIP:                      extractIP(addr),
	}

	p.MarshalCIF(hs)
	return p
}

// BuildExtHSREQ creates a UMSG_EXT control packet containing HSREQ payload.
// Used for post-handshake extension exchange in HSv4 mode.
func BuildExtHSREQ(
	destSocketID uint32,
	srtVersion uint32,
	srtFlags uint32,
	latency uint16,
	addr net.Addr,
) packet.Packet {
	p := packet.NewControl(addr, packet.CtrlTypeUser, destSocketID, 0)
	p.Header.SubType = packet.ExtTypeHSReq

	if srtFlags == 0 {
		srtFlags = defaultFlags
	}

	// HSREQ payload: 3 uint32s (version, flags, latency)
	// HSv4 uses a single 16-bit latency value in the lower 16 bits.
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:], srtVersion)
	binary.BigEndian.PutUint32(buf[4:], srtFlags)
	binary.BigEndian.PutUint32(buf[8:], uint32(latency))
	p.SetData(buf)
	return p
}

// BuildExtHSRSP creates a UMSG_EXT control packet containing HSRSP payload.
// Used for post-handshake extension exchange in HSv4 mode.
func BuildExtHSRSP(
	destSocketID uint32,
	srtVersion uint32,
	srtFlags uint32,
	latency uint16,
	addr net.Addr,
) packet.Packet {
	p := packet.NewControl(addr, packet.CtrlTypeUser, destSocketID, 0)
	p.Header.SubType = packet.ExtTypeHSRsp

	if srtFlags == 0 {
		srtFlags = defaultFlags
	}

	// HSRSP payload: 3 uint32s (version, flags, latency)
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:], srtVersion)
	binary.BigEndian.PutUint32(buf[4:], srtFlags)
	binary.BigEndian.PutUint32(buf[8:], uint32(latency))
	p.SetData(buf)
	return p
}

// BuildExtKMREQ creates a UMSG_EXT control packet containing KMREQ payload.
// Used for post-handshake key material exchange in HSv4 mode.
func BuildExtKMREQ(destSocketID uint32, km *packet.CIFKeyMaterial, addr net.Addr) (packet.Packet, error) {
	p := packet.NewControl(addr, packet.CtrlTypeUser, destSocketID, 0)
	p.Header.SubType = packet.ExtTypeKMReq

	data, err := km.MarshalCIF()
	if err != nil {
		p.Release()
		return packet.Packet{}, fmt.Errorf("handshake: marshal KMREQ: %w", err)
	}
	p.SetData(data)
	return p, nil
}

// BuildExtKMRSP creates a UMSG_EXT control packet containing KMRSP payload.
// Used for post-handshake key material response in HSv4 mode.
func BuildExtKMRSP(destSocketID uint32, km *packet.CIFKeyMaterial, addr net.Addr) (packet.Packet, error) {
	p := packet.NewControl(addr, packet.CtrlTypeUser, destSocketID, 0)
	p.Header.SubType = packet.ExtTypeKMRsp

	data, err := km.MarshalCIF()
	if err != nil {
		p.Release()
		return packet.Packet{}, fmt.Errorf("handshake: marshal KMRSP: %w", err)
	}
	p.SetData(data)
	return p, nil
}

// ParseExtHSREQ parses an HSREQ payload from a UMSG_EXT packet.
// Returns SRT version, flags, and latency (single HSv4 value).
func ParseExtHSREQ(data []byte) (srtVersion, srtFlags uint32, latency uint16, err error) {
	if len(data) < 12 {
		return 0, 0, 0, fmt.Errorf("handshake: HSREQ data too short (%d bytes)", len(data))
	}
	srtVersion = binary.BigEndian.Uint32(data[0:])
	srtFlags = binary.BigEndian.Uint32(data[4:])
	latencyRaw := binary.BigEndian.Uint32(data[8:])
	latency = uint16(latencyRaw & 0xFFFF)
	return srtVersion, srtFlags, latency, nil
}

func extractIP(addr net.Addr) net.IP {
	if addr == nil {
		return net.IPv4(0, 0, 0, 0)
	}
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	default:
		return net.IPv4(0, 0, 0, 0)
	}
}
