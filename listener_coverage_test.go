package srt

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/handshake"
	"github.com/zsiec/srtgo/internal/packet"
)

// sendRawHandshake sends a raw handshake CIF to the listener's address via UDP.
// Returns the raw response bytes. Returns an error (typically timeout) if no response.
func sendRawHandshake(t *testing.T, listenerAddr string, hs *packet.CIFHandshake) ([]byte, error) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	raddr, err := net.ResolveUDPAddr("udp", listenerAddr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	if err := p.MarshalCIF(hs); err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}
	raw, err := p.MarshalTo()
	p.Release()
	if err != nil {
		t.Fatalf("MarshalTo: %v", err)
	}

	if _, err := conn.WriteTo(raw, raddr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := conn.ReadFrom(respBuf)
	if err != nil {
		return nil, err
	}
	return respBuf[:n], nil
}

// doInduction performs the INDUCTION phase with the listener and returns
// the SYN cookie and the UDP connection (for reuse in the CONCLUSION phase).
func doInduction(t *testing.T, listenerAddr string) (cookie uint32, srcConn net.PacketConn) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	raddr, err := net.ResolveUDPAddr("udp", listenerAddr)
	if err != nil {
		conn.Close()
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	// Send INDUCTION
	indHS := &packet.CIFHandshake{
		Version:                     4,
		EncryptionField:             0,
		ExtensionField:              2, // UDT_DGRAM
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               packet.HandshakeTypeInduction,
		SRTSocketID:                 12345,
		SynCookie:                   0,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
	}

	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.MarshalCIF(indHS)
	raw, _ := p.MarshalTo()
	p.Release()

	conn.WriteTo(raw, raddr)

	// Read induction response
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := conn.ReadFrom(respBuf)
	if err != nil {
		conn.Close()
		t.Fatalf("read induction response: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		conn.Close()
		t.Fatalf("parse induction response: %v", err)
	}
	var respHS packet.CIFHandshake
	if err := resp.UnmarshalCIF(&respHS); err != nil {
		resp.Release()
		conn.Close()
		t.Fatalf("unmarshal induction response: %v", err)
	}
	resp.Release()

	return respHS.SynCookie, conn
}

// common SRT flags for test handshakes.
var testSRTFlags = packet.FlagTSBPDSend | packet.FlagTSBPDRecv |
	packet.FlagCrypt | packet.FlagTLPktDrop |
	packet.FlagPeriodicNAK | packet.FlagRexmit | packet.FlagPacketFilter

// TestHandleHandshakeInvalidType sends a handshake with an unexpected type
// (AGREEMENT) to hit the default path in handleHandshake.
func TestHandleHandshakeInvalidType(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	hs := &packet.CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               packet.HandshakeTypeAgreement,
		SRTSocketID:                 99999,
		SynCookie:                   0,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
	}

	// Expect no response (the listener should silently drop it)
	_, err = sendRawHandshake(t, l.Addr().String(), hs)
	if err == nil {
		t.Error("expected timeout (no response) for AGREEMENT handshake, but got a response")
	}
}

// TestHandleHandshakeWavehand sends a WAVEHAND handshake type
// to hit the default path in handleHandshake.
func TestHandleHandshakeWavehand(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	hs := &packet.CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               packet.HandshakeTypeWavehand,
		SRTSocketID:                 99998,
		SynCookie:                   0,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
	}

	_, err = sendRawHandshake(t, l.Addr().String(), hs)
	if err == nil {
		t.Error("expected timeout (no response) for WAVEHAND handshake, but got a response")
	}
}

// TestHandleConclusionInvalidCookie sends a CONCLUSION with a wrong SYN cookie.
func TestHandleConclusionInvalidCookie(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	hs := &packet.CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 55555,
		SynCookie:                   0xDEADBEEF,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
		ExtensionField:              1,
		HasHS:                       true,
		IsRequest:                   true,
		SRTHS: &packet.CIFHandshakeExtension{
			SRTVersion:     handshake.SRTVersion,
			SRTFlags:       testSRTFlags,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
		HasCongestion:  true,
		CongestionType: "live",
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.MarshalCIF(hs)
	raw, _ := p.MarshalTo()
	p.Release()

	conn.WriteTo(raw, raddr)

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := conn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected rejection response, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	var respHS packet.CIFHandshake
	if err := resp.UnmarshalCIF(&respHS); err != nil {
		resp.Release()
		t.Fatalf("unmarshal response: %v", err)
	}
	resp.Release()

	if !respHS.HandshakeType.IsRejection() {
		t.Errorf("expected rejection, got type=%v", respHS.HandshakeType)
	}
}

// TestHandleConclusionVersionMismatch sends a CONCLUSION with version=3
// to test the unsupported version rejection path.
// Version 3 is < 5, so sendRejection sends a SHUTDOWN control packet (v4 style).
func TestHandleConclusionVersionMismatch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	// Build a CONCLUSION with version=3 (not 4 or 5)
	cifData := make([]byte, 48)
	binary.BigEndian.PutUint32(cifData[0:], 3) // Version 3
	binary.BigEndian.PutUint16(cifData[4:], 0)
	binary.BigEndian.PutUint16(cifData[6:], 0)
	binary.BigEndian.PutUint32(cifData[8:], 1000)
	binary.BigEndian.PutUint32(cifData[12:], 1500)
	binary.BigEndian.PutUint32(cifData[16:], 8192)
	binary.BigEndian.PutUint32(cifData[20:], uint32(packet.HandshakeTypeConclusion))
	binary.BigEndian.PutUint32(cifData[24:], 12345)
	binary.BigEndian.PutUint32(cifData[28:], cookie)

	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	// Version 3 < 5, so sendRejection sends SHUTDOWN (not error handshake)
	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected SHUTDOWN, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Version < 5 means the rejection is sent as a SHUTDOWN control packet
	if !resp.Header.IsControl || resp.Header.ControlType != packet.CtrlTypeShutdown {
		t.Errorf("expected SHUTDOWN for version 3 rejection, got control=%v type=%v",
			resp.Header.IsControl, resp.Header.ControlType)
	}
	resp.Release()
}

// TestHandleConclusionExtensionFieldZero sends a v5 CONCLUSION with ExtensionField=0
// to test the RejRogue rejection when no extensions are present.
func TestHandleConclusionExtensionFieldZero(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	cifData := make([]byte, 48)
	binary.BigEndian.PutUint32(cifData[0:], 5) // Version 5
	binary.BigEndian.PutUint16(cifData[4:], 0) // EncryptionField
	binary.BigEndian.PutUint16(cifData[6:], 0) // ExtensionField = 0
	binary.BigEndian.PutUint32(cifData[8:], 1000)
	binary.BigEndian.PutUint32(cifData[12:], 1500)
	binary.BigEndian.PutUint32(cifData[16:], 8192)
	binary.BigEndian.PutUint32(cifData[20:], uint32(packet.HandshakeTypeConclusion))
	binary.BigEndian.PutUint32(cifData[24:], 12345)
	binary.BigEndian.PutUint32(cifData[28:], cookie)

	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected rejection, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var respHS packet.CIFHandshake
	if err := resp.UnmarshalCIF(&respHS); err != nil {
		resp.Release()
		t.Fatalf("unmarshal: %v", err)
	}
	resp.Release()

	if respHS.HandshakeType != RejRogue {
		t.Errorf("expected RejRogue for ExtensionField=0, got type=%v", respHS.HandshakeType)
	}
}

// TestHandleConclusionOldSRTVersion sends a v5 CONCLUSION with an SRT version < 1.3.0
// to test the RejRogue rejection for old versions.
func TestHandleConclusionOldSRTVersion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	hs := &packet.CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 12345,
		SynCookie:                   cookie,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
		IsRequest:                   true,
		HasHS:                       true,
		SRTHS: &packet.CIFHandshakeExtension{
			SRTVersion:     0x010200, // 1.2.0 -- below 1.3.0
			SRTFlags:       testSRTFlags,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
		HasCongestion:  true,
		CongestionType: "live",
	}

	cifData, _ := hs.MarshalCIF()
	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected rejection, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var respHS packet.CIFHandshake
	if err := resp.UnmarshalCIF(&respHS); err != nil {
		resp.Release()
		t.Fatalf("unmarshal: %v", err)
	}
	resp.Release()

	if respHS.HandshakeType != RejRogue {
		t.Errorf("expected RejRogue for old SRT version, got type=%v", respHS.HandshakeType)
	}
}

// TestHandleConclusionGroupReject tests that a listener with GroupConnect=false
// rejects a connection that sends a group extension.
func TestHandleConclusionGroupReject(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.GroupConnect = false

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	hs := &packet.CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 12345,
		SynCookie:                   cookie,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
		IsRequest:                   true,
		HasHS:                       true,
		SRTHS: &packet.CIFHandshakeExtension{
			SRTVersion:     handshake.SRTVersion,
			SRTFlags:       testSRTFlags,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
		HasCongestion:  true,
		CongestionType: "live",
		HasGroup:       true,
		GroupID:         42,
		GroupType:       1, // broadcast
		GroupWeight:     0,
	}

	cifData, _ := hs.MarshalCIF()
	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected rejection, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var respHS packet.CIFHandshake
	if err := resp.UnmarshalCIF(&respHS); err != nil {
		resp.Release()
		t.Fatalf("unmarshal: %v", err)
	}
	resp.Release()

	if respHS.HandshakeType != RejGroup {
		t.Errorf("expected RejGroup, got type=%v", respHS.HandshakeType)
	}
}

// TestHandleConclusionGroupBalancingReject tests that GroupBalancing type is rejected
// even when GroupConnect is true.
func TestHandleConclusionGroupBalancingReject(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.GroupConnect = true

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	hs := &packet.CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 12345,
		SynCookie:                   cookie,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
		IsRequest:                   true,
		HasHS:                       true,
		SRTHS: &packet.CIFHandshakeExtension{
			SRTVersion:     handshake.SRTVersion,
			SRTFlags:       testSRTFlags,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
		HasCongestion:  true,
		CongestionType: "live",
		HasGroup:       true,
		GroupID:         42,
		GroupType:       uint8(GroupBalancing),
		GroupWeight:     0,
	}

	cifData, _ := hs.MarshalCIF()
	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected rejection, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var respHS packet.CIFHandshake
	if err := resp.UnmarshalCIF(&respHS); err != nil {
		resp.Release()
		t.Fatalf("unmarshal: %v", err)
	}
	resp.Release()

	if respHS.HandshakeType != RejGroup {
		t.Errorf("expected RejGroup for GroupBalancing, got type=%v", respHS.HandshakeType)
	}
}

// TestHandleConclusionV4 sends a v4 CONCLUSION to test the handleConclusionV4 path.
func TestHandleConclusionV4(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	// Build v4 CONCLUSION (UDT_DGRAM)
	cifData := make([]byte, 48)
	binary.BigEndian.PutUint32(cifData[0:], 4) // Version 4
	binary.BigEndian.PutUint16(cifData[4:], 0) // EncryptionField = 0
	binary.BigEndian.PutUint16(cifData[6:], 2) // ExtensionField = UDT_DGRAM
	binary.BigEndian.PutUint32(cifData[8:], 1000)
	binary.BigEndian.PutUint32(cifData[12:], 1500)
	binary.BigEndian.PutUint32(cifData[16:], 8192)
	binary.BigEndian.PutUint32(cifData[20:], uint32(packet.HandshakeTypeConclusion))
	binary.BigEndian.PutUint32(cifData[24:], 12345)
	binary.BigEndian.PutUint32(cifData[28:], cookie)

	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	// Should get a v4 CONCLUSION response (accepted)
	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected v4 conclusion response, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var respHS packet.CIFHandshake
	if err := resp.UnmarshalCIF(&respHS); err != nil {
		resp.Release()
		t.Fatalf("unmarshal: %v", err)
	}
	resp.Release()

	if respHS.HandshakeType != packet.HandshakeTypeConclusion {
		t.Errorf("expected CONCLUSION response, got type=%v", respHS.HandshakeType)
	}
	if respHS.Version != 4 {
		t.Errorf("expected version=4, got %d", respHS.Version)
	}

	// Accept the connection from the listener side
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		c, err := l.Accept()
		if err != nil {
			return
		}
		c.Close()
	}()

	select {
	case <-acceptDone:
	case <-time.After(2 * time.Second):
		t.Error("Accept did not return for v4 connection")
	}
}

// TestHandleConclusionV4BadType sends a v4 CONCLUSION with bad type field
// (EncryptionField != 0) to test the v4 UDT_DGRAM validation.
func TestHandleConclusionV4BadType(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	// v4 CONCLUSION with bad EncryptionField (should be 0 for UDT_DGRAM)
	cifData := make([]byte, 48)
	binary.BigEndian.PutUint32(cifData[0:], 4)
	binary.BigEndian.PutUint16(cifData[4:], 1) // EncryptionField = 1 (bad)
	binary.BigEndian.PutUint16(cifData[6:], 2) // ExtensionField = UDT_DGRAM
	binary.BigEndian.PutUint32(cifData[8:], 1000)
	binary.BigEndian.PutUint32(cifData[12:], 1500)
	binary.BigEndian.PutUint32(cifData[16:], 8192)
	binary.BigEndian.PutUint32(cifData[20:], uint32(packet.HandshakeTypeConclusion))
	binary.BigEndian.PutUint32(cifData[24:], 12345)
	binary.BigEndian.PutUint32(cifData[28:], cookie)

	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	// For v4 clients, rejection is sent as SHUTDOWN (not error handshake)
	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected SHUTDOWN for bad v4 type, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !resp.Header.IsControl || resp.Header.ControlType != packet.CtrlTypeShutdown {
		t.Errorf("expected SHUTDOWN for v4 rejection, got control=%v type=%v",
			resp.Header.IsControl, resp.Header.ControlType)
	}
	resp.Release()
}

// TestHandleConclusionV4MinVersionReject tests v4 rejection when MinVersion >= 1.3.0.
func TestHandleConclusionV4MinVersionReject(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.MinVersion = 0x010300

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	cifData := make([]byte, 48)
	binary.BigEndian.PutUint32(cifData[0:], 4)
	binary.BigEndian.PutUint16(cifData[4:], 0)
	binary.BigEndian.PutUint16(cifData[6:], 2)
	binary.BigEndian.PutUint32(cifData[8:], 1000)
	binary.BigEndian.PutUint32(cifData[12:], 1500)
	binary.BigEndian.PutUint32(cifData[16:], 8192)
	binary.BigEndian.PutUint32(cifData[20:], uint32(packet.HandshakeTypeConclusion))
	binary.BigEndian.PutUint32(cifData[24:], 12345)
	binary.BigEndian.PutUint32(cifData[28:], cookie)

	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected SHUTDOWN, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !resp.Header.IsControl || resp.Header.ControlType != packet.CtrlTypeShutdown {
		t.Errorf("expected SHUTDOWN for v4 version rejection, got type=%v", resp.Header.ControlType)
	}
	resp.Release()
}

// TestHandleConclusionInvalidMSS sends a v5 CONCLUSION with an out-of-range MSS.
func TestHandleConclusionInvalidMSS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	hs := &packet.CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     10, // way below MinMSS (76)
		MaxFlowWindowSize:           8192,
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 12345,
		SynCookie:                   cookie,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
		IsRequest:                   true,
		HasHS:                       true,
		SRTHS: &packet.CIFHandshakeExtension{
			SRTVersion:     handshake.SRTVersion,
			SRTFlags:       testSRTFlags,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
		HasCongestion:  true,
		CongestionType: "live",
	}

	cifData, _ := hs.MarshalCIF()
	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected rejection, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var respHS packet.CIFHandshake
	if err := resp.UnmarshalCIF(&respHS); err != nil {
		resp.Release()
		t.Fatalf("unmarshal: %v", err)
	}
	resp.Release()

	if respHS.HandshakeType != RejRogue {
		t.Errorf("expected RejRogue for invalid MSS, got type=%v", respHS.HandshakeType)
	}
}

// TestHandleConclusionInvalidFC sends a v5 CONCLUSION with FC < 2 to trigger rejection.
func TestHandleConclusionInvalidFC(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	hs := &packet.CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           1, // FC < 2
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 12345,
		SynCookie:                   cookie,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
		IsRequest:                   true,
		HasHS:                       true,
		SRTHS: &packet.CIFHandshakeExtension{
			SRTVersion:     handshake.SRTVersion,
			SRTFlags:       testSRTFlags,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
		HasCongestion:  true,
		CongestionType: "live",
	}

	cifData, _ := hs.MarshalCIF()
	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected rejection, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var respHS packet.CIFHandshake
	if err := resp.UnmarshalCIF(&respHS); err != nil {
		resp.Release()
		t.Fatalf("unmarshal: %v", err)
	}
	resp.Release()

	if respHS.HandshakeType != RejRogue {
		t.Errorf("expected RejRogue for FC<2, got type=%v", respHS.HandshakeType)
	}
}

// TestHandleConclusionStreamModeMismatch sends a v5 CONCLUSION with stream mode
// while the listener is in message mode (default).
func TestHandleConclusionStreamModeMismatch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	hs := &packet.CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 12345,
		SynCookie:                   cookie,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
		IsRequest:                   true,
		HasHS:                       true,
		SRTHS: &packet.CIFHandshakeExtension{
			SRTVersion:     handshake.SRTVersion,
			SRTFlags:       testSRTFlags | packet.FlagStream, // stream mode
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
		HasCongestion:  true,
		CongestionType: "live",
	}

	cifData, _ := hs.MarshalCIF()
	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected rejection, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var respHS packet.CIFHandshake
	if err := resp.UnmarshalCIF(&respHS); err != nil {
		resp.Release()
		t.Fatalf("unmarshal: %v", err)
	}
	resp.Release()

	if respHS.HandshakeType != RejMessageAPI {
		t.Errorf("expected RejMessageAPI, got type=%v", respHS.HandshakeType)
	}
}

// TestHandleConclusionFilterMismatchBadConfig sends a CONCLUSION with an invalid
// filter config to test the filter rejection path.
func TestHandleConclusionFilterMismatchBadConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.PacketFilter = "fec,cols:5"

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	hs := &packet.CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 12345,
		SynCookie:                   cookie,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
		IsRequest:                   true,
		HasHS:                       true,
		SRTHS: &packet.CIFHandshakeExtension{
			SRTVersion:     handshake.SRTVersion,
			SRTFlags:       testSRTFlags,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
		HasCongestion:  true,
		CongestionType: "live",
		HasFilter:      true,
		FilterConfig:   "totally_invalid_filter",
	}

	cifData, _ := hs.MarshalCIF()
	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected rejection, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var respHS packet.CIFHandshake
	if err := resp.UnmarshalCIF(&respHS); err != nil {
		resp.Release()
		t.Fatalf("unmarshal: %v", err)
	}
	resp.Release()

	if respHS.HandshakeType != RejFilter {
		t.Errorf("expected RejFilter, got type=%v", respHS.HandshakeType)
	}
}

// TestHandleConclusionDuplicateConclusion tests the duplicate CONCLUSION caching.
func TestHandleConclusionDuplicateConclusion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Accept connections in background so backlog doesn't fill
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	hs := &packet.CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               packet.HandshakeTypeConclusion,
		SRTSocketID:                 12345,
		SynCookie:                   cookie,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
		IsRequest:                   true,
		HasHS:                       true,
		SRTHS: &packet.CIFHandshakeExtension{
			SRTVersion:     handshake.SRTVersion,
			SRTFlags:       testSRTFlags,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
		HasCongestion:  true,
		CongestionType: "live",
	}

	cifData, _ := hs.MarshalCIF()
	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	// First send
	srcConn.WriteTo(raw, raddr)
	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("first conclusion response: %v", err)
	}

	resp1, _ := packet.Parse(respBuf[:n], raddr)
	var hs1 packet.CIFHandshake
	resp1.UnmarshalCIF(&hs1)
	resp1.Release()

	if hs1.HandshakeType != packet.HandshakeTypeConclusion {
		t.Fatalf("first response should be CONCLUSION, got %v", hs1.HandshakeType)
	}

	// Resend the same CONCLUSION (simulate retransmit)
	time.Sleep(50 * time.Millisecond)
	srcConn.WriteTo(raw, raddr)

	// Read responses, skipping non-handshake packets (keepalives, ACKs from accepted conn)
	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	var hs2 packet.CIFHandshake
	found := false
	for i := 0; i < 10; i++ {
		n, _, err = srcConn.ReadFrom(respBuf)
		if err != nil {
			break
		}
		resp2, parseErr := packet.Parse(respBuf[:n], raddr)
		if parseErr != nil {
			continue
		}
		if resp2.Header.IsControl && resp2.Header.ControlType == packet.CtrlTypeHandshake {
			if err := resp2.UnmarshalCIF(&hs2); err == nil {
				found = true
				resp2.Release()
				break
			}
		}
		resp2.Release()
	}

	if !found {
		t.Fatal("did not receive cached handshake response for duplicate CONCLUSION")
	}

	if hs2.HandshakeType != packet.HandshakeTypeConclusion {
		t.Errorf("duplicate response should be CONCLUSION, got %v", hs2.HandshakeType)
	}

	if hs1.SRTSocketID != hs2.SRTSocketID {
		t.Errorf("duplicate response should return same socket ID: first=%d, second=%d",
			hs1.SRTSocketID, hs2.SRTSocketID)
	}
}

// TestHandleConclusionV4InvalidMSS tests v4 CONCLUSION rejection for out-of-range MSS.
func TestHandleConclusionV4InvalidMSS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	cifData := make([]byte, 48)
	binary.BigEndian.PutUint32(cifData[0:], 4)
	binary.BigEndian.PutUint16(cifData[4:], 0)
	binary.BigEndian.PutUint16(cifData[6:], 2)
	binary.BigEndian.PutUint32(cifData[8:], 1000)
	binary.BigEndian.PutUint32(cifData[12:], 50000) // MSS too large
	binary.BigEndian.PutUint32(cifData[16:], 8192)
	binary.BigEndian.PutUint32(cifData[20:], uint32(packet.HandshakeTypeConclusion))
	binary.BigEndian.PutUint32(cifData[24:], 12345)
	binary.BigEndian.PutUint32(cifData[28:], cookie)

	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected SHUTDOWN, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !resp.Header.IsControl || resp.Header.ControlType != packet.CtrlTypeShutdown {
		t.Errorf("expected SHUTDOWN for v4 MSS rejection, got type=%v", resp.Header.ControlType)
	}
	resp.Release()
}

// TestHandleConclusionV4InvalidFC tests v4 CONCLUSION rejection for FC < 2.
func TestHandleConclusionV4InvalidFC(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	cifData := make([]byte, 48)
	binary.BigEndian.PutUint32(cifData[0:], 4)
	binary.BigEndian.PutUint16(cifData[4:], 0)
	binary.BigEndian.PutUint16(cifData[6:], 2)
	binary.BigEndian.PutUint32(cifData[8:], 1000)
	binary.BigEndian.PutUint32(cifData[12:], 1500)
	binary.BigEndian.PutUint32(cifData[16:], 1) // FC too small
	binary.BigEndian.PutUint32(cifData[20:], uint32(packet.HandshakeTypeConclusion))
	binary.BigEndian.PutUint32(cifData[24:], 12345)
	binary.BigEndian.PutUint32(cifData[28:], cookie)

	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	srcConn.WriteTo(raw, raddr)

	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("expected SHUTDOWN, got error: %v", err)
	}

	resp, err := packet.Parse(respBuf[:n], raddr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !resp.Header.IsControl || resp.Header.ControlType != packet.CtrlTypeShutdown {
		t.Errorf("expected SHUTDOWN for v4 FC rejection, got type=%v", resp.Header.ControlType)
	}
	resp.Release()
}

// TestCleanupPending verifies that stale pending and concluded entries are cleaned up.
func TestCleanupPending(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 100 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Insert stale pending entry
	l.pendingMu.Lock()
	l.pending[99999] = &pendingConn{
		callerSocketID: 99999,
		createdAt:      time.Now().Add(-5 * time.Second),
	}
	l.pending[88888] = &pendingConn{
		callerSocketID: 88888,
		createdAt:      time.Now(),
	}
	l.pendingMu.Unlock()

	// Insert stale concluded entry
	l.concludedMu.Lock()
	staleResp := packet.New(nil)
	staleResp.SetData([]byte{0, 0, 0, 0})
	l.concluded[77777] = &concludedConn{
		response:  staleResp,
		createdAt: time.Now().Add(-15 * time.Second),
	}
	freshResp := packet.New(nil)
	freshResp.SetData([]byte{0, 0, 0, 0})
	l.concluded[66666] = &concludedConn{
		response:  freshResp,
		createdAt: time.Now(),
	}
	l.concludedMu.Unlock()

	l.cleanupPending()

	l.pendingMu.Lock()
	if _, exists := l.pending[99999]; exists {
		t.Error("stale pending entry 99999 should have been cleaned up")
	}
	if _, exists := l.pending[88888]; !exists {
		t.Error("fresh pending entry 88888 should still exist")
	}
	l.pendingMu.Unlock()

	l.concludedMu.Lock()
	if _, exists := l.concluded[77777]; exists {
		t.Error("stale concluded entry 77777 should have been cleaned up")
	}
	if _, exists := l.concluded[66666]; !exists {
		t.Error("fresh concluded entry 66666 should still exist")
	}
	l.concludedMu.Unlock()
}

// TestHandleHandshakeMalformedPacket sends a truncated packet to test the
// unmarshal error path in handleHandshake.
func TestHandleHandshakeMalformedPacket(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	// Build a control packet header (handshake type) with truncated CIF
	hdr := make([]byte, 16)
	binary.BigEndian.PutUint16(hdr[0:], 0x8000) // IsControl + CtrlTypeHandshake
	binary.BigEndian.PutUint16(hdr[2:], 0)
	binary.BigEndian.PutUint32(hdr[4:], 0)
	binary.BigEndian.PutUint32(hdr[8:], 0)
	binary.BigEndian.PutUint32(hdr[12:], 0) // DestinationSocketID = 0

	// Only 10 bytes of CIF data (need 48)
	raw := append(hdr, make([]byte, 10)...)
	conn.WriteTo(raw, raddr)

	// No response expected
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	respBuf := make([]byte, 2048)
	_, _, err = conn.ReadFrom(respBuf)
	if err == nil {
		t.Error("expected timeout (no response) for malformed handshake, but got a response")
	}
}

// TestServerHandlerNilPublish tests the server handler path when HandlePublish is nil.
func TestServerHandlerNilPublish(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	var connectCalled atomic.Bool

	s := &Server{
		Addr:   "127.0.0.1:0",
		Config: &cfg,
		HandleConnect: func(req ConnRequest) ConnType {
			connectCalled.Store(true)
			return Publish
		},
		HandlePublish: nil, // Intentionally nil
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := s.ln.Addr().String()
	go s.Serve()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	client, err := Dial(addr, dialCfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	client.Close()

	if !connectCalled.Load() {
		t.Error("HandleConnect should have been called")
	}

	s.Shutdown()
}

// TestServerHandlerNilSubscribe tests the server handler path when HandleSubscribe is nil.
func TestServerHandlerNilSubscribe(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	var connectCalled atomic.Bool

	s := &Server{
		Addr:   "127.0.0.1:0",
		Config: &cfg,
		HandleConnect: func(req ConnRequest) ConnType {
			connectCalled.Store(true)
			return Subscribe
		},
		HandleSubscribe: nil, // Intentionally nil
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := s.ln.Addr().String()
	go s.Serve()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	client, err := Dial(addr, dialCfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	client.Close()

	if !connectCalled.Load() {
		t.Error("HandleConnect should have been called")
	}

	s.Shutdown()
}

// TestServerListenAndServeShutdownDuringAccept tests that ListenAndServe returns
// ErrServerClosed when shutdown is called while Accept is blocking.
func TestServerListenAndServeShutdownDuringAccept(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	s := &Server{
		Addr:   "127.0.0.1:0",
		Config: &cfg,
		HandleConnect: func(req ConnRequest) ConnType {
			return Publish
		},
		HandlePublish: func(conn *Conn) {
			buf := make([]byte, 1500)
			conn.Read(buf)
		},
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- s.ListenAndServe()
	}()

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown while no connections are active
	s.Shutdown()

	select {
	case err := <-serveErr:
		if err != ErrServerClosed {
			t.Errorf("ListenAndServe: got %v, want ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("ListenAndServe did not return after Shutdown")
	}
}

// TestServerListenAndServeInvalidAddr tests that ListenAndServe returns an error
// for an invalid address.
func TestServerListenAndServeInvalidAddr(t *testing.T) {
	s := &Server{
		Addr: "invalid:address:too:many:colons",
	}

	err := s.ListenAndServe()
	if err == nil {
		t.Error("ListenAndServe should fail with invalid address")
	}
}

// TestHandleConclusionV4DuplicateConclusion tests the duplicate CONCLUSION cache
// for v4 handshakes.
func TestHandleConclusionV4DuplicateConclusion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Accept connections in background
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	cookie, srcConn := doInduction(t, l.Addr().String())
	defer srcConn.Close()

	raddr, _ := net.ResolveUDPAddr("udp", l.Addr().String())

	// v4 CONCLUSION
	cifData := make([]byte, 48)
	binary.BigEndian.PutUint32(cifData[0:], 4)
	binary.BigEndian.PutUint16(cifData[4:], 0)
	binary.BigEndian.PutUint16(cifData[6:], 2) // UDT_DGRAM
	binary.BigEndian.PutUint32(cifData[8:], 1000)
	binary.BigEndian.PutUint32(cifData[12:], 1500)
	binary.BigEndian.PutUint32(cifData[16:], 8192)
	binary.BigEndian.PutUint32(cifData[20:], uint32(packet.HandshakeTypeConclusion))
	binary.BigEndian.PutUint32(cifData[24:], 12345)
	binary.BigEndian.PutUint32(cifData[28:], cookie)

	p := packet.NewControl(raddr, packet.CtrlTypeHandshake, 0, 0)
	p.SetData(cifData)
	raw, _ := p.MarshalTo()
	p.Release()

	// First send
	srcConn.WriteTo(raw, raddr)
	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := srcConn.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("first v4 conclusion response: %v", err)
	}

	resp1, _ := packet.Parse(respBuf[:n], raddr)
	var hs1 packet.CIFHandshake
	resp1.UnmarshalCIF(&hs1)
	resp1.Release()

	if hs1.HandshakeType != packet.HandshakeTypeConclusion {
		t.Fatalf("expected v4 CONCLUSION, got %v", hs1.HandshakeType)
	}

	// Resend (simulate retransmit)
	time.Sleep(50 * time.Millisecond)
	srcConn.WriteTo(raw, raddr)

	// Drain non-handshake packets (keepalives etc from accepted connection)
	srcConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	var hs2 packet.CIFHandshake
	found := false
	for i := 0; i < 10; i++ {
		n, _, err = srcConn.ReadFrom(respBuf)
		if err != nil {
			break
		}
		resp2, parseErr := packet.Parse(respBuf[:n], raddr)
		if parseErr != nil {
			continue
		}
		if resp2.Header.IsControl && resp2.Header.ControlType == packet.CtrlTypeHandshake {
			if err := resp2.UnmarshalCIF(&hs2); err == nil {
				found = true
				resp2.Release()
				break
			}
		}
		resp2.Release()
	}

	if !found {
		t.Fatal("did not receive cached v4 handshake response for duplicate CONCLUSION")
	}

	if hs2.HandshakeType != packet.HandshakeTypeConclusion {
		t.Errorf("duplicate v4 response should be CONCLUSION, got %v", hs2.HandshakeType)
	}

	if hs1.SRTSocketID != hs2.SRTSocketID {
		t.Errorf("v4 duplicate response should return same socket ID: first=%d, second=%d",
			hs1.SRTSocketID, hs2.SRTSocketID)
	}
}
