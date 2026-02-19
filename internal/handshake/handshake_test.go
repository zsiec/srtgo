package handshake

import (
	"net"
	"testing"

	"github.com/zsiec/srtgo/internal/packet"
)

func TestSYNCookieGenerateAndVerify(t *testing.T) {
	sc, err := NewSYNCookie("127.0.0.1:6000")
	if err != nil {
		t.Fatalf("NewSYNCookie: %v", err)
	}

	srcAddr := "192.168.1.100:12345"
	cookie := sc.Generate(srcAddr)

	if cookie == 0 {
		t.Error("cookie should not be zero")
	}

	if !sc.Verify(srcAddr, cookie) {
		t.Error("cookie should verify for same source address")
	}

	// Different source should fail
	if sc.Verify("10.0.0.1:9999", cookie) {
		t.Error("cookie should not verify for different source address")
	}

	// Wrong cookie value should fail
	if sc.Verify(srcAddr, cookie+1) {
		t.Error("wrong cookie value should not verify")
	}
}

func TestSYNCookieDeterministic(t *testing.T) {
	sc, err := NewSYNCookie("127.0.0.1:6000")
	if err != nil {
		t.Fatalf("NewSYNCookie: %v", err)
	}

	srcAddr := "192.168.1.100:12345"
	cookie1 := sc.Generate(srcAddr)
	cookie2 := sc.Generate(srcAddr)

	// Within the same time window, cookies should be identical
	if cookie1 != cookie2 {
		t.Errorf("cookies should be deterministic: %d != %d", cookie1, cookie2)
	}
}

func TestGenerateSocketID(t *testing.T) {
	seen := make(map[uint32]bool)
	for range 100 {
		id, err := GenerateSocketID()
		if err != nil {
			t.Fatalf("GenerateSocketID: %v", err)
		}
		if id == 0 {
			t.Error("socket ID should not be zero")
		}
		seen[id] = true
	}
	// Should generate diverse values
	if len(seen) < 90 {
		t.Errorf("expected diverse socket IDs, got %d unique out of 100", len(seen))
	}
}

func TestGenerateISN(t *testing.T) {
	for range 100 {
		isn, err := GenerateISN()
		if err != nil {
			t.Fatalf("GenerateISN: %v", err)
		}
		if isn > 0x7FFFFFFF {
			t.Errorf("ISN should be 31-bit, got %#x", isn)
		}
	}
}

func TestBuildInduction(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6000}
	p := BuildInduction(42, 1000, 1500, 8192, addr)
	defer p.Release()

	if !p.Header.IsControl {
		t.Error("should be control packet")
	}
	if p.Header.ControlType != packet.CtrlTypeHandshake {
		t.Errorf("type: got %v, want HANDSHAKE", p.Header.ControlType)
	}

	var hs packet.CIFHandshake
	if err := p.UnmarshalCIF(&hs); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if hs.Version != 4 {
		t.Errorf("Version: got %d, want 4", hs.Version)
	}
	if hs.HandshakeType != packet.HandshakeTypeInduction {
		t.Errorf("Type: got %v, want INDUCTION", hs.HandshakeType)
	}
	if hs.SRTSocketID != 42 {
		t.Errorf("SocketID: got %d, want 42", hs.SRTSocketID)
	}
	if hs.InitialPacketSequenceNumber != 1000 {
		t.Errorf("ISN: got %d, want 1000", hs.InitialPacketSequenceNumber)
	}
	if hs.SynCookie != 0 {
		t.Errorf("SynCookie: got %d, want 0", hs.SynCookie)
	}
}

func TestBuildInductionResponse(t *testing.T) {
	callerAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 12345}
	listenerAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6000}

	callerHS := &packet.CIFHandshake{
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		SRTSocketID:                 42,
	}

	p := BuildInductionResponse(callerHS, 0xDEADBEEF, listenerAddr, callerAddr, 0)
	defer p.Release()

	var hs packet.CIFHandshake
	if err := p.UnmarshalCIF(&hs); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if hs.Version != 5 {
		t.Errorf("Version: got %d, want 5", hs.Version)
	}
	if hs.ExtensionField != SRTMagic {
		t.Errorf("ExtensionField: got %#x, want %#x", hs.ExtensionField, SRTMagic)
	}
	if hs.SynCookie != 0xDEADBEEF {
		t.Errorf("SynCookie: got %#x, want 0xDEADBEEF", hs.SynCookie)
	}
	if hs.HandshakeType != packet.HandshakeTypeInduction {
		t.Errorf("Type: got %v, want INDUCTION", hs.HandshakeType)
	}
}

func TestBuildConclusion(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6000}

	p := BuildConclusion(42, 1000, 1500, 8192, 0xDEADBEEF, "live/test", 120, 120, 0, "live", "", 0, 0, 0, addr, nil)
	defer p.Release()

	var hs packet.CIFHandshake
	if err := p.UnmarshalCIF(&hs); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if hs.Version != 5 {
		t.Errorf("Version: got %d, want 5", hs.Version)
	}
	if hs.HandshakeType != packet.HandshakeTypeConclusion {
		t.Errorf("Type: got %v, want CONCLUSION", hs.HandshakeType)
	}
	if hs.SynCookie != 0xDEADBEEF {
		t.Errorf("SynCookie: got %#x, want 0xDEADBEEF", hs.SynCookie)
	}
	if !hs.HasHS {
		t.Error("expected HasHS=true")
	}
	if !hs.IsRequest {
		t.Error("expected IsRequest=true")
	}
	if hs.SRTHS.SRTVersion != SRTVersion {
		t.Errorf("SRTVersion: got %#x, want %#x", hs.SRTHS.SRTVersion, SRTVersion)
	}
	if hs.SRTHS.RecvTSBPDDelay != 120 {
		t.Errorf("RecvTSBPDDelay: got %d, want 120", hs.SRTHS.RecvTSBPDDelay)
	}
	if !hs.HasSID {
		t.Error("expected HasSID=true")
	}
	if hs.StreamID != "live/test" {
		t.Errorf("StreamID: got %q, want %q", hs.StreamID, "live/test")
	}
	if !hs.HasCongestion {
		t.Error("expected HasCongestion=true")
	}
	if hs.CongestionType != "live" {
		t.Errorf("CongestionType: got %q, want %q", hs.CongestionType, "live")
	}
}

func TestBuildConclusionResponse(t *testing.T) {
	callerAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 12345}

	p := BuildConclusionResponse(99, 2000, 1500, 8192, 42, 120, 120, 0, "live", "", 0, 0, 0, callerAddr, nil)
	defer p.Release()

	var hs packet.CIFHandshake
	if err := p.UnmarshalCIF(&hs); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if hs.HandshakeType != packet.HandshakeTypeConclusion {
		t.Errorf("Type: got %v, want CONCLUSION", hs.HandshakeType)
	}
	if hs.SRTSocketID != 99 {
		t.Errorf("SocketID: got %d, want 99", hs.SRTSocketID)
	}
	if hs.SynCookie != 0 {
		t.Errorf("SynCookie: got %d, want 0 (cleared for response)", hs.SynCookie)
	}
	if hs.IsRequest {
		t.Error("expected IsRequest=false for response")
	}
	if !hs.HasCongestion {
		t.Error("expected HasCongestion=true in response")
	}
	if hs.CongestionType != "live" {
		t.Errorf("CongestionType: got %q, want %q", hs.CongestionType, "live")
	}
}

func TestNegotiateLatency(t *testing.T) {
	tests := []struct {
		callerRecv, callerSend     uint16
		listenerRecv, listenerSend uint16
		wantRecv, wantSend         uint16
	}{
		{120, 120, 120, 120, 120, 120},
		{120, 120, 200, 200, 200, 200},
		{300, 100, 100, 300, 300, 300},
		{0, 0, 120, 120, 120, 120},
	}

	for _, tt := range tests {
		recv, send := NegotiateLatency(tt.callerRecv, tt.callerSend, tt.listenerRecv, tt.listenerSend)
		if recv != tt.wantRecv || send != tt.wantSend {
			t.Errorf("NegotiateLatency(%d,%d,%d,%d) = (%d,%d), want (%d,%d)",
				tt.callerRecv, tt.callerSend, tt.listenerRecv, tt.listenerSend,
				recv, send, tt.wantRecv, tt.wantSend)
		}
	}
}

func TestNegotiateMSS(t *testing.T) {
	if NegotiateMSS(1500, 1400) != 1400 {
		t.Error("should pick smaller MSS")
	}
	if NegotiateMSS(1200, 1500) != 1200 {
		t.Error("should pick smaller MSS")
	}
	if NegotiateMSS(1500, 1500) != 1500 {
		t.Error("equal MSS should return same value")
	}
}

func TestBuildConclusionCustomFlags(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6000}

	// Test with FlagStream set (buffer/stream mode)
	flags := defaultFlags | packet.FlagStream
	p := BuildConclusion(1, 0, 1500, 8192, 0, "", 120, 120, flags, "live", "", 0, 0, 0, addr, nil)
	defer p.Release()

	var hs packet.CIFHandshake
	if err := p.UnmarshalCIF(&hs); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if !hs.HasHS {
		t.Fatal("expected HasHS=true")
	}
	if hs.SRTHS.SRTFlags&packet.FlagStream == 0 {
		t.Error("FlagStream should be set in custom flags")
	}
	// Other required flags should still be present
	if hs.SRTHS.SRTFlags&packet.FlagTSBPDSend == 0 {
		t.Error("FlagTSBPDSend should still be set")
	}
}

func TestBuildConclusionResponseCustomFlags(t *testing.T) {
	callerAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 12345}

	flags := defaultFlags | packet.FlagStream
	p := BuildConclusionResponse(99, 2000, 1500, 8192, 42, 120, 120, flags, "live", "", 0, 0, 0, callerAddr, nil)
	defer p.Release()

	var hs packet.CIFHandshake
	if err := p.UnmarshalCIF(&hs); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if hs.SRTHS.SRTFlags&packet.FlagStream == 0 {
		t.Error("FlagStream should be set in response custom flags")
	}
}

func TestBuildConclusionDefaultFlags(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6000}

	// Pass 0 for flags — should use defaultFlags (no FlagStream)
	p := BuildConclusion(1, 0, 1500, 8192, 0, "", 120, 120, 0, "live", "", 0, 0, 0, addr, nil)
	defer p.Release()

	var hs packet.CIFHandshake
	if err := p.UnmarshalCIF(&hs); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if hs.SRTHS.SRTFlags&packet.FlagStream != 0 {
		t.Error("FlagStream should NOT be set with default flags")
	}
	if hs.SRTHS.SRTFlags&packet.FlagTSBPDSend == 0 {
		t.Error("FlagTSBPDSend should be set with default flags")
	}
}

func TestBuildConclusionNoStreamID(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6000}
	p := BuildConclusion(1, 0, 1500, 8192, 0, "", 120, 120, 0, "live", "", 0, 0, 0, addr, nil)
	defer p.Release()

	var hs packet.CIFHandshake
	if err := p.UnmarshalCIF(&hs); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if hs.HasSID {
		t.Error("should not have SID when stream ID is empty")
	}
}

func TestFullHandshakeFlow(t *testing.T) {
	// Simulate the full 4-step handshake
	callerAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 12345}
	listenerAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6000}

	callerSocketID, _ := GenerateSocketID()
	callerISN, _ := GenerateISN()
	listenerSocketID, _ := GenerateSocketID()
	listenerISN, _ := GenerateISN()

	sc, _ := NewSYNCookie(listenerAddr.String())

	// Step 1: Caller sends INDUCTION
	indPkt := BuildInduction(callerSocketID, callerISN, 1500, 8192, listenerAddr)
	var indHS packet.CIFHandshake
	indPkt.UnmarshalCIF(&indHS)

	// Step 2: Listener responds with cookie
	cookie := sc.Generate(callerAddr.String())
	indRespPkt := BuildInductionResponse(&indHS, cookie, listenerAddr, callerAddr, 0)
	var indRespHS packet.CIFHandshake
	indRespPkt.UnmarshalCIF(&indRespHS)

	// Verify cookie and magic
	if indRespHS.SynCookie == 0 {
		t.Error("response should have SYN cookie")
	}
	if indRespHS.ExtensionField != SRTMagic {
		t.Error("response should have SRT magic")
	}

	// Step 3: Caller sends CONCLUSION
	conclPkt := BuildConclusion(callerSocketID, callerISN, 1500, 8192,
		indRespHS.SynCookie, "live/test", 120, 120, 0, "live", "", 0, 0, 0, listenerAddr, nil)
	var conclHS packet.CIFHandshake
	conclPkt.UnmarshalCIF(&conclHS)

	// Verify cookie
	if !sc.Verify(callerAddr.String(), conclHS.SynCookie) {
		t.Error("CONCLUSION cookie should verify")
	}

	// Step 4: Listener sends CONCLUSION response
	recv, send := NegotiateLatency(
		conclHS.SRTHS.RecvTSBPDDelay, conclHS.SRTHS.SendTSBPDDelay,
		120, 120,
	)
	mss := NegotiateMSS(conclHS.MaxTransmissionUnitSize, 1500)

	conclRespPkt := BuildConclusionResponse(listenerSocketID, listenerISN,
		mss, 8192, callerSocketID, recv, send, 0, "live", "", 0, 0, 0, callerAddr, nil)
	var conclRespHS packet.CIFHandshake
	conclRespPkt.UnmarshalCIF(&conclRespHS)

	if conclRespHS.HandshakeType != packet.HandshakeTypeConclusion {
		t.Error("response should be CONCLUSION")
	}
	if conclRespHS.SRTSocketID != listenerSocketID {
		t.Error("response should contain listener's socket ID")
	}

	// Cleanup
	indPkt.Release()
	indRespPkt.Release()
	conclPkt.Release()
	conclRespPkt.Release()
}

// ---- HSv4 builder tests ----

func TestBuildConclusionV4(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6000}

	p := BuildConclusionV4(42, 1000, 1500, 8192, 0xDEADBEEF, addr)
	defer p.Release()

	var hs packet.CIFHandshake
	if err := p.UnmarshalCIF(&hs); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if hs.Version != 4 {
		t.Errorf("Version = %d, want 4", hs.Version)
	}
	if hs.HandshakeType != packet.HandshakeTypeConclusion {
		t.Errorf("HandshakeType = %v, want CONCLUSION", hs.HandshakeType)
	}
	if hs.SRTSocketID != 42 {
		t.Errorf("SRTSocketID = %d, want 42", hs.SRTSocketID)
	}
	if hs.SynCookie != 0xDEADBEEF {
		t.Errorf("SynCookie = %#x, want 0xDEADBEEF", hs.SynCookie)
	}
	if hs.InitialPacketSequenceNumber != 1000 {
		t.Errorf("ISN = %d, want 1000", hs.InitialPacketSequenceNumber)
	}
	// HSv4: no extensions
	if hs.HasHS {
		t.Error("HSv4 should not have HSREQ extension")
	}
	if hs.HasKM {
		t.Error("HSv4 should not have KMREQ extension")
	}
}

func TestBuildExtHSREQ_RoundTrip(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6000}

	p := BuildExtHSREQ(42, SRTVersion, defaultFlags, 120, addr)
	defer p.Release()

	if !p.Header.IsControl {
		t.Fatal("should be a control packet")
	}
	if p.Header.ControlType != packet.CtrlTypeUser {
		t.Errorf("ControlType = %v, want User (0x7FFF)", p.Header.ControlType)
	}
	if p.Header.SubType != packet.ExtTypeHSReq {
		t.Errorf("SubType = %v, want HSReq", p.Header.SubType)
	}
	if p.Header.DestinationSocketID != 42 {
		t.Errorf("DestSocketID = %d, want 42", p.Header.DestinationSocketID)
	}

	// Parse back
	version, flags, latency, err := ParseExtHSREQ(p.Data)
	if err != nil {
		t.Fatalf("ParseExtHSREQ: %v", err)
	}
	if version != SRTVersion {
		t.Errorf("Version = %#x, want %#x", version, SRTVersion)
	}
	if flags != defaultFlags {
		t.Errorf("Flags = %#x, want %#x", flags, defaultFlags)
	}
	if latency != 120 {
		t.Errorf("Latency = %d, want 120", latency)
	}
}

func TestBuildExtHSRSP(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6000}

	p := BuildExtHSRSP(99, SRTVersion, packet.FlagTSBPDRecv|packet.FlagRexmit, 200, addr)
	defer p.Release()

	if p.Header.SubType != packet.ExtTypeHSRsp {
		t.Errorf("SubType = %v, want HSRsp", p.Header.SubType)
	}

	version, flags, latency, err := ParseExtHSREQ(p.Data) // same format as HSREQ
	if err != nil {
		t.Fatalf("ParseExtHSREQ: %v", err)
	}
	if version != SRTVersion {
		t.Errorf("Version = %#x, want %#x", version, SRTVersion)
	}
	if flags&packet.FlagTSBPDRecv == 0 {
		t.Error("FlagTSBPDRecv should be set")
	}
	if latency != 200 {
		t.Errorf("Latency = %d, want 200", latency)
	}
}

func TestBuildExtKMREQ(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6000}

	km := &packet.CIFKeyMaterial{
		Version:             1,
		PacketType:          2,
		KeyBasedEncryption:  packet.EncryptionEven,
		KLen:                16,
		Cipher:              2,
		Authentication:      0,
		StreamEncapsulation: 2,
		Salt:                make([]byte, 16),
		Wrap:                make([]byte, 24),
	}

	p := BuildExtKMREQ(42, km, addr)
	defer p.Release()

	if p.Header.SubType != packet.ExtTypeKMReq {
		t.Errorf("SubType = %v, want KMReq", p.Header.SubType)
	}
	if len(p.Data) == 0 {
		t.Error("KMREQ payload should not be empty")
	}
}

func TestBuildExtKMRSP(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6000}

	km := &packet.CIFKeyMaterial{
		Version:             1,
		PacketType:          2,
		KeyBasedEncryption:  packet.EncryptionEven,
		KLen:                16,
		Cipher:              2,
		Authentication:      0,
		StreamEncapsulation: 2,
		Salt:                make([]byte, 16),
		Wrap:                make([]byte, 24),
	}

	p := BuildExtKMRSP(99, km, addr)
	defer p.Release()

	if p.Header.SubType != packet.ExtTypeKMRsp {
		t.Errorf("SubType = %v, want KMRsp", p.Header.SubType)
	}
}

func TestParseExtHSREQ_TooShort(t *testing.T) {
	_, _, _, err := ParseExtHSREQ([]byte{0, 1, 2})
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestParseExtHSREQ_SingleLatency(t *testing.T) {
	// HSv4 uses single 16-bit latency in lower bits of the third uint32
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6000}

	// Build with a specific latency and verify it round-trips
	p := BuildExtHSREQ(42, SRTVersion, defaultFlags, 250, addr)
	defer p.Release()

	_, _, latency, err := ParseExtHSREQ(p.Data)
	if err != nil {
		t.Fatalf("ParseExtHSREQ: %v", err)
	}
	if latency != 250 {
		t.Errorf("Latency = %d, want 250", latency)
	}
}
