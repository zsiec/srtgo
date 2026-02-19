package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

// Test header marshal/unmarshal against known byte patterns from the
// Haivision SRT implementation.

func TestHeaderDataPacketRoundtrip(t *testing.T) {
	original := Header{
		IsControl:           false,
		SequenceNumber:      0x00123456,
		PacketPosition:      PositionSingle, // 11b
		Order:               true,
		Encryption:          EncryptionEven, // 01b
		Retransmitted:       false,
		MessageNumber:       0x00ABCDEF,
		Timestamp:           0xDEADBEEF,
		DestinationSocketID: 0x12345678,
	}

	var buf [HeaderSize]byte
	original.Marshal(buf[:])

	var parsed Header
	if err := parsed.Unmarshal(buf[:]); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.IsControl {
		t.Error("expected data packet")
	}
	if parsed.SequenceNumber != original.SequenceNumber {
		t.Errorf("SequenceNumber: got %#x, want %#x", parsed.SequenceNumber, original.SequenceNumber)
	}
	if parsed.PacketPosition != original.PacketPosition {
		t.Errorf("PacketPosition: got %d, want %d", parsed.PacketPosition, original.PacketPosition)
	}
	if parsed.Order != original.Order {
		t.Errorf("Order: got %v, want %v", parsed.Order, original.Order)
	}
	if parsed.Encryption != original.Encryption {
		t.Errorf("Encryption: got %d, want %d", parsed.Encryption, original.Encryption)
	}
	if parsed.Retransmitted != original.Retransmitted {
		t.Errorf("Retransmitted: got %v, want %v", parsed.Retransmitted, original.Retransmitted)
	}
	if parsed.MessageNumber != original.MessageNumber {
		t.Errorf("MessageNumber: got %#x, want %#x", parsed.MessageNumber, original.MessageNumber)
	}
	if parsed.Timestamp != original.Timestamp {
		t.Errorf("Timestamp: got %#x, want %#x", parsed.Timestamp, original.Timestamp)
	}
	if parsed.DestinationSocketID != original.DestinationSocketID {
		t.Errorf("DestinationSocketID: got %#x, want %#x", parsed.DestinationSocketID, original.DestinationSocketID)
	}
}

func TestHeaderControlPacketRoundtrip(t *testing.T) {
	original := Header{
		IsControl:           true,
		ControlType:         CtrlTypeACK,
		SubType:             SubTypeNone,
		TypeSpecific:        42, // ACK sequence number
		Timestamp:           0x11223344,
		DestinationSocketID: 0xAABBCCDD,
	}

	var buf [HeaderSize]byte
	original.Marshal(buf[:])

	// Verify first byte has control bit set
	if buf[0]&0x80 == 0 {
		t.Error("control bit not set in first byte")
	}

	var parsed Header
	if err := parsed.Unmarshal(buf[:]); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !parsed.IsControl {
		t.Error("expected control packet")
	}
	if parsed.ControlType != original.ControlType {
		t.Errorf("ControlType: got %v, want %v", parsed.ControlType, original.ControlType)
	}
	if parsed.TypeSpecific != original.TypeSpecific {
		t.Errorf("TypeSpecific: got %d, want %d", parsed.TypeSpecific, original.TypeSpecific)
	}
}

// TestHeaderDataPacketBitLayout verifies exact bit positions match the
// Haivision SRT implementation:
//
//	Word 0: [0]=control(0), [30:0]=seqno
//	Word 1: [31:30]=PP, [29]=O, [28:27]=KK, [26]=R, [25:0]=msgno
//	Word 2: timestamp
//	Word 3: destination socket ID
func TestHeaderDataPacketBitLayout(t *testing.T) {
	h := Header{
		IsControl:           false,
		SequenceNumber:      0x7FFFFFFF,    // max 31-bit
		PacketPosition:      PositionFirst, // 10b
		Order:               true,          // 1
		Encryption:          EncryptionOdd, // 10b
		Retransmitted:       true,          // 1
		MessageNumber:       0x03FFFFFF,    // max 26-bit
		Timestamp:           0xFFFFFFFF,
		DestinationSocketID: 0xFFFFFFFF,
	}

	var buf [HeaderSize]byte
	h.Marshal(buf[:])

	// Word 0: bit 31 should be 0 (data packet), bits 30-0 = 0x7FFFFFFF
	word0 := binary.BigEndian.Uint32(buf[0:])
	if word0 != 0x7FFFFFFF {
		t.Errorf("word0: got %#08x, want %#08x", word0, uint32(0x7FFFFFFF))
	}

	// Word 1: PP=10b(bits 31-30), O=1(bit 29), KK=10b(bits 28-27), R=1(bit 26), msgno=0x03FFFFFF
	// = 1010_1100_0000_0000_0000_0000_0000_0000 | 0x03FFFFFF
	// PP=10 -> 0x80000000, O=1 -> 0x20000000, KK=10 -> 0x10000000, R=1 -> 0x04000000
	// = 0xB4000000 | 0x03FFFFFF = 0xB7FFFFFF
	word1 := binary.BigEndian.Uint32(buf[4:])
	expected1 := uint32(0x80000000 | 0x20000000 | 0x10000000 | 0x04000000 | 0x03FFFFFF)
	if word1 != expected1 {
		t.Errorf("word1: got %#08x, want %#08x", word1, expected1)
	}
}

// TestHeaderControlPacketBitLayout verifies the control packet header layout.
func TestHeaderControlPacketBitLayout(t *testing.T) {
	h := Header{
		IsControl:           true,
		ControlType:         CtrlTypeHandshake, // 0x0000
		SubType:             SubTypeNone,       // 0x0000
		TypeSpecific:        0,
		Timestamp:           1000000,
		DestinationSocketID: 0,
	}

	var buf [HeaderSize]byte
	h.Marshal(buf[:])

	// Word 0: bit 15 set (control), control type = 0x0000, subtype = 0x0000
	word0 := binary.BigEndian.Uint16(buf[0:])
	if word0 != 0x8000 {
		t.Errorf("word0 high: got %#04x, want %#04x", word0, uint16(0x8000))
	}
}

func TestHeaderUnmarshalTooShort(t *testing.T) {
	var h Header
	err := h.Unmarshal([]byte{0, 1, 2})
	if err == nil {
		t.Error("expected error for short data")
	}
}

// --- Packet tests ---

func TestParseDataPacket(t *testing.T) {
	// Build a raw packet: header + payload
	var raw [HeaderSize + 4]byte
	// Data packet: seq=1, PP=single(11b), O=0, KK=00, R=0, msg=1
	binary.BigEndian.PutUint32(raw[0:], 1)           // seq=1 (bit 31=0)
	binary.BigEndian.PutUint32(raw[4:], 0xC0000001)  // PP=11, msg=1
	binary.BigEndian.PutUint32(raw[8:], 1000)        // timestamp
	binary.BigEndian.PutUint32(raw[12:], 42)         // dest socket ID
	binary.BigEndian.PutUint32(raw[16:], 0xDEADBEEF) // payload

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	p, err := Parse(raw[:], addr)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	defer p.Release()

	if p.Header.IsControl {
		t.Error("expected data packet")
	}
	if p.Header.SequenceNumber != 1 {
		t.Errorf("seq: got %d, want 1", p.Header.SequenceNumber)
	}
	if p.Header.PacketPosition != PositionSingle {
		t.Errorf("PP: got %d, want %d", p.Header.PacketPosition, PositionSingle)
	}
	if p.Header.Timestamp != 1000 {
		t.Errorf("timestamp: got %d, want 1000", p.Header.Timestamp)
	}
	if p.Len() != 4 {
		t.Errorf("payload len: got %d, want 4", p.Len())
	}
	if binary.BigEndian.Uint32(p.Data) != 0xDEADBEEF {
		t.Errorf("payload: got %#x, want 0xDEADBEEF", binary.BigEndian.Uint32(p.Data))
	}
}

func TestParseControlPacket(t *testing.T) {
	var raw [HeaderSize + 28]byte
	// Control packet: HANDSHAKE
	binary.BigEndian.PutUint16(raw[0:], 0x8000) // control=1, type=HANDSHAKE(0)
	binary.BigEndian.PutUint16(raw[2:], 0)      // subtype=0
	binary.BigEndian.PutUint32(raw[4:], 0)      // type specific
	binary.BigEndian.PutUint32(raw[8:], 5000)   // timestamp
	binary.BigEndian.PutUint32(raw[12:], 100)   // dest socket ID

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	p, err := Parse(raw[:], addr)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	defer p.Release()

	if !p.Header.IsControl {
		t.Error("expected control packet")
	}
	if p.Header.ControlType != CtrlTypeHandshake {
		t.Errorf("type: got %v, want HANDSHAKE", p.Header.ControlType)
	}
	if p.Header.Timestamp != 5000 {
		t.Errorf("timestamp: got %d, want 5000", p.Header.Timestamp)
	}
}

func TestPacketMarshalRoundtrip(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	payload := []byte("hello SRT")
	p := NewData(addr, 42, 1234, 100, payload)
	defer p.Release()

	buf := make([]byte, HeaderSize+len(payload))
	n, err := p.Marshal(buf)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	parsed, err := Parse(buf[:n], addr)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	defer parsed.Release()

	if parsed.Header.SequenceNumber != 42 {
		t.Errorf("seq: got %d, want 42", parsed.Header.SequenceNumber)
	}
	if parsed.Header.Timestamp != 1234 {
		t.Errorf("timestamp: got %d, want 1234", parsed.Header.Timestamp)
	}
	if string(parsed.Data) != "hello SRT" {
		t.Errorf("data: got %q, want %q", parsed.Data, "hello SRT")
	}
}

func TestPacketClone(t *testing.T) {
	p := NewData(nil, 1, 100, 42, []byte("test"))
	defer p.Release()

	clone := p.Clone()
	defer clone.Release()

	if string(clone.Data) != "test" {
		t.Errorf("clone data: got %q, want %q", clone.Data, "test")
	}

	// Modify original, clone should be independent
	p.Data[0] = 'X'
	if clone.Data[0] == 'X' {
		t.Error("clone should have independent data")
	}
}

func TestPacketSetData(t *testing.T) {
	p := New(nil)
	defer p.Release()

	p.SetData([]byte("initial"))
	if string(p.Data) != "initial" {
		t.Errorf("got %q, want %q", p.Data, "initial")
	}

	p.SetData([]byte("replaced"))
	if string(p.Data) != "replaced" {
		t.Errorf("got %q, want %q", p.Data, "replaced")
	}
}

func TestParseTooShort(t *testing.T) {
	_, err := Parse([]byte{0, 1, 2}, nil)
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestPacketPool(t *testing.T) {
	// Create and release many packets to exercise the pool
	for range 1000 {
		p := New(nil)
		p.SetData([]byte("pool test data"))
		p.Release()
	}
}

// --- CIF tests ---

func TestCIFACKRoundtrip(t *testing.T) {
	original := &CIFACK{
		LastACKPacketSequenceNumber: 12345,
		RTT:                         50000,
		RTTVariance:                 10000,
		AvailableBufferSize:         8192,
		PacketsReceivingRate:        1000,
		EstimatedLinkCapacity:       5000,
		ReceivingRate:               1250000,
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF failed: %v", err)
	}

	if len(data) != 28 {
		t.Fatalf("ACK CIF length: got %d, want 28", len(data))
	}

	parsed := &CIFACK{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF failed: %v", err)
	}

	if parsed.LastACKPacketSequenceNumber != original.LastACKPacketSequenceNumber {
		t.Errorf("LastACKSeq: got %d, want %d", parsed.LastACKPacketSequenceNumber, original.LastACKPacketSequenceNumber)
	}
	if parsed.RTT != original.RTT {
		t.Errorf("RTT: got %d, want %d", parsed.RTT, original.RTT)
	}
	if parsed.ReceivingRate != original.ReceivingRate {
		t.Errorf("ReceivingRate: got %d, want %d", parsed.ReceivingRate, original.ReceivingRate)
	}
}

func TestCIFACKLite(t *testing.T) {
	// Lite ACK: only 4 bytes (just the ACK sequence number)
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, 999)

	ack := &CIFACK{}
	if err := ack.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF failed: %v", err)
	}
	if ack.LastACKPacketSequenceNumber != 999 {
		t.Errorf("got %d, want 999", ack.LastACKPacketSequenceNumber)
	}
	// Other fields should be zero
	if ack.RTT != 0 {
		t.Errorf("RTT should be 0 for lite ACK, got %d", ack.RTT)
	}
}

func TestCIFNAKSingleLoss(t *testing.T) {
	original := &CIFNAK{
		LossList: []uint32{100, 200, 300},
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF failed: %v", err)
	}

	// 3 single losses = 3 * 4 = 12 bytes
	if len(data) != 12 {
		t.Fatalf("NAK CIF length: got %d, want 12", len(data))
	}

	parsed := &CIFNAK{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF failed: %v", err)
	}

	if len(parsed.LossList) != 3 {
		t.Fatalf("LossList length: got %d, want 3", len(parsed.LossList))
	}
	for i, expected := range []uint32{100, 200, 300} {
		if parsed.LossList[i] != expected {
			t.Errorf("LossList[%d]: got %d, want %d", i, parsed.LossList[i], expected)
		}
	}
}

func TestCIFNAKRange(t *testing.T) {
	// Loss of packets 100-105 (contiguous range)
	original := &CIFNAK{
		LossList: []uint32{100, 101, 102, 103, 104, 105},
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF failed: %v", err)
	}

	// Should encode as a range: 8 bytes (start with bit 31 set + end)
	if len(data) != 8 {
		t.Fatalf("NAK CIF length: got %d, want 8 (range encoding)", len(data))
	}

	// Verify range encoding: first word has bit 31 set
	firstWord := binary.BigEndian.Uint32(data[0:])
	if firstWord&0x80000000 == 0 {
		t.Error("range start should have bit 31 set")
	}
	if firstWord&0x7FFFFFFF != 100 {
		t.Errorf("range start: got %d, want 100", firstWord&0x7FFFFFFF)
	}

	secondWord := binary.BigEndian.Uint32(data[4:])
	if secondWord != 105 {
		t.Errorf("range end: got %d, want 105", secondWord)
	}

	// Unmarshal back
	parsed := &CIFNAK{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF failed: %v", err)
	}

	if len(parsed.LossList) != 6 {
		t.Fatalf("LossList length: got %d, want 6", len(parsed.LossList))
	}
	for i, expected := range []uint32{100, 101, 102, 103, 104, 105} {
		if parsed.LossList[i] != expected {
			t.Errorf("LossList[%d]: got %d, want %d", i, parsed.LossList[i], expected)
		}
	}
}

func TestCIFNAKMixed(t *testing.T) {
	// Mix of single loss and ranges: 50, 100-103, 200
	original := &CIFNAK{
		LossList: []uint32{50, 100, 101, 102, 103, 200},
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF failed: %v", err)
	}

	// 50 = 4 bytes, 100-103 = 8 bytes, 200 = 4 bytes = 16 total
	if len(data) != 16 {
		t.Fatalf("NAK CIF length: got %d, want 16", len(data))
	}

	parsed := &CIFNAK{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF failed: %v", err)
	}

	expected := []uint32{50, 100, 101, 102, 103, 200}
	if len(parsed.LossList) != len(expected) {
		t.Fatalf("LossList length: got %d, want %d", len(parsed.LossList), len(expected))
	}
	for i := range expected {
		if parsed.LossList[i] != expected[i] {
			t.Errorf("LossList[%d]: got %d, want %d", i, parsed.LossList[i], expected[i])
		}
	}
}

func TestCIFHandshakeRoundtrip(t *testing.T) {
	original := &CIFHandshake{
		Version:                     5,
		EncryptionField:             0,
		InitialPacketSequenceNumber: 1000,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               HandshakeTypeInduction,
		SRTSocketID:                 0xABCD1234,
		SynCookie:                   0xDEADBEEF,
		PeerIP:                      net.IPv4(192, 168, 1, 100),
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF failed: %v", err)
	}

	if len(data) != 48 {
		t.Fatalf("Handshake CIF length: got %d, want 48", len(data))
	}

	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF failed: %v", err)
	}

	if parsed.Version != 5 {
		t.Errorf("Version: got %d, want 5", parsed.Version)
	}
	if parsed.InitialPacketSequenceNumber != 1000 {
		t.Errorf("ISN: got %d, want 1000", parsed.InitialPacketSequenceNumber)
	}
	if parsed.HandshakeType != HandshakeTypeInduction {
		t.Errorf("Type: got %v, want INDUCTION", parsed.HandshakeType)
	}
	if parsed.SRTSocketID != 0xABCD1234 {
		t.Errorf("SocketID: got %#x, want %#x", parsed.SRTSocketID, uint32(0xABCD1234))
	}
	if parsed.SynCookie != 0xDEADBEEF {
		t.Errorf("SynCookie: got %#x, want %#x", parsed.SynCookie, uint32(0xDEADBEEF))
	}
	ip4 := parsed.PeerIP.To4()
	if ip4 == nil || !ip4.Equal(net.IPv4(192, 168, 1, 100)) {
		t.Errorf("PeerIP: got %v, want 192.168.1.100", parsed.PeerIP)
	}
}

func TestCIFHandshakeConclusionWithExtensions(t *testing.T) {
	original := &CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 0,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               HandshakeTypeConclusion,
		SRTSocketID:                 1,
		SynCookie:                   0,
		PeerIP:                      net.IPv4(127, 0, 0, 1),

		IsRequest: true,
		HasHS:     true,
		SRTHS: &CIFHandshakeExtension{
			SRTVersion:     0x00010401,
			SRTFlags:       FlagTSBPDSend | FlagTSBPDRecv | FlagCrypt | FlagTLPktDrop | FlagPeriodicNAK | FlagRexmit,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
		HasSID:   true,
		StreamID: "#!::r=live/stream1",
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF failed: %v", err)
	}

	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF failed: %v", err)
	}

	if !parsed.HasHS {
		t.Error("expected HasHS=true")
	}
	if parsed.SRTHS.SRTVersion != 0x00010401 {
		t.Errorf("SRTVersion: got %#x, want %#x", parsed.SRTHS.SRTVersion, uint32(0x00010401))
	}
	if parsed.SRTHS.RecvTSBPDDelay != 120 {
		t.Errorf("RecvTSBPDDelay: got %d, want 120", parsed.SRTHS.RecvTSBPDDelay)
	}
	if !parsed.HasSID {
		t.Error("expected HasSID=true")
	}
	if parsed.StreamID != "#!::r=live/stream1" {
		t.Errorf("StreamID: got %q, want %q", parsed.StreamID, "#!::r=live/stream1")
	}
}

func TestStreamIDEncoding(t *testing.T) {
	// Verify the 4-byte word reversal encoding
	tests := []string{
		"test",
		"#!::r=live/stream1",
		"a",        // short, needs padding
		"abcdefgh", // exactly 8 bytes (2 words)
	}

	for _, sid := range tests {
		encoded := marshalStreamID(sid)
		decoded := unmarshalStreamID(encoded)
		if decoded != sid {
			t.Errorf("StreamID roundtrip: %q -> %q", sid, decoded)
		}
	}
}

func TestCIFHandshakeCongestionExtension(t *testing.T) {
	original := &CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 100,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               HandshakeTypeConclusion,
		SRTSocketID:                 42,
		PeerIP:                      net.IPv4(127, 0, 0, 1),

		IsRequest: true,
		HasHS:     true,
		SRTHS: &CIFHandshakeExtension{
			SRTVersion:     0x00010401,
			SRTFlags:       FlagTSBPDSend | FlagTSBPDRecv | FlagTLPktDrop | FlagPeriodicNAK | FlagRexmit,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
		HasCongestion:  true,
		CongestionType: "live",
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if !parsed.HasCongestion {
		t.Error("expected HasCongestion=true")
	}
	if parsed.CongestionType != "live" {
		t.Errorf("CongestionType: got %q, want %q", parsed.CongestionType, "live")
	}

	// Also verify other extensions still parse correctly
	if !parsed.HasHS {
		t.Error("expected HasHS=true")
	}
	if parsed.SRTHS.RecvTSBPDDelay != 120 {
		t.Errorf("RecvTSBPDDelay: got %d, want 120", parsed.SRTHS.RecvTSBPDDelay)
	}
}

func TestCIFHandshakeUnknownExtensionSkipped(t *testing.T) {
	// Build a valid conclusion with HS extension, then append an unknown extension.
	// UnmarshalCIF should skip the unknown extension without error.
	original := &CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 100,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               HandshakeTypeConclusion,
		SRTSocketID:                 42,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
		IsRequest:                   true,
		HasHS:                       true,
		SRTHS: &CIFHandshakeExtension{
			SRTVersion:     0x00010401,
			SRTFlags:       FlagTSBPDSend | FlagTSBPDRecv | FlagTLPktDrop | FlagPeriodicNAK | FlagRexmit,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	// Append a fake unknown extension (type=0x00FF, length=1 word = 4 bytes)
	var extHdr [4]byte
	binary.BigEndian.PutUint16(extHdr[0:], 0x00FF) // unknown type
	binary.BigEndian.PutUint16(extHdr[2:], 1)      // 1 word = 4 bytes
	data = append(data, extHdr[:]...)
	data = append(data, 0xDE, 0xAD, 0xBE, 0xEF)

	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF should skip unknown extensions, got error: %v", err)
	}

	// Verify known extensions still parsed correctly
	if !parsed.HasHS {
		t.Error("expected HasHS=true")
	}
	if parsed.SRTHS.RecvTSBPDDelay != 120 {
		t.Errorf("RecvTSBPDDelay: got %d, want 120", parsed.SRTHS.RecvTSBPDDelay)
	}
}

func TestCIFHandshakeExtensionFieldBitmask(t *testing.T) {
	// When only HasCongestion is set (no HasSID), bit 4 of ExtensionField
	// should still be set since congestion is a config extension.
	original := &CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 100,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               HandshakeTypeConclusion,
		SRTSocketID:                 42,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
		IsRequest:                   true,
		HasHS:                       true,
		SRTHS: &CIFHandshakeExtension{
			SRTVersion:     0x00010401,
			SRTFlags:       FlagTSBPDSend | FlagTSBPDRecv | FlagTLPktDrop | FlagPeriodicNAK | FlagRexmit,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
		HasCongestion:  true,
		CongestionType: "live",
		// HasSID is NOT set
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	// Check the ExtensionField in the marshaled bytes
	extField := binary.BigEndian.Uint16(data[6:8])

	// Bit 0 = HasHS (1), Bit 2 (value 4) = config extensions
	if extField&1 == 0 {
		t.Error("expected bit 0 (HS) set in ExtensionField")
	}
	if extField&4 == 0 {
		t.Error("expected bit 2 (config extensions) set in ExtensionField for HasCongestion")
	}

	// Verify round-trip
	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if !parsed.HasCongestion {
		t.Error("expected HasCongestion=true after round-trip")
	}
	if parsed.CongestionType != "live" {
		t.Errorf("CongestionType: got %q, want %q", parsed.CongestionType, "live")
	}
}

func TestCIFDropReqRoundtrip(t *testing.T) {
	original := &CIFDropReq{
		MsgID:      42,
		FirstSeqNo: 1000,
		LastSeqNo:  1005,
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF failed: %v", err)
	}

	parsed := &CIFDropReq{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF failed: %v", err)
	}

	if parsed.MsgID != 42 || parsed.FirstSeqNo != 1000 || parsed.LastSeqNo != 1005 {
		t.Errorf("DropReq mismatch: got %+v, want %+v", parsed, original)
	}
}

// --- Benchmarks ---

func BenchmarkParse(b *testing.B) {
	var raw [HeaderSize + 1316]byte // typical video packet
	binary.BigEndian.PutUint32(raw[0:], 1)
	binary.BigEndian.PutUint32(raw[4:], 0xC0000001)
	binary.BigEndian.PutUint32(raw[8:], 1000)
	binary.BigEndian.PutUint32(raw[12:], 42)
	for i := HeaderSize; i < len(raw); i++ {
		raw[i] = byte(i)
	}

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}

	b.ResetTimer()
	for b.Loop() {
		p, _ := Parse(raw[:], addr)
		p.Release()
	}
}

func BenchmarkMarshal(b *testing.B) {
	payload := make([]byte, 1316)
	p := NewData(nil, 42, 1234, 100, payload)
	defer p.Release()

	buf := make([]byte, HeaderSize+1316)

	b.ResetTimer()
	for b.Loop() {
		p.Marshal(buf)
	}
}

func BenchmarkHeaderMarshal(b *testing.B) {
	h := Header{
		SequenceNumber:      42,
		PacketPosition:      PositionSingle,
		MessageNumber:       1,
		Timestamp:           1234,
		DestinationSocketID: 100,
	}
	var buf [HeaderSize]byte

	for b.Loop() {
		h.Marshal(buf[:])
	}
}

func BenchmarkHeaderUnmarshal(b *testing.B) {
	var buf [HeaderSize]byte
	binary.BigEndian.PutUint32(buf[0:], 42)
	binary.BigEndian.PutUint32(buf[4:], 0xC0000001)
	binary.BigEndian.PutUint32(buf[8:], 1234)
	binary.BigEndian.PutUint32(buf[12:], 100)

	var h Header
	for b.Loop() {
		h.Unmarshal(buf[:])
	}
}
