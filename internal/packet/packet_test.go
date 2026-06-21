package packet

import (
	"encoding/binary"
	"fmt"
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
		FirstSeqNo: 1000,
		LastSeqNo:  1005,
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF failed: %v", err)
	}
	// libsrt wire layout: an 8-byte [firstSeq, lastSeq] body, no message number.
	if len(data) != 8 {
		t.Fatalf("DropReq CIF = %d bytes, want 8 (libsrt seqpair layout)", len(data))
	}
	if binary.BigEndian.Uint32(data[0:]) != 1000 || binary.BigEndian.Uint32(data[4:]) != 1005 {
		t.Fatalf("DropReq CIF bytes = %x, want first=1000 at [0:4], last=1005 at [4:8]", data)
	}

	parsed := &CIFDropReq{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF failed: %v", err)
	}

	if parsed.FirstSeqNo != 1000 || parsed.LastSeqNo != 1005 {
		t.Errorf("DropReq mismatch: got %+v, want %+v", parsed, original)
	}
}

// --- HandshakeType String / IsHandshake / IsRejection tests ---

func TestHandshakeTypeString(t *testing.T) {
	tests := []struct {
		ht   HandshakeType
		want string
	}{
		{HandshakeTypeDone, "DONE"},
		{HandshakeTypeAgreement, "AGREEMENT"},
		{HandshakeTypeConclusion, "CONCLUSION"},
		{HandshakeTypeWavehand, "WAVEHAND"},
		{HandshakeTypeInduction, "INDUCTION"},
		{HandshakeType(1002), "REJECT(1002)"},
	}
	for _, tt := range tests {
		got := tt.ht.String()
		if got != tt.want {
			t.Errorf("HandshakeType(%#x).String() = %q, want %q", uint32(tt.ht), got, tt.want)
		}
	}
}

func TestHandshakeTypeIsHandshake(t *testing.T) {
	validTypes := []HandshakeType{
		HandshakeTypeDone, HandshakeTypeAgreement, HandshakeTypeConclusion,
		HandshakeTypeWavehand, HandshakeTypeInduction,
	}
	for _, ht := range validTypes {
		if !ht.IsHandshake() {
			t.Errorf("IsHandshake(%s) = false, want true", ht)
		}
		if ht.IsRejection() {
			t.Errorf("IsRejection(%s) = true, want false", ht)
		}
	}

	// Rejection codes
	rejections := []HandshakeType{HandshakeType(1000), HandshakeType(1002), HandshakeType(1010)}
	for _, ht := range rejections {
		if ht.IsHandshake() {
			t.Errorf("IsHandshake(%s) = true, want false", ht)
		}
		if !ht.IsRejection() {
			t.Errorf("IsRejection(%s) = false, want true", ht)
		}
	}
}

// --- CtrlType.String and SubType.String tests ---

func TestCtrlTypeString(t *testing.T) {
	tests := []struct {
		ct   CtrlType
		want string
	}{
		{CtrlTypeHandshake, "HANDSHAKE"},
		{CtrlTypeKeepalive, "KEEPALIVE"},
		{CtrlTypeACK, "ACK"},
		{CtrlTypeNAK, "NAK"},
		{CtrlTypeShutdown, "SHUTDOWN"},
		{CtrlTypeACKACK, "ACKACK"},
		{CtrlTypeDropReq, "DROPREQ"},
		{CtrlTypeUser, "USER"},
		{CtrlTypeWarn, "CTRL(4)"},
		{CtrlTypePeerError, "CTRL(8)"},
		{CtrlType(0x1234), "CTRL(4660)"},
	}
	for _, tt := range tests {
		got := tt.ct.String()
		if got != tt.want {
			t.Errorf("CtrlType(%d).String() = %q, want %q", tt.ct, got, tt.want)
		}
	}
}

func TestSubTypeString(t *testing.T) {
	tests := []struct {
		st   SubType
		want string
	}{
		{SubTypeNone, "NONE"},
		{ExtTypeHSReq, "HSREQ"},
		{ExtTypeHSRsp, "HSRSP"},
		{ExtTypeKMReq, "KMREQ"},
		{ExtTypeKMRsp, "KMRSP"},
		{ExtTypeSID, "SID"},
		{ExtTypeCongestion, "CONGESTION"},
		{ExtTypeFilter, "FILTER"},
		{ExtTypeGroup, "GROUP"},
		{SubType(99), "EXT(99)"},
	}
	for _, tt := range tests {
		got := tt.st.String()
		if got != tt.want {
			t.Errorf("SubType(%d).String() = %q, want %q", tt.st, got, tt.want)
		}
	}
}

// --- NewControl test ---

func TestNewControl(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	p := NewControl(addr, CtrlTypeShutdown, 0xABCD, 5000)
	defer p.Release()

	if !p.Header.IsControl {
		t.Error("expected IsControl=true")
	}
	if p.Header.ControlType != CtrlTypeShutdown {
		t.Errorf("ControlType: got %v, want SHUTDOWN", p.Header.ControlType)
	}
	if p.Header.DestinationSocketID != 0xABCD {
		t.Errorf("DestinationSocketID: got %#x, want 0xABCD", p.Header.DestinationSocketID)
	}
	if p.Header.Timestamp != 5000 {
		t.Errorf("Timestamp: got %d, want 5000", p.Header.Timestamp)
	}
}

// --- MarshalTo test ---

func TestMarshalToRoundtrip(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	payload := []byte("marshalto test")
	p := NewData(addr, 77, 9999, 200, payload)
	defer p.Release()

	raw, err := p.MarshalTo()
	if err != nil {
		t.Fatalf("MarshalTo failed: %v", err)
	}

	if len(raw) != HeaderSize+len(payload) {
		t.Fatalf("MarshalTo length: got %d, want %d", len(raw), HeaderSize+len(payload))
	}

	parsed, err := Parse(raw, addr)
	if err != nil {
		t.Fatalf("Parse after MarshalTo failed: %v", err)
	}
	defer parsed.Release()

	if parsed.Header.SequenceNumber != 77 {
		t.Errorf("seq: got %d, want 77", parsed.Header.SequenceNumber)
	}
	if string(parsed.Data) != "marshalto test" {
		t.Errorf("data: got %q, want %q", parsed.Data, "marshalto test")
	}
}

// --- Marshal buffer too small ---

func TestMarshalBufferTooSmall(t *testing.T) {
	p := NewData(nil, 1, 100, 42, []byte("hello"))
	defer p.Release()

	buf := make([]byte, 2) // way too small
	_, err := p.Marshal(buf)
	if err == nil {
		t.Error("expected error for undersized buffer")
	}
}

// --- ACK CIF variants ---

func TestCIFACKMarshalSmallCIF(t *testing.T) {
	ack := &CIFACK{
		LastACKPacketSequenceNumber: 500,
		RTT:                         1000,
		RTTVariance:                 200,
		AvailableBufferSize:         4096,
		PacketsReceivingRate:        999, // should NOT appear in small
	}

	data, err := ack.MarshalSmallCIF()
	if err != nil {
		t.Fatalf("MarshalSmallCIF failed: %v", err)
	}
	if len(data) != 16 {
		t.Fatalf("MarshalSmallCIF length: got %d, want 16", len(data))
	}

	// Verify each field
	if binary.BigEndian.Uint32(data[0:]) != 500 {
		t.Errorf("seq: got %d, want 500", binary.BigEndian.Uint32(data[0:]))
	}
	if binary.BigEndian.Uint32(data[4:]) != 1000 {
		t.Errorf("RTT: got %d, want 1000", binary.BigEndian.Uint32(data[4:]))
	}
	if binary.BigEndian.Uint32(data[8:]) != 200 {
		t.Errorf("RTTVar: got %d, want 200", binary.BigEndian.Uint32(data[8:]))
	}
	if binary.BigEndian.Uint32(data[12:]) != 4096 {
		t.Errorf("BufferSize: got %d, want 4096", binary.BigEndian.Uint32(data[12:]))
	}

	// Unmarshal as Small ACK (16 bytes) and verify
	parsed := &CIFACK{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF small: %v", err)
	}
	if parsed.LastACKPacketSequenceNumber != 500 {
		t.Errorf("parsed seq: got %d, want 500", parsed.LastACKPacketSequenceNumber)
	}
	if parsed.RTT != 1000 {
		t.Errorf("parsed RTT: got %d, want 1000", parsed.RTT)
	}
	if parsed.PacketsReceivingRate != 0 {
		t.Errorf("parsed PacketsReceivingRate should be 0 for small ACK, got %d", parsed.PacketsReceivingRate)
	}
}

func TestCIFACKMarshalUDTBaseCIF(t *testing.T) {
	ack := &CIFACK{
		LastACKPacketSequenceNumber: 100,
		RTT:                         5000,
		RTTVariance:                 500,
		AvailableBufferSize:         2048,
		PacketsReceivingRate:        3000,
		EstimatedLinkCapacity:       10000,
		ReceivingRate:               999999, // should NOT appear in UDT base
	}

	data, err := ack.MarshalUDTBaseCIF()
	if err != nil {
		t.Fatalf("MarshalUDTBaseCIF failed: %v", err)
	}
	if len(data) != 24 {
		t.Fatalf("MarshalUDTBaseCIF length: got %d, want 24", len(data))
	}

	if binary.BigEndian.Uint32(data[0:]) != 100 {
		t.Errorf("seq: got %d, want 100", binary.BigEndian.Uint32(data[0:]))
	}
	if binary.BigEndian.Uint32(data[16:]) != 3000 {
		t.Errorf("PacketsReceivingRate: got %d, want 3000", binary.BigEndian.Uint32(data[16:]))
	}
	if binary.BigEndian.Uint32(data[20:]) != 10000 {
		t.Errorf("EstimatedLinkCapacity: got %d, want 10000", binary.BigEndian.Uint32(data[20:]))
	}
}

func TestCIFACKMarshalV102CIF(t *testing.T) {
	ack := &CIFACK{
		LastACKPacketSequenceNumber: 200,
		RTT:                         8000,
		RTTVariance:                 800,
		AvailableBufferSize:         1024,
		PacketsReceivingRate:        5000,
		EstimatedLinkCapacity:       20000,
		ReceivingRate:               1250000,
	}
	xmRate := uint32(6580000)

	data, err := ack.MarshalV102CIF(xmRate)
	if err != nil {
		t.Fatalf("MarshalV102CIF failed: %v", err)
	}
	if len(data) != 32 {
		t.Fatalf("MarshalV102CIF length: got %d, want 32", len(data))
	}

	if binary.BigEndian.Uint32(data[0:]) != 200 {
		t.Errorf("seq: got %d, want 200", binary.BigEndian.Uint32(data[0:]))
	}
	if binary.BigEndian.Uint32(data[24:]) != 1250000 {
		t.Errorf("ReceivingRate: got %d, want 1250000", binary.BigEndian.Uint32(data[24:]))
	}
	if binary.BigEndian.Uint32(data[28:]) != xmRate {
		t.Errorf("xmRate: got %d, want %d", binary.BigEndian.Uint32(data[28:]), xmRate)
	}
}

func TestCIFACKUnmarshalSmallACK(t *testing.T) {
	// 16-byte Small ACK
	data := make([]byte, 16)
	binary.BigEndian.PutUint32(data[0:], 42)
	binary.BigEndian.PutUint32(data[4:], 1234)
	binary.BigEndian.PutUint32(data[8:], 567)
	binary.BigEndian.PutUint32(data[12:], 8192)

	ack := &CIFACK{}
	if err := ack.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if ack.LastACKPacketSequenceNumber != 42 {
		t.Errorf("seq: got %d, want 42", ack.LastACKPacketSequenceNumber)
	}
	if ack.RTT != 1234 {
		t.Errorf("RTT: got %d, want 1234", ack.RTT)
	}
	if ack.RTTVariance != 567 {
		t.Errorf("RTTVar: got %d, want 567", ack.RTTVariance)
	}
	if ack.AvailableBufferSize != 8192 {
		t.Errorf("BufferSize: got %d, want 8192", ack.AvailableBufferSize)
	}
	// Extended fields should be zero
	if ack.PacketsReceivingRate != 0 || ack.EstimatedLinkCapacity != 0 || ack.ReceivingRate != 0 {
		t.Error("extended fields should be zero for small ACK")
	}
}

func TestCIFACKUnmarshalFullACK(t *testing.T) {
	// 28-byte Full ACK
	data := make([]byte, 28)
	binary.BigEndian.PutUint32(data[0:], 10)
	binary.BigEndian.PutUint32(data[4:], 2000)
	binary.BigEndian.PutUint32(data[8:], 300)
	binary.BigEndian.PutUint32(data[12:], 4096)
	binary.BigEndian.PutUint32(data[16:], 5000)
	binary.BigEndian.PutUint32(data[20:], 10000)
	binary.BigEndian.PutUint32(data[24:], 1250000)

	ack := &CIFACK{}
	if err := ack.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if ack.PacketsReceivingRate != 5000 {
		t.Errorf("PacketsReceivingRate: got %d, want 5000", ack.PacketsReceivingRate)
	}
	if ack.EstimatedLinkCapacity != 10000 {
		t.Errorf("EstimatedLinkCapacity: got %d, want 10000", ack.EstimatedLinkCapacity)
	}
	if ack.ReceivingRate != 1250000 {
		t.Errorf("ReceivingRate: got %d, want 1250000", ack.ReceivingRate)
	}
}

func TestCIFACKUnmarshalTooShort(t *testing.T) {
	ack := &CIFACK{}
	err := ack.UnmarshalCIF([]byte{0, 1})
	if err == nil {
		t.Error("expected error for 2-byte ACK CIF")
	}
}

// --- Shutdown CIF ---

func TestCIFShutdownMarshalUnmarshal(t *testing.T) {
	s := &CIFShutdown{}
	data, err := s.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}
	if data != nil {
		t.Errorf("expected nil data, got %v", data)
	}

	err = s.UnmarshalCIF([]byte{1, 2, 3})
	if err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
}

// --- Packet.MarshalCIF / UnmarshalCIF ---

func TestPacketMarshalCIFShutdown(t *testing.T) {
	p := NewControl(nil, CtrlTypeShutdown, 42, 1000)
	defer p.Release()

	err := p.MarshalCIF(&CIFShutdown{})
	if err != nil {
		t.Fatalf("MarshalCIF shutdown: %v", err)
	}
	// Shutdown has empty CIF
	if len(p.Data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(p.Data))
	}
}

func TestPacketUnmarshalCIFDropReq(t *testing.T) {
	// Create a DropReq packet manually
	cif := &CIFDropReq{FirstSeqNo: 100, LastSeqNo: 105}
	data, _ := cif.MarshalCIF()

	p := NewControl(nil, CtrlTypeDropReq, 42, 1000)
	defer p.Release()
	p.SetData(data)

	parsed := &CIFDropReq{}
	err := p.UnmarshalCIF(parsed)
	if err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if parsed.FirstSeqNo != 100 || parsed.LastSeqNo != 105 {
		t.Errorf("DropReq mismatch: %+v", parsed)
	}
}

func TestPacketMarshalCIFACK(t *testing.T) {
	p := NewControl(nil, CtrlTypeACK, 42, 1000)
	defer p.Release()

	ack := &CIFACK{
		LastACKPacketSequenceNumber: 500,
		RTT:                         2000,
		RTTVariance:                 300,
		AvailableBufferSize:         8192,
		PacketsReceivingRate:        1000,
		EstimatedLinkCapacity:       5000,
		ReceivingRate:               1250000,
	}
	err := p.MarshalCIF(ack)
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}
	if len(p.Data) != 28 {
		t.Fatalf("expected 28 bytes, got %d", len(p.Data))
	}

	// Unmarshal back
	parsed := &CIFACK{}
	err = p.UnmarshalCIF(parsed)
	if err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if parsed.LastACKPacketSequenceNumber != 500 {
		t.Errorf("seq: got %d, want 500", parsed.LastACKPacketSequenceNumber)
	}
}

// --- CIFDropReq edge cases ---

func TestCIFDropReqMarshalRoundtrip(t *testing.T) {
	original := &CIFDropReq{FirstSeqNo: 200, LastSeqNo: 210}
	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}
	if len(data) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(data))
	}

	parsed := &CIFDropReq{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if parsed.FirstSeqNo != 200 || parsed.LastSeqNo != 210 {
		t.Errorf("mismatch: %+v", parsed)
	}
}

func TestCIFDropReqUnmarshalTooShort(t *testing.T) {
	parsed := &CIFDropReq{}
	err := parsed.UnmarshalCIF([]byte{0, 1, 2, 3})
	if err == nil {
		t.Error("expected error for 4-byte DropReq CIF")
	}
}

// --- CIFHandshake v4 path ---

func TestCIFHandshakeMarshalV4(t *testing.T) {
	hs := &CIFHandshake{
		Version:                     4,
		InitialPacketSequenceNumber: 500,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               HandshakeTypeInduction,
		SRTSocketID:                 1,
		SynCookie:                   0x12345678,
		PeerIP:                      net.IPv4(10, 0, 0, 1),
	}

	data, err := hs.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}
	if len(data) != 48 {
		t.Fatalf("expected 48 bytes, got %d", len(data))
	}

	// v4 should set EncryptionField=0, ExtensionField=2
	encField := binary.BigEndian.Uint16(data[4:6])
	extField := binary.BigEndian.Uint16(data[6:8])
	if encField != 0 {
		t.Errorf("v4 EncryptionField: got %d, want 0", encField)
	}
	if extField != 2 {
		t.Errorf("v4 ExtensionField: got %d, want 2", extField)
	}

	// Roundtrip
	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if parsed.Version != 4 {
		t.Errorf("version: got %d, want 4", parsed.Version)
	}
}

// --- CIFHandshake with group extension ---

func TestCIFHandshakeGroupExtension(t *testing.T) {
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
		HasGroup:    true,
		GroupID:     0xDEAD0001,
		GroupType:   2, // backup
		GroupFlags:  0,
		GroupWeight: 50,
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if !parsed.HasGroup {
		t.Error("expected HasGroup=true")
	}
	if parsed.GroupID != 0xDEAD0001 {
		t.Errorf("GroupID: got %#x, want %#x", parsed.GroupID, uint32(0xDEAD0001))
	}
	if parsed.GroupType != 2 {
		t.Errorf("GroupType: got %d, want 2", parsed.GroupType)
	}
	if parsed.GroupWeight != 50 {
		t.Errorf("GroupWeight: got %d, want 50", parsed.GroupWeight)
	}
}

// --- CIFHandshake with filter extension ---

func TestCIFHandshakeFilterExtension(t *testing.T) {
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
		HasFilter:    true,
		FilterConfig: "fec,cols:10,rows:5,layout:staircase,arq:onreq",
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if !parsed.HasFilter {
		t.Error("expected HasFilter=true")
	}
	if parsed.FilterConfig != "fec,cols:10,rows:5,layout:staircase,arq:onreq" {
		t.Errorf("FilterConfig: got %q, want %q", parsed.FilterConfig, "fec,cols:10,rows:5,layout:staircase,arq:onreq")
	}
}

// --- CIFHandshake encryption field validation ---

func TestCIFHandshakeInvalidEncryptionField(t *testing.T) {
	// Build a conclusion with extension field set and invalid encryption field
	hs := &CIFHandshake{
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
			SRTFlags:       FlagTSBPDSend | FlagTSBPDRecv,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
	}

	data, err := hs.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	// Corrupt the encryption field to an invalid value (5)
	binary.BigEndian.PutUint16(data[4:6], 5)

	parsed := &CIFHandshake{}
	err = parsed.UnmarshalCIF(data)
	if err == nil {
		t.Error("expected error for invalid encryption field 5")
	}
}

// --- CIFHandshake short CIF ---

func TestCIFHandshakeUnmarshalTooShort(t *testing.T) {
	parsed := &CIFHandshake{}
	err := parsed.UnmarshalCIF(make([]byte, 20))
	if err == nil {
		t.Error("expected error for 20-byte handshake CIF")
	}
}

// --- CIFHandshake v5 non-conclusion (DONE/AGREEMENT/WAVEHAND) early return ---

func TestCIFHandshakeUnmarshalNonConclusionEarlyReturn(t *testing.T) {
	// A DONE handshake should return immediately after the base 48 bytes
	hs := &CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 100,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               HandshakeTypeDone,
		SRTSocketID:                 42,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
	}

	data, err := hs.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if parsed.HandshakeType != HandshakeTypeDone {
		t.Errorf("HandshakeType: got %v, want DONE", parsed.HandshakeType)
	}
	// No extensions should be parsed
	if parsed.HasHS || parsed.HasSID || parsed.HasCongestion || parsed.HasFilter || parsed.HasGroup || parsed.HasKM {
		t.Error("no extensions should be parsed for non-CONCLUSION handshake")
	}
}

// --- CIFHandshake conclusion with no extension field ---

func TestCIFHandshakeConclusionNoExtensions(t *testing.T) {
	// Build raw 48 bytes with v5 CONCLUSION but ExtensionField=0
	data := make([]byte, 48)
	binary.BigEndian.PutUint32(data[0:], 5)           // version 5
	binary.BigEndian.PutUint16(data[4:], 0)           // encryption
	binary.BigEndian.PutUint16(data[6:], 0)           // extension field = 0
	binary.BigEndian.PutUint32(data[8:], 100)         // ISN
	binary.BigEndian.PutUint32(data[12:], 1500)       // MTU
	binary.BigEndian.PutUint32(data[16:], 8192)       // FC
	binary.BigEndian.PutUint32(data[20:], 0xFFFFFFFF) // CONCLUSION
	binary.BigEndian.PutUint32(data[24:], 1)          // SRT socket ID
	binary.BigEndian.PutUint32(data[28:], 0)          // cookie
	copy(data[32:], net.IPv4(127, 0, 0, 1).To4())

	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if parsed.HasHS || parsed.HasKM || parsed.HasSID {
		t.Error("no extensions should be parsed when ExtensionField=0")
	}
}

// --- CIFHandshake truncated extension ---

func TestCIFHandshakeTruncatedExtension(t *testing.T) {
	// Build valid conclusion handshake then append truncated extension header
	hs := &CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 100,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               HandshakeTypeConclusion,
		SRTSocketID:                 42,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
	}
	data, _ := hs.MarshalCIF()
	// Set extension field to 1 (HasHS)
	binary.BigEndian.PutUint16(data[6:], 1)
	// Append extension header claiming 4 words (16 bytes) but only provide 4 bytes
	var extHdr [4]byte
	binary.BigEndian.PutUint16(extHdr[0:], uint16(ExtTypeHSReq))
	binary.BigEndian.PutUint16(extHdr[2:], 4) // 4 words = 16 bytes
	data = append(data, extHdr[:]...)
	data = append(data, 0, 0, 0, 0) // only 4 bytes instead of 16

	parsed := &CIFHandshake{}
	err := parsed.UnmarshalCIF(data)
	if err == nil {
		t.Error("expected error for truncated extension data")
	}
}

// --- CIFHandshake duplicate extension ---

func TestCIFHandshakeDuplicateExtension(t *testing.T) {
	// Build a valid CONCLUSION with HS extension, then manually duplicate it
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
			SRTFlags:       FlagTSBPDSend | FlagTSBPDRecv,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	// Append a second HSREQ extension (duplicate)
	hsData := make([]byte, 12)
	binary.BigEndian.PutUint32(hsData[0:], 0x00010401)
	binary.BigEndian.PutUint32(hsData[4:], FlagTSBPDSend)
	binary.BigEndian.PutUint16(hsData[8:], 100)
	binary.BigEndian.PutUint16(hsData[10:], 100)
	data = appendExtension(data, ExtTypeHSReq, hsData)

	parsed := &CIFHandshake{}
	err = parsed.UnmarshalCIF(data)
	if err == nil {
		t.Error("expected error for duplicate extension type")
	}
}

// --- CIFHandshake HS extension wrong length ---

func TestCIFHandshakeHSExtWrongLength(t *testing.T) {
	// Build a CONCLUSION and manually add an HSREQ with wrong length (8 instead of 12)
	data := make([]byte, 48)
	binary.BigEndian.PutUint32(data[0:], 5)           // version 5
	binary.BigEndian.PutUint16(data[4:], 0)           // encryption
	binary.BigEndian.PutUint16(data[6:], 1)           // extension field: HasHS
	binary.BigEndian.PutUint32(data[20:], 0xFFFFFFFF) // CONCLUSION
	copy(data[32:], net.IPv4(127, 0, 0, 1).To4())

	// Add HSREQ with 8 bytes (wrong - should be 12)
	hsData := make([]byte, 8)
	data = appendExtension(data, ExtTypeHSReq, hsData)

	parsed := &CIFHandshake{}
	err := parsed.UnmarshalCIF(data)
	if err == nil {
		t.Error("expected error for HS extension wrong length")
	}
}

// --- CIFHandshake HSRSP path ---

func TestCIFHandshakeHSRsp(t *testing.T) {
	original := &CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 100,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               HandshakeTypeConclusion,
		SRTSocketID:                 42,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
		IsRequest:                   false, // RESPONSE
		HasHS:                       true,
		SRTHS: &CIFHandshakeExtension{
			SRTVersion:     0x00010401,
			SRTFlags:       FlagTSBPDSend | FlagTSBPDRecv,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if parsed.IsRequest {
		t.Error("expected IsRequest=false for HSRSP")
	}
	if !parsed.HasHS {
		t.Error("expected HasHS=true")
	}
}

// --- CIFHandshake with KM extension (KMRSP path) ---

func TestCIFHandshakeKMRsp(t *testing.T) {
	km := &CIFKeyMaterial{
		S:                     0,
		Version:               1,
		PacketType:            2,
		Sign:                  0x2029,
		KeyBasedEncryption:    EncryptionEven,
		KeyEncryptionKeyIndex: 0,
		Cipher:                2, // AES-CTR
		Authentication:        0,
		StreamEncapsulation:   2,
		SLen:                  16,
		KLen:                  16,
		Salt:                  make([]byte, 16),
		Wrap:                  make([]byte, 24), // 1 key * 16 + 8
	}
	original := &CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 100,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               HandshakeTypeConclusion,
		SRTSocketID:                 42,
		PeerIP:                      net.IPv4(127, 0, 0, 1),
		IsRequest:                   false, // response
		HasHS:                       true,
		SRTHS: &CIFHandshakeExtension{
			SRTVersion:     0x00010401,
			SRTFlags:       FlagTSBPDSend | FlagTSBPDRecv | FlagCrypt,
			RecvTSBPDDelay: 120,
			SendTSBPDDelay: 120,
		},
		HasKM: true,
		SRTKM: km,
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if parsed.IsRequest {
		t.Error("expected IsRequest=false for KMRSP")
	}
	if !parsed.HasKM {
		t.Error("expected HasKM=true")
	}
	if parsed.SRTKM.Cipher != 2 {
		t.Errorf("Cipher: got %d, want 2", parsed.SRTKM.Cipher)
	}
}

// --- CIFKeyMaterial error response ---

func TestCIFKeyMaterialErrorResponse(t *testing.T) {
	km := &CIFKeyMaterial{Error: 2}
	data, err := km.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}
	if len(data) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(data))
	}
	if binary.BigEndian.Uint32(data) != 2 {
		t.Errorf("error code: got %d, want 2", binary.BigEndian.Uint32(data))
	}

	parsed := &CIFKeyMaterial{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if parsed.Error != 2 {
		t.Errorf("Error: got %d, want 2", parsed.Error)
	}
}

// --- CIFKeyMaterial too short ---

func TestCIFKeyMaterialUnmarshalTooShort(t *testing.T) {
	parsed := &CIFKeyMaterial{}
	err := parsed.UnmarshalCIF(make([]byte, 8))
	if err == nil {
		t.Error("expected error for 8-byte KM")
	}
}

// --- CIFHandshake IPv6 ---

func TestCIFHandshakeIPv6(t *testing.T) {
	ipv6 := net.ParseIP("2001:db8::1")
	original := &CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 100,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               HandshakeTypeInduction,
		SRTSocketID:                 42,
		PeerIP:                      ipv6,
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	if !parsed.PeerIP.Equal(ipv6) {
		t.Errorf("PeerIP: got %v, want %v", parsed.PeerIP, ipv6)
	}
}

// --- CIFHandshake nil IP ---

func TestCIFHandshakeNilIP(t *testing.T) {
	original := &CIFHandshake{
		Version:                     5,
		InitialPacketSequenceNumber: 100,
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           8192,
		HandshakeType:               HandshakeTypeInduction,
		SRTSocketID:                 42,
		PeerIP:                      nil,
	}

	data, err := original.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	parsed := &CIFHandshake{}
	if err := parsed.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}

	// IP should be all zeros (IPv4)
	if !parsed.PeerIP.Equal(net.IPv4(0, 0, 0, 0)) {
		t.Errorf("PeerIP: got %v, want 0.0.0.0", parsed.PeerIP)
	}
}

// --- SetData with non-pooled packet ---

func TestSetDataNonPooled(t *testing.T) {
	// Create a packet without pool (simulate by zeroing pooled)
	p := Packet{
		Header: Header{},
		Data:   nil,
		pooled: nil,
	}

	p.SetData([]byte("external data"))
	if string(p.Data) != "external data" {
		t.Errorf("got %q, want %q", p.Data, "external data")
	}

	// pooled should now be set (getBuffer was called)
	if p.pooled == nil {
		t.Error("expected pooled buffer to be set after SetData on non-pooled packet")
	}
	p.Release()
}

// --- Parse control packet with zero payload ---

func TestParseControlPacketNoPayload(t *testing.T) {
	// Keepalive has no payload
	var raw [HeaderSize]byte
	binary.BigEndian.PutUint16(raw[0:], 0x8001) // control=1, type=KEEPALIVE
	binary.BigEndian.PutUint16(raw[2:], 0)      // subtype
	binary.BigEndian.PutUint32(raw[4:], 0)      // type specific
	binary.BigEndian.PutUint32(raw[8:], 1000)   // timestamp
	binary.BigEndian.PutUint32(raw[12:], 42)    // dest socket ID

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	p, err := Parse(raw[:], addr)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	defer p.Release()

	if !p.Header.IsControl {
		t.Error("expected control packet")
	}
	if p.Header.ControlType != CtrlTypeKeepalive {
		t.Errorf("type: got %v, want KEEPALIVE", p.Header.ControlType)
	}
	// No payload
	if len(p.Data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(p.Data))
	}
}

// --- CIFHandshake SID too long ---

func TestCIFHandshakeStreamIDTooLong(t *testing.T) {
	// Build a CONCLUSION with an oversized SID extension
	data := make([]byte, 48)
	binary.BigEndian.PutUint32(data[0:], 5)           // version 5
	binary.BigEndian.PutUint16(data[4:], 0)           // encryption
	binary.BigEndian.PutUint16(data[6:], 4)           // extension field: config
	binary.BigEndian.PutUint32(data[20:], 0xFFFFFFFF) // CONCLUSION
	copy(data[32:], net.IPv4(127, 0, 0, 1).To4())

	// Add oversized SID extension (>512 bytes)
	sidData := make([]byte, 516)
	for i := range sidData {
		sidData[i] = 'A'
	}
	data = appendExtension(data, ExtTypeSID, sidData)

	parsed := &CIFHandshake{}
	err := parsed.UnmarshalCIF(data)
	if err == nil {
		t.Error("expected error for SID too long")
	}
}

// --- NAK empty loss list ---

func TestCIFNAKEmptyLossList(t *testing.T) {
	nak := &CIFNAK{}
	data, err := nak.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}
	if data != nil {
		t.Errorf("expected nil data for empty loss list, got %v", data)
	}
}

// --- CIFHandshakeExtension unmarshal too short ---

func TestCIFHandshakeExtensionUnmarshalTooShort(t *testing.T) {
	ext := &CIFHandshakeExtension{}
	err := ext.UnmarshalCIF(make([]byte, 8))
	if err == nil {
		t.Error("expected error for 8-byte HS extension")
	}
}

// --- CIFKeyMaterial validation error paths ---

// buildValidKMData builds a valid KM data buffer for AES-128-CTR with one key.
func buildValidKMData() []byte {
	// 16 header + 16 salt + 24 wrap (1*16 + 8) = 56 bytes
	data := make([]byte, 56)
	// byte 0: S=0, Version=1, PacketType=2 => 0b0_001_0010 = 0x12
	data[0] = 0x12
	// bytes 1-2: Sign = 0x2029
	binary.BigEndian.PutUint16(data[1:], 0x2029)
	// byte 3: KF=01 (EncryptionEven)
	data[3] = 0x01
	// bytes 4-7: KEK index
	binary.BigEndian.PutUint32(data[4:], 0)
	// byte 8: Cipher=2 (AES-CTR)
	data[8] = 2
	// byte 9: Auth=0
	data[9] = 0
	// byte 10: SE=2
	data[10] = 2
	// byte 14: SLen/4 = 4 (16 bytes)
	data[14] = 4
	// byte 15: KLen/4 = 4 (16 bytes)
	data[15] = 4
	// bytes 16-31: salt (16 bytes)
	// bytes 32-55: wrap (24 bytes)
	return data
}

func TestCIFKeyMaterialUnmarshalValidRoundtrip(t *testing.T) {
	data := buildValidKMData()
	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if km.Version != 1 || km.PacketType != 2 || km.Sign != 0x2029 {
		t.Errorf("basic fields: V=%d PT=%d Sign=%#x", km.Version, km.PacketType, km.Sign)
	}
	if km.Cipher != 2 || km.Authentication != 0 || km.StreamEncapsulation != 2 {
		t.Errorf("crypto fields: Cipher=%d Auth=%d SE=%d", km.Cipher, km.Authentication, km.StreamEncapsulation)
	}
	if km.SLen != 16 || km.KLen != 16 {
		t.Errorf("lengths: SLen=%d KLen=%d", km.SLen, km.KLen)
	}
	if len(km.Salt) != 16 || len(km.Wrap) != 24 {
		t.Errorf("data lengths: Salt=%d Wrap=%d", len(km.Salt), len(km.Wrap))
	}
}

func TestCIFKeyMaterialInvalidVersion(t *testing.T) {
	data := buildValidKMData()
	// Set version to 2 (invalid): byte 0 = S=0, Version=2, PT=2 => 0b0_010_0010 = 0x22
	data[0] = 0x22
	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err == nil {
		t.Error("expected error for invalid version")
	}
}

func TestCIFKeyMaterialInvalidPacketType(t *testing.T) {
	data := buildValidKMData()
	// Set packet type to 3 (invalid): byte 0 = S=0, Version=1, PT=3 => 0b0_001_0011 = 0x13
	data[0] = 0x13
	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err == nil {
		t.Error("expected error for invalid packet type")
	}
}

func TestCIFKeyMaterialInvalidSignature(t *testing.T) {
	data := buildValidKMData()
	binary.BigEndian.PutUint16(data[1:], 0xBEEF) // wrong signature
	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err == nil {
		t.Error("expected error for invalid signature")
	}
}

func TestCIFKeyMaterialNoKeyIndicated(t *testing.T) {
	data := buildValidKMData()
	data[3] = 0x00 // KF=0 (no key)
	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err == nil {
		t.Error("expected error for KF=0")
	}
}

func TestCIFKeyMaterialUnsupportedCipher(t *testing.T) {
	data := buildValidKMData()
	data[8] = 3 // invalid cipher (not 2 or 4)
	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err == nil {
		t.Error("expected error for unsupported cipher")
	}
}

func TestCIFKeyMaterialGCMNoAuth(t *testing.T) {
	data := buildValidKMData()
	data[8] = 4 // AES-GCM
	data[9] = 0 // Auth=0 (wrong for GCM)
	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err == nil {
		t.Error("expected error: GCM requires auth=1")
	}
}

func TestCIFKeyMaterialCTRWithAuth(t *testing.T) {
	data := buildValidKMData()
	data[8] = 2 // AES-CTR
	data[9] = 1 // Auth=1 (wrong for CTR)
	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err == nil {
		t.Error("expected error: CTR requires auth=0")
	}
}

func TestCIFKeyMaterialInvalidSE(t *testing.T) {
	data := buildValidKMData()
	data[10] = 1 // invalid SE (not 2)
	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err == nil {
		t.Error("expected error for invalid stream encapsulation")
	}
}

func TestCIFKeyMaterialInvalidKeyLength(t *testing.T) {
	data := buildValidKMData()
	data[15] = 5 // KLen = 20 bytes (invalid, not 16/24/32)
	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err == nil {
		t.Error("expected error for invalid key length")
	}
}

func TestCIFKeyMaterialInvalidSaltLength(t *testing.T) {
	data := buildValidKMData()
	data[14] = 3 // SLen = 12 bytes (invalid, must be 16)
	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err == nil {
		t.Error("expected error for invalid salt length")
	}
}

func TestCIFKeyMaterialDataTooShortForSalt(t *testing.T) {
	// 16 header + only 8 bytes of salt (need 16)
	data := make([]byte, 24)
	data[0] = 0x12 // S=0, V=1, PT=2
	binary.BigEndian.PutUint16(data[1:], 0x2029)
	data[3] = 0x01 // KF=even
	data[8] = 2    // CTR
	data[9] = 0    // auth=0
	data[10] = 2   // SE=2
	data[14] = 4   // SLen=16
	data[15] = 4   // KLen=16

	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err == nil {
		t.Error("expected error for data too short for salt")
	}
}

func TestCIFKeyMaterialDataTooShortForWrap(t *testing.T) {
	// 16 header + 16 salt + only 8 bytes (need 24 for wrap)
	data := make([]byte, 40)
	data[0] = 0x12
	binary.BigEndian.PutUint16(data[1:], 0x2029)
	data[3] = 0x01
	data[8] = 2
	data[9] = 0
	data[10] = 2
	data[14] = 4
	data[15] = 4

	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err == nil {
		t.Error("expected error for data too short for wrap")
	}
}

func TestCIFKeyMaterialLengthInconsistent(t *testing.T) {
	// Valid except extra trailing bytes
	data := buildValidKMData()
	data = append(data, 0xFF, 0xFF, 0xFF, 0xFF) // extra 4 bytes
	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err == nil {
		t.Error("expected error for length inconsistency")
	}
}

func TestCIFKeyMaterialBothKeys(t *testing.T) {
	// Build valid KM with EncryptionBoth (2 keys)
	// 16 header + 16 salt + (2*16 + 8) wrap = 16 + 16 + 40 = 72 bytes
	data := make([]byte, 72)
	data[0] = 0x12
	binary.BigEndian.PutUint16(data[1:], 0x2029)
	data[3] = 0x03 // KF=both (EncryptionBoth)
	data[8] = 2
	data[9] = 0
	data[10] = 2
	data[14] = 4 // SLen=16
	data[15] = 4 // KLen=16

	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if km.KeyBasedEncryption != EncryptionBoth {
		t.Errorf("KBE: got %d, want %d", km.KeyBasedEncryption, EncryptionBoth)
	}
	if len(km.Wrap) != 40 {
		t.Errorf("Wrap length: got %d, want 40", len(km.Wrap))
	}
}

func TestCIFKeyMaterialGCMValid(t *testing.T) {
	// Build valid KM with AES-GCM cipher (4) and auth=1
	data := buildValidKMData()
	data[8] = 4 // AES-GCM
	data[9] = 1 // auth=GCM

	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if km.Cipher != 4 || km.Authentication != 1 {
		t.Errorf("Cipher=%d Auth=%d, want Cipher=4 Auth=1", km.Cipher, km.Authentication)
	}
}

func TestCIFKeyMaterialSLenZero(t *testing.T) {
	// Valid KM with SLen=0 (no salt)
	// 16 header + 0 salt + (1*16 + 8) wrap = 40 bytes
	data := make([]byte, 40)
	data[0] = 0x12
	binary.BigEndian.PutUint16(data[1:], 0x2029)
	data[3] = 0x01
	data[8] = 2
	data[9] = 0
	data[10] = 2
	data[14] = 0 // SLen=0
	data[15] = 4 // KLen=16

	km := &CIFKeyMaterial{}
	if err := km.UnmarshalCIF(data); err != nil {
		t.Fatalf("UnmarshalCIF: %v", err)
	}
	if km.SLen != 0 {
		t.Errorf("SLen: got %d, want 0", km.SLen)
	}
	if len(km.Salt) != 0 {
		t.Errorf("Salt length: got %d, want 0", len(km.Salt))
	}
}

// --- Packet.MarshalCIF error path ---

type errCIF struct{}

func (e *errCIF) MarshalCIF() ([]byte, error) {
	return nil, fmt.Errorf("mock marshal error")
}
func (e *errCIF) UnmarshalCIF([]byte) error {
	return nil
}

func TestPacketMarshalCIFError(t *testing.T) {
	p := NewControl(nil, CtrlTypeHandshake, 42, 1000)
	defer p.Release()

	err := p.MarshalCIF(&errCIF{})
	if err == nil {
		t.Error("expected error from MarshalCIF")
	}
}

// --- putBuffer undersized rejection ---

func TestPutBufferUndersized(t *testing.T) {
	// putBuffer should silently discard buffers smaller than MaxPayloadSize
	small := make([]byte, 10)
	putBuffer(small) // should not panic
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
