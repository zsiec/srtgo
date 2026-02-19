package mux

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/packet"
)

func TestMuxDispatchToConnection(t *testing.T) {
	// Set up a UDP socket pair
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	m := New(serverConn, DefaultMSS)
	defer m.Close()

	socketID := uint32(42)
	ch := m.Register(socketID)

	// Send a packet to the mux from a "client"
	clientConn, err := net.Dial("udp", serverConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	// Build a data packet with DestinationSocketID = 42
	var raw [packet.HeaderSize + 4]byte
	binary.BigEndian.PutUint32(raw[0:], 1)          // seq=1
	binary.BigEndian.PutUint32(raw[4:], 0xC0000001) // PP=single, msg=1
	binary.BigEndian.PutUint32(raw[8:], 1000)       // timestamp
	binary.BigEndian.PutUint32(raw[12:], socketID)  // dest socket ID
	binary.BigEndian.PutUint32(raw[16:], 0xCAFE)    // payload

	_, err = clientConn.Write(raw[:])
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Should receive the packet on the registered channel
	select {
	case p := <-ch:
		defer p.Release()
		if p.Header.DestinationSocketID != socketID {
			t.Errorf("DestSocketID: got %d, want %d", p.Header.DestinationSocketID, socketID)
		}
		if p.Header.SequenceNumber != 1 {
			t.Errorf("SeqNo: got %d, want 1", p.Header.SequenceNumber)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for packet")
	}
}

func TestMuxHandshakeChannel(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	m := New(serverConn, DefaultMSS)
	defer m.Close()

	clientConn, err := net.Dial("udp", serverConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	// Build a control packet with DestinationSocketID = 0 (handshake)
	var raw [packet.HeaderSize + 48]byte
	binary.BigEndian.PutUint16(raw[0:], 0x8000) // control, type=HANDSHAKE
	binary.BigEndian.PutUint16(raw[2:], 0)      // subtype
	binary.BigEndian.PutUint32(raw[4:], 0)      // type specific
	binary.BigEndian.PutUint32(raw[8:], 0)      // timestamp
	binary.BigEndian.PutUint32(raw[12:], 0)     // dest socket ID = 0

	_, err = clientConn.Write(raw[:])
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case p := <-m.Handshake:
		defer p.Release()
		if !p.Header.IsControl {
			t.Error("expected control packet")
		}
		if p.Header.ControlType != packet.CtrlTypeHandshake {
			t.Errorf("type: got %v, want HANDSHAKE", p.Header.ControlType)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handshake packet")
	}
}

func TestMuxSend(t *testing.T) {
	// Set up listener
	receiverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer receiverConn.Close()

	// Set up mux with a different socket
	senderConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	m := New(senderConn, DefaultMSS)
	defer m.Close()

	// Send a packet through the mux
	p := packet.NewData(receiverConn.LocalAddr(), 42, 1234, 100, []byte("hello"))
	defer p.Release()

	err = m.Send(p)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Read on receiver side
	buf := make([]byte, DefaultMSS)
	receiverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := receiverConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}

	received, err := packet.Parse(buf[:n], nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	defer received.Release()

	if received.Header.SequenceNumber != 42 {
		t.Errorf("seq: got %d, want 42", received.Header.SequenceNumber)
	}
	if string(received.Data) != "hello" {
		t.Errorf("data: got %q, want %q", received.Data, "hello")
	}
}

func TestMuxUnregister(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	m := New(serverConn, DefaultMSS)
	defer m.Close()

	socketID := uint32(99)
	ch := m.Register(socketID)
	m.Unregister(socketID)

	// Send a packet — it should be dropped (not dispatched)
	clientConn, err := net.Dial("udp", serverConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	var raw [packet.HeaderSize]byte
	binary.BigEndian.PutUint32(raw[12:], socketID)
	clientConn.Write(raw[:])

	select {
	case <-ch:
		t.Error("should not receive after Unregister")
	case <-time.After(200 * time.Millisecond):
		// Good — packet was dropped
	}
}

func TestMuxLocalAddr(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	m := New(serverConn, DefaultMSS)
	defer m.Close()

	localAddr := m.LocalAddr()
	if localAddr == nil {
		t.Fatal("LocalAddr should not be nil")
	}

	// Should match the underlying conn's address
	expected := serverConn.LocalAddr()
	if localAddr.String() != expected.String() {
		t.Errorf("LocalAddr: got %s, want %s", localAddr.String(), expected.String())
	}
	if localAddr.Network() != expected.Network() {
		t.Errorf("LocalAddr network: got %s, want %s", localAddr.Network(), expected.Network())
	}
}

func TestMuxLocalAddrFormat(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	m := New(serverConn, DefaultMSS)
	defer m.Close()

	addr := m.LocalAddr()

	// Should be a UDP address on 127.0.0.1
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", addr)
	}

	if !udpAddr.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("expected IP 127.0.0.1, got %s", udpAddr.IP)
	}

	if udpAddr.Port == 0 {
		t.Error("expected non-zero port")
	}
}

func TestMuxSendNilAddr(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	m := New(serverConn, DefaultMSS)
	defer m.Close()

	// Build a packet with nil Addr
	p := packet.Packet{
		Header: packet.Header{
			SequenceNumber:      1,
			DestinationSocketID: 42,
			Timestamp:           1000,
			Addr:                nil, // nil address
		},
		Data: []byte("test"),
	}

	err = m.Send(p)
	if err == nil {
		t.Error("expected error for nil Addr")
	}
}

func TestMuxSendLargePayload(t *testing.T) {
	// Test that Send handles payloads larger than the pooled buffer
	receiverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer receiverConn.Close()

	// Create mux with very small MSS so pool buffer is tiny
	senderConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	m := New(senderConn, 64) // very small MSS
	defer m.Close()

	// Create a large payload that exceeds the small pool buffer
	largePayload := make([]byte, 200)
	for i := range largePayload {
		largePayload[i] = byte(i)
	}

	p := packet.NewData(receiverConn.LocalAddr(), 42, 1234, 100, largePayload)
	defer p.Release()

	err = m.Send(p)
	if err != nil {
		t.Fatalf("Send with large payload: %v", err)
	}

	// Verify it arrives correctly
	buf := make([]byte, 2000)
	receiverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := receiverConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}

	received, err := packet.Parse(buf[:n], nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	defer received.Release()

	if received.Header.SequenceNumber != 42 {
		t.Errorf("seq: got %d, want 42", received.Header.SequenceNumber)
	}
	if len(received.Data) != len(largePayload) {
		t.Errorf("data length: got %d, want %d", len(received.Data), len(largePayload))
	}
}

func TestMuxDefaultMSS(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	// MSS=0 should use DefaultMSS
	m := New(serverConn, 0)
	defer m.Close()

	// Verify the mux works by doing a simple local addr check
	addr := m.LocalAddr()
	if addr == nil {
		t.Fatal("expected non-nil LocalAddr even with MSS=0")
	}
}

func TestMuxDropWhenChannelFull(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	m := New(serverConn, DefaultMSS)
	defer m.Close()

	socketID := uint32(77)
	ch := m.Register(socketID)

	clientConn, err := net.Dial("udp", serverConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	// Fill the channel (buffer size = 256) by sending many packets quickly
	var raw [packet.HeaderSize + 4]byte
	binary.BigEndian.PutUint32(raw[12:], socketID)
	binary.BigEndian.PutUint32(raw[16:], 0xCAFE)

	for i := 0; i < 300; i++ {
		binary.BigEndian.PutUint32(raw[0:], uint32(i+1)) // unique seq
		binary.BigEndian.PutUint32(raw[8:], uint32(i))   // timestamp
		clientConn.Write(raw[:])
	}

	// Wait a bit for packets to arrive
	time.Sleep(500 * time.Millisecond)

	// Drain what we can
	drained := 0
	for {
		select {
		case <-ch:
			drained++
		default:
			goto done
		}
	}
done:
	// We sent 300 but channel capacity is 256, so some should have been dropped
	if drained > 256 {
		t.Errorf("should not receive more than channel capacity: got %d", drained)
	}
}

func TestMuxHandshakeDropWhenFull(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	m := New(serverConn, DefaultMSS)
	defer m.Close()

	clientConn, err := net.Dial("udp", serverConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	// Flood with handshake packets (destSocketID=0) to fill the handshake channel (128)
	var raw [packet.HeaderSize + 48]byte
	binary.BigEndian.PutUint16(raw[0:], 0x8000) // control, type=HANDSHAKE
	binary.BigEndian.PutUint32(raw[12:], 0)     // dest socket ID = 0

	for i := 0; i < 200; i++ {
		binary.BigEndian.PutUint32(raw[8:], uint32(i)) // vary timestamp
		clientConn.Write(raw[:])
	}

	time.Sleep(500 * time.Millisecond)

	// Drain handshake channel
	drained := 0
	for {
		select {
		case <-m.Handshake:
			drained++
		default:
			goto done2
		}
	}
done2:
	if drained > 128 {
		t.Errorf("should not receive more than handshake channel capacity: got %d", drained)
	}
}

func TestMuxInvalidPacketDropped(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	m := New(serverConn, DefaultMSS)
	defer m.Close()

	socketID := uint32(55)
	ch := m.Register(socketID)

	clientConn, err := net.Dial("udp", serverConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	// Send a packet that's too short to parse (less than header size)
	clientConn.Write([]byte{0x01, 0x02, 0x03})

	// Then send a valid packet
	time.Sleep(100 * time.Millisecond)
	var raw [packet.HeaderSize + 4]byte
	binary.BigEndian.PutUint32(raw[0:], 1)
	binary.BigEndian.PutUint32(raw[12:], socketID)
	binary.BigEndian.PutUint32(raw[16:], 0xBEEF)
	clientConn.Write(raw[:])

	// Should only receive the valid packet
	select {
	case p := <-ch:
		defer p.Release()
		if p.Header.SequenceNumber != 1 {
			t.Errorf("expected seqno 1, got %d", p.Header.SequenceNumber)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for valid packet")
	}
}

func TestMuxUnregisteredSocketDropped(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	m := New(serverConn, DefaultMSS)
	defer m.Close()

	// Register socket 10 but send packet to socket 99 (unregistered)
	ch := m.Register(10)

	clientConn, err := net.Dial("udp", serverConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	// Send packet to unregistered socket 99
	var raw [packet.HeaderSize + 4]byte
	binary.BigEndian.PutUint32(raw[0:], 1)
	binary.BigEndian.PutUint32(raw[12:], 99) // unregistered
	binary.BigEndian.PutUint32(raw[16:], 0xDEAD)
	clientConn.Write(raw[:])

	// Should not appear on registered channel
	select {
	case <-ch:
		t.Error("should not receive packet for unregistered socket")
	case <-time.After(300 * time.Millisecond):
		// Good — packet was dropped
	}
}

func TestMuxClose(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	m := New(serverConn, DefaultMSS)

	err = m.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Double close should not panic
	// (conn is already closed, so this may return an error, which is fine)
	_ = m.Close()
}
