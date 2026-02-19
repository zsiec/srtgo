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
