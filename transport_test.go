package srt

import (
	"net"
	"testing"
	"time"
)

func TestDialPacketConn(t *testing.T) {
	// Start a listener to dial into
	ln, err := Listen("127.0.0.1:0", DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Create our own PacketConn
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.ConnTimeout = 2 * time.Second

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	conn, err := DialPacketConn(pc, ln.Addr(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	<-done
}

func TestListenPacketConn(t *testing.T) {
	// Create our own PacketConn
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	ln, err := ListenPacketConn(pc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Verify the listener works by dialing into it
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	dialCfg := DefaultConfig()
	dialCfg.ConnTimeout = 2 * time.Second
	conn, err := Dial(ln.Addr().String(), dialCfg)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	<-done
}

func TestDialPacketConn_InvalidConfig(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	cfg := DefaultConfig()
	cfg.Passphrase = "short" // Too short — must be 10-79 chars

	_, err = DialPacketConn(pc, &net.UDPAddr{}, cfg)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestListenPacketConn_InvalidConfig(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	cfg := DefaultConfig()
	cfg.Passphrase = "short"

	_, err = ListenPacketConn(pc, cfg)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestDialRendezvousPacketConn_InvalidConfig(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	cfg := DefaultConfig()
	cfg.Passphrase = "short"

	_, err = DialRendezvousPacketConn(pc, &net.UDPAddr{}, cfg)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}
