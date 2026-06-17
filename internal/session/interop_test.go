package session_test

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	srt "github.com/zsiec/srtgo"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/session"
)

// TestInteropCallerToLegacyListener connects the new Sans-I/O caller
// (core.Dial + session.Dial) to the EXISTING legacy srt.Listen listener over
// real UDP and streams data. It proves the new handshake and data path are
// wire-compatible with the production implementation.
func TestInteropCallerToLegacyListener(t *testing.T) {
	const (
		n          = 300
		payloadLen = 1200
	)

	cfg := srt.DefaultConfig()
	cfg.Latency = 120 * time.Millisecond
	ln, err := srt.Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Legacy listener side: accept the new caller and read every payload.
	recvd := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			recvd <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 2000)
		for i := 0; i < n; i++ {
			got, err := conn.Read(buf)
			if err != nil {
				recvd <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			if got != payloadLen || binary.BigEndian.Uint32(buf) != uint32(i) {
				recvd <- fmt.Errorf("payload mismatch at %d (n=%d)", i, got)
				return
			}
		}
		recvd <- nil
	}()

	// New Sans-I/O caller side.
	uconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.Dial(uconn, ln.Addr(), core.DialConfig{
		Live:          true,
		MaxBW:         125_000_000, // ~1 Gbps so the stream finishes quickly
		RecvLatencyMS: 120,
		SendLatencyMS: 120,
	}, nil, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer s.Close()

	go func() {
		for i := 0; i < n; i++ {
			p := make([]byte, payloadLen)
			binary.BigEndian.PutUint32(p, uint32(i))
			if err := s.Write(p); err != nil {
				return
			}
		}
	}()

	select {
	case err := <-recvd:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout: legacy listener did not receive all payloads")
	}
}
