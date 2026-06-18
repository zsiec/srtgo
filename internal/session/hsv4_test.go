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

// TestInteropHSv4CallerToLegacyListener drives the new Sans-I/O caller in legacy
// HSv4 mode (ForceHSv4) against the production srt.Listen listener: a UDT_DGRAM
// CONCLUSION followed by a post-handshake HSREQ over UMSG_EXT. The legacy
// listener downgrades to its HSv4 path (handleConclusionV4) and its connection
// processes the HSREQ; every payload must arrive in order — proving the new
// HSv4 handshake + data path is wire-compatible with the production stack.
func TestInteropHSv4CallerToLegacyListener(t *testing.T) {
	const (
		n          = 100
		payloadLen = 1000
	)

	cfg := srt.DefaultConfig()
	cfg.Latency = 120 * time.Millisecond
	ln, err := srt.Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

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

	uconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.Dial(uconn, ln.Addr(), core.DialConfig{
		MaxBW:         125_000_000,
		RecvLatencyMS: 120,
		SendLatencyMS: 120,
		ForceHSv4:     true, // legacy HSv4 handshake
	}, nil, 5*time.Second)
	if err != nil {
		t.Fatalf("dial (HSv4): %v", err)
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
		t.Fatal("timeout: legacy listener did not receive all HSv4 payloads")
	}
}
