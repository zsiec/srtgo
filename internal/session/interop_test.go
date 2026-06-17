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

// TestInteropLegacyCallerToNewListener runs the handshake in the other
// direction: the EXISTING legacy srt.Dial caller connects to the new Sans-I/O
// listener (session.Listen) over real UDP and streams data. This closes the
// compatibility loop — the new listener's induction/conclusion responses and
// receive path are wire-compatible with the production caller.
func TestInteropLegacyCallerToNewListener(t *testing.T) {
	const (
		n          = 300
		payloadLen = 1200
	)

	uconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := session.Listen(uconn, core.ListenerConfig{
		Live:          true,
		MaxBW:         125_000_000,
		RecvLatencyMS: 120,
		SendLatencyMS: 120,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	recvd := make(chan error, 1)
	go func() {
		s, err := ln.Accept()
		if err != nil {
			recvd <- fmt.Errorf("accept: %w", err)
			return
		}
		defer s.Close()
		buf := make([]byte, 2000)
		for i := 0; i < n; i++ {
			got, err := s.Read(buf)
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

	cfg := srt.DefaultConfig()
	cfg.Latency = 120 * time.Millisecond
	caller, err := srt.Dial(ln.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer caller.Close()

	go func() {
		for i := 0; i < n; i++ {
			p := make([]byte, payloadLen)
			binary.BigEndian.PutUint32(p, uint32(i))
			if _, err := caller.Write(p); err != nil {
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
		t.Fatal("timeout: new listener did not receive all payloads")
	}
}

// TestNewStackEndToEnd connects the new Sans-I/O caller to the new Sans-I/O
// listener — the full rebuilt stack with no legacy code in the path.
func TestNewStackEndToEnd(t *testing.T) {
	const (
		n          = 400
		payloadLen = 1200
	)

	luconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := session.Listen(luconn, core.ListenerConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	recvd := make(chan error, 1)
	go func() {
		s, err := ln.Accept()
		if err != nil {
			recvd <- fmt.Errorf("accept: %w", err)
			return
		}
		defer s.Close()
		buf := make([]byte, 2000)
		for i := 0; i < n; i++ {
			got, err := s.Read(buf)
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

	cuconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.Dial(cuconn, ln.Addr(), core.DialConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
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
		t.Fatal("timeout: new stack did not deliver all payloads")
	}
}

// TestInteropEncryptedCallerToLegacyListener does the same as the plaintext
// interop test but with AES-CTR encryption: the new caller wraps its session
// key into the CONCLUSION KMREQ and encrypts every data packet; the legacy
// listener unwraps the key and decrypts. Proves the handshake key exchange and
// the encrypted data path are wire-compatible.
func TestInteropEncryptedCallerToLegacyListener(t *testing.T) {
	const (
		n          = 300
		payloadLen = 1200
		passphrase = "0123456789abcdef" // 16 bytes, within SRT's 10-80 range
	)

	cfg := srt.DefaultConfig()
	cfg.Latency = 120 * time.Millisecond
	cfg.Passphrase = passphrase
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
		Live:          true,
		MaxBW:         125_000_000,
		RecvLatencyMS: 120,
		SendLatencyMS: 120,
		Passphrase:    passphrase,
		KeyLength:     16,
		CryptoMode:    0, // AES-CTR
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
		t.Fatal("timeout: legacy listener did not receive all encrypted payloads")
	}
}
