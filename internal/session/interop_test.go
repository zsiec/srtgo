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

// streamEncrypted runs a 300-payload AES-CTR stream from caller (a Session) to
// a reader goroutine, used by the encrypted listener tests below.
func streamEncrypted(t *testing.T, write func([]byte) error, read func([]byte) (int, error)) {
	t.Helper()
	const (
		n          = 300
		payloadLen = 1200
	)
	recvd := make(chan error, 1)
	go func() {
		buf := make([]byte, 2000)
		for i := 0; i < n; i++ {
			got, err := read(buf)
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
	go func() {
		for i := 0; i < n; i++ {
			p := make([]byte, payloadLen)
			binary.BigEndian.PutUint32(p, uint32(i))
			if err := write(p); err != nil {
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
		t.Fatal("timeout: not all encrypted payloads received")
	}
}

const encPass = "0123456789abcdef" // 16 bytes, within SRT's 10-80 range

// TestNewStackFEC verifies the new stack negotiates a FEC packet filter through
// the handshake and the sender emits repair packets the driver carries through
// to the receiver without breaking delivery.
func TestNewStackFEC(t *testing.T) {
	const fecCfg = "fec,cols:8,rows:4,arq:onreq" // 2D staircase FEC end-to-end

	luconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := session.Listen(luconn, core.ListenerConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
		FilterConfig: fecCfg,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan *session.Session, 1)
	go func() {
		if s, err := ln.Accept(); err == nil {
			accepted <- s
		}
	}()

	cuconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	caller, err := session.Dial(cuconn, ln.Addr(), core.DialConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
		FilterConfig: fecCfg,
	}, nil, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer caller.Close()

	var recv *session.Session
	select {
	case recv = <-accepted:
		defer recv.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not accept")
	}

	streamEncrypted(t, caller.Write, recv.Read) // 300 payloads

	cs, err := caller.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if cs.SentFEC == 0 {
		t.Errorf("caller SentFEC = 0, expected FEC repair packets (filter not negotiated?)")
	}
}

// TestStats streams new-to-new and checks both ends' Stats() snapshots.
func TestStats(t *testing.T) {
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

	accepted := make(chan *session.Session, 1)
	go func() {
		if s, err := ln.Accept(); err == nil {
			accepted <- s
		}
	}()

	cuconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	caller, err := session.Dial(cuconn, ln.Addr(), core.DialConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
	}, nil, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer caller.Close()

	var recv *session.Session
	select {
	case recv = <-accepted:
		defer recv.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not accept")
	}

	streamEncrypted(t, caller.Write, recv.Read) // 300 payloads
	time.Sleep(150 * time.Millisecond)          // let the last ACKs/ACKACKs flow

	cs, err := caller.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if cs.SentPackets < 300 {
		t.Errorf("caller SentPackets = %d, want >= 300", cs.SentPackets)
	}
	if cs.RecvACKs == 0 {
		t.Errorf("caller RecvACKs = 0, expected ACKs from the receiver")
	}
	if cs.RTTMicros <= 0 {
		t.Errorf("caller RTTMicros = %d, expected a measured RTT", cs.RTTMicros)
	}

	rs, err := recv.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if rs.RecvPackets < 300 {
		t.Errorf("receiver RecvPackets = %d, want >= 300", rs.RecvPackets)
	}
	if rs.SentACKs == 0 {
		t.Errorf("receiver SentACKs = 0, expected periodic ACKs")
	}
}

// TestNewStackEncryptedEndToEnd runs the full new stack with AES-CTR: the new
// listener unwraps the new caller's KMREQ and decrypts its data.
func TestNewStackEncryptedEndToEnd(t *testing.T) {
	luconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := session.Listen(luconn, core.ListenerConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
		Passphrase: encPass,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan *session.Session, 1)
	go func() {
		s, err := ln.Accept()
		if err == nil {
			accepted <- s
		}
	}()

	cuconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	caller, err := session.Dial(cuconn, ln.Addr(), core.DialConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
		Passphrase: encPass, KeyLength: 16,
	}, nil, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer caller.Close()

	var recv *session.Session
	select {
	case recv = <-accepted:
		defer recv.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not accept")
	}

	streamEncrypted(t, caller.Write, recv.Read)
}

// TestInteropLegacyEncryptedCallerToNewListener: the legacy encrypted caller
// connects to the new listener, which unwraps the key material and decrypts.
func TestInteropLegacyEncryptedCallerToNewListener(t *testing.T) {
	uconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := session.Listen(uconn, core.ListenerConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
		Passphrase: encPass,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan *session.Session, 1)
	go func() {
		if s, err := ln.Accept(); err == nil {
			accepted <- s
		}
	}()

	cfg := srt.DefaultConfig()
	cfg.Latency = 120 * time.Millisecond
	cfg.Passphrase = encPass
	caller, err := srt.Dial(ln.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer caller.Close()

	var recv *session.Session
	select {
	case recv = <-accepted:
		defer recv.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not accept")
	}

	streamEncrypted(t, func(b []byte) error { _, err := caller.Write(b); return err }, recv.Read)
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
