package session_test

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/session"
)

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

// TestNewStackHSv4 connects a legacy HSv4 (UDT_DGRAM) caller to the new
// Sans-I/O listener over real UDP and streams messages. It proves the
// listener-side HSv4 handshake (v4 CONCLUSION + post-connect HSREQ/HSRSP) and the
// reliable message data path work end to end.
func TestNewStackHSv4(t *testing.T) {
	const (
		n          = 200
		payloadLen = 1200
	)

	luconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := session.Listen(luconn, core.ListenerConfig{
		MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
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
		ForceHSv4: true, Message: true, MaxBW: 125_000_000,
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
		t.Fatal("timeout: HSv4 listener did not deliver all payloads")
	}
}

// TestNewStackHSv4EncryptedRejected proves that requesting encryption on an HSv4
// connection fails loudly rather than silently downgrading to plaintext.
func TestNewStackHSv4EncryptedRejected(t *testing.T) {
	luconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := session.Listen(luconn, core.ListenerConfig{RecvLatencyMS: 120, SendLatencyMS: 120}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if s, err := ln.Accept(); err == nil {
			s.Close()
		}
	}()

	cuconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.Dial(cuconn, ln.Addr(), core.DialConfig{
		ForceHSv4: true, Message: true, Passphrase: "should-not-downgrade", KeyLength: 16,
	}, nil, 2*time.Second)
	if err == nil {
		s.Close()
		t.Fatal("expected encrypted HSv4 dial to fail, got a connection (silent plaintext downgrade)")
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
	// Expanded fields: unique sends, ACKACK responses, negotiated latency, window.
	if cs.SentUniquePackets < 300 {
		t.Errorf("caller SentUniquePackets = %d, want >= 300", cs.SentUniquePackets)
	}
	if cs.SentUniquePackets != cs.SentPackets-cs.RetransPackets {
		t.Errorf("caller SentUniquePackets %d != SentPackets %d - Retrans %d", cs.SentUniquePackets, cs.SentPackets, cs.RetransPackets)
	}
	if cs.SentACKACKs == 0 {
		t.Errorf("caller SentACKACKs = 0, expected ACKACKs in response to ACKs")
	}
	if cs.NegotiatedLatency <= 0 {
		t.Errorf("caller NegotiatedLatency = %d, expected the negotiated TSBPD delay", cs.NegotiatedLatency)
	}
	if cs.FlowWindow <= 0 {
		t.Errorf("caller FlowWindow = %d, expected a positive flow window", cs.FlowWindow)
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
	if rs.RecvUniquePackets < 300 {
		t.Errorf("receiver RecvUniquePackets = %d, want >= 300", rs.RecvUniquePackets)
	}
	if rs.RecvACKACKs == 0 {
		t.Errorf("receiver RecvACKACKs = 0, expected ACKACKs from the sender")
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
