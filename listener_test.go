package srt

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestListenAndAccept(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	if l.Addr() == nil {
		t.Fatal("Addr should not be nil")
	}

	// Dial from a client
	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.StreamID = "live/test"
	dialCfg.ConnTimeout = 2 * time.Second

	var clientConn *Conn
	var dialErr error
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		clientConn, dialErr = Dial(l.Addr().String(), dialCfg)
	}()

	// Accept on the listener side
	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer serverConn.Close()

	wg.Wait()

	if dialErr != nil {
		t.Fatalf("Dial: %v", dialErr)
	}
	defer clientConn.Close()

	// Verify the connection properties
	if serverConn.StreamID() != "live/test" {
		t.Errorf("StreamID: got %q, want %q", serverConn.StreamID(), "live/test")
	}
	if serverConn.SocketID() == 0 {
		t.Error("server SocketID should not be zero")
	}
	if clientConn.SocketID() == 0 {
		t.Error("client SocketID should not be zero")
	}
}

func TestListenAndAcceptNoStreamID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := Dial(l.Addr().String(), dialCfg)
		if err != nil {
			t.Errorf("Dial: %v", err)
			return
		}
		c.Close()
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	serverConn.Close()

	wg.Wait()
}

func TestListenAcceptFunc(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	var receivedStreamID string
	l.SetAcceptFunc(func(req ConnRequest) bool {
		receivedStreamID = req.StreamID
		return req.StreamID == "allowed"
	})

	// Connect with allowed stream ID
	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.StreamID = "allowed"
	dialCfg.ConnTimeout = 2 * time.Second

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := Dial(l.Addr().String(), dialCfg)
		if err != nil {
			t.Errorf("Dial with allowed stream: %v", err)
			return
		}
		c.Close()
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	serverConn.Close()
	wg.Wait()

	if receivedStreamID != "allowed" {
		t.Errorf("AcceptFunc received StreamID: got %q, want %q", receivedStreamID, "allowed")
	}
}

func TestListenAcceptFuncReject(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	l.SetAcceptFunc(func(req ConnRequest) bool {
		return false // reject all
	})

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.StreamID = "rejected"
	dialCfg.ConnTimeout = 1 * time.Second

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Error("Dial should fail when AcceptFunc rejects")
	}
}

func TestListenerClose(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	// Close the listener
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Accept after close should fail
	_, err = l.Accept()
	if err == nil {
		t.Error("Accept after Close should fail")
	}
}

func TestListenInvalidAddress(t *testing.T) {
	cfg := DefaultConfig()
	_, err := Listen("invalid:address:too:many:colons", cfg)
	if err == nil {
		t.Error("Listen with invalid address should fail")
	}
}

func TestListenMultipleConnections(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	const numClients = 3
	var wg sync.WaitGroup

	// Start multiple dialers
	for i := range numClients {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			dialCfg := DefaultConfig()
			dialCfg.Latency = 20 * time.Millisecond
			dialCfg.ConnTimeout = 2 * time.Second

			c, err := Dial(l.Addr().String(), dialCfg)
			if err != nil {
				t.Errorf("Dial %d: %v", id, err)
				return
			}
			time.Sleep(100 * time.Millisecond)
			c.Close()
		}(i)
	}

	// Accept all connections
	conns := make([]*Conn, 0, numClients)
	for range numClients {
		c, err := l.Accept()
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		conns = append(conns, c)
	}

	// Close all server-side connections
	for _, c := range conns {
		c.Close()
	}

	wg.Wait()

	if len(conns) != numClients {
		t.Errorf("accepted %d connections, want %d", len(conns), numClients)
	}
}

func TestFECNegotiation(t *testing.T) {
	fecConfig := "fec,cols:5"

	// Listener with FEC
	serverCfg := DefaultConfig()
	serverCfg.Latency = 20 * time.Millisecond
	serverCfg.ConnTimeout = 2 * time.Second
	serverCfg.PacketFilter = fecConfig

	l, err := Listen("127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Dialer with matching FEC
	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second
	dialCfg.PacketFilter = fecConfig

	var clientConn *Conn
	var dialErr error
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		clientConn, dialErr = Dial(l.Addr().String(), dialCfg)
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer serverConn.Close()

	wg.Wait()
	if dialErr != nil {
		t.Fatalf("Dial: %v", dialErr)
	}
	defer clientConn.Close()

	// Verify both sides have FEC initialized
	if clientConn.fecSender == nil {
		t.Error("client FEC sender should be initialized")
	}
	if clientConn.fecReceiver == nil {
		t.Error("client FEC receiver should be initialized")
	}
	if serverConn.fecSender == nil {
		t.Error("server FEC sender should be initialized")
	}
	if serverConn.fecReceiver == nil {
		t.Error("server FEC receiver should be initialized")
	}
}

func TestFECNegotiationMismatch(t *testing.T) {
	// Listener with FEC cols:5
	serverCfg := DefaultConfig()
	serverCfg.Latency = 20 * time.Millisecond
	serverCfg.ConnTimeout = 2 * time.Second
	serverCfg.PacketFilter = "fec,cols:5"

	l, err := Listen("127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Dialer with mismatching FEC cols:10
	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 1 * time.Second
	dialCfg.PacketFilter = "fec,cols:10"

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Error("Dial should fail when FEC configs don't match")
	}
}

func TestFECDataTransferWithStats(t *testing.T) {
	fecConfig := "fec,cols:5"

	serverCfg := DefaultConfig()
	serverCfg.Latency = 20 * time.Millisecond
	serverCfg.ConnTimeout = 2 * time.Second
	serverCfg.PacketFilter = fecConfig

	l, err := Listen("127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second
	dialCfg.PacketFilter = fecConfig

	var clientConn *Conn
	var dialErr error
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		clientConn, dialErr = Dial(l.Addr().String(), dialCfg)
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer serverConn.Close()

	wg.Wait()
	if dialErr != nil {
		t.Fatalf("Dial: %v", dialErr)
	}
	defer clientConn.Close()

	// Send enough packets to trigger FEC control packet emission.
	// With cols:5, a row FEC packet is emitted every 5 data packets.
	payload := make([]byte, 100)
	for i := range 10 {
		payload[0] = byte(i)
		_, err := clientConn.Write(payload)
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	// Give time for packets to be sent and processed
	time.Sleep(100 * time.Millisecond)

	// Check sender stats: 10 data packets = 2 row FEC packets (at packet 5 and 10)
	clientStats := clientConn.Stats(false)
	if clientStats.SndFilterExtra == 0 {
		t.Error("SndFilterExtra should be > 0 after sending 10 packets with cols:5")
	}

	// Check receiver stats: FEC control packets received
	serverStats := serverConn.Stats(false)
	if serverStats.RcvFilterExtra == 0 {
		t.Error("RcvFilterExtra should be > 0 after receiving FEC packets")
	}
}

func TestFECNoFilterConnectsClean(t *testing.T) {
	// Both sides without FEC — should connect cleanly (baseline)
	serverCfg := DefaultConfig()
	serverCfg.Latency = 20 * time.Millisecond
	serverCfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := Dial(l.Addr().String(), dialCfg)
		if err != nil {
			t.Errorf("Dial: %v", err)
			return
		}
		defer c.Close()
		if c.fecSender != nil {
			t.Error("FEC sender should be nil without PacketFilter")
		}
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer serverConn.Close()

	wg.Wait()

	if serverConn.fecSender != nil {
		t.Error("server FEC sender should be nil without PacketFilter")
	}
}

func TestAcceptRejectFuncAccept(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	var receivedStreamID string
	l.SetAcceptRejectFunc(func(req ConnRequest) RejectReason {
		receivedStreamID = req.StreamID
		return 0 // accept
	})

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.StreamID = "accept-test"
	dialCfg.ConnTimeout = 2 * time.Second

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := Dial(l.Addr().String(), dialCfg)
		if err != nil {
			t.Errorf("Dial: %v", err)
			return
		}
		c.Close()
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	serverConn.Close()
	wg.Wait()

	if receivedStreamID != "accept-test" {
		t.Errorf("AcceptRejectFunc received StreamID: got %q, want %q", receivedStreamID, "accept-test")
	}
}

func TestAcceptRejectFuncRejectPeer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	l.SetAcceptRejectFunc(func(req ConnRequest) RejectReason {
		return RejPeer // reject with standard code
	})

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 1 * time.Second

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Error("Dial should fail when AcceptRejectFunc returns RejPeer")
	}
}

func TestAcceptRejectFuncUserDefined(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Use a user-defined rejection code (>= 2000)
	userCode := RejUserDefined + 42 // 2042
	l.SetAcceptRejectFunc(func(req ConnRequest) RejectReason {
		return userCode
	})

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 1 * time.Second

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Error("Dial should fail when AcceptRejectFunc returns user-defined code")
	}
}

func TestAcceptRejectFuncPrecedence(t *testing.T) {
	// AcceptRejectFunc takes precedence over AcceptFunc
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	acceptFuncCalled := false
	l.SetAcceptFunc(func(req ConnRequest) bool {
		acceptFuncCalled = true
		return true
	})

	rejectFuncCalled := false
	l.SetAcceptRejectFunc(func(req ConnRequest) RejectReason {
		rejectFuncCalled = true
		return 0 // accept
	})

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := Dial(l.Addr().String(), dialCfg)
		if err != nil {
			t.Errorf("Dial: %v", err)
			return
		}
		c.Close()
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	serverConn.Close()
	wg.Wait()

	if !rejectFuncCalled {
		t.Error("AcceptRejectFunc should have been called")
	}
	if acceptFuncCalled {
		t.Error("AcceptFunc should NOT be called when AcceptRejectFunc is set (precedence)")
	}
}

func TestListenerAddr(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	addr := l.Addr()
	if addr == nil {
		t.Fatal("Addr should not be nil")
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", addr)
	}

	if udpAddr.Port == 0 {
		t.Error("listener should have a non-zero port")
	}
}

func TestListenWithEncryption(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.Latency = 20 * time.Millisecond
	serverCfg.ConnTimeout = 2 * time.Second
	serverCfg.Passphrase = "secretpassword1234"
	serverCfg.KeyLength = 16

	l, err := Listen("127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Client with matching passphrase
	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second
	dialCfg.Passphrase = "secretpassword1234"
	dialCfg.KeyLength = 16

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := Dial(l.Addr().String(), dialCfg)
		if err != nil {
			t.Errorf("Dial with matching passphrase: %v", err)
			return
		}
		c.Close()
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	serverConn.Close()
	wg.Wait()
}

func TestListenWithWrongPassphrase(t *testing.T) {
	serverCfg := DefaultConfig()
	serverCfg.Latency = 20 * time.Millisecond
	serverCfg.ConnTimeout = 2 * time.Second
	serverCfg.Passphrase = "correctpassword1234"
	serverCfg.KeyLength = 16

	l, err := Listen("127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Client with wrong passphrase
	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 1 * time.Second
	dialCfg.Passphrase = "wrongpassword12345"
	dialCfg.KeyLength = 16

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Error("Dial should fail with wrong passphrase")
	}
}

func TestListenWithEncryptionEnforced(t *testing.T) {
	// Server requires encryption, client doesn't provide it
	serverCfg := DefaultConfig()
	serverCfg.Latency = 20 * time.Millisecond
	serverCfg.ConnTimeout = 2 * time.Second
	serverCfg.Passphrase = "secretpassword1234"
	serverCfg.KeyLength = 16
	enforced := true
	serverCfg.EnforcedEncryption = &enforced

	l, err := Listen("127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Client without encryption
	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 1 * time.Second

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Error("Dial should fail when server requires encryption and client doesn't provide it")
	}
}

func TestListenWithLogger(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second
	cfg.Logger = StdLogger(nil) // nil writer — just verifies no panic

	// Use a real writer for the test
	var buf = &safeBuffer{}
	cfg.Logger = StdLogger(buf)

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := Dial(l.Addr().String(), dialCfg)
		if err != nil {
			t.Errorf("Dial: %v", err)
			return
		}
		c.Close()
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	serverConn.Close()
	wg.Wait()
}

// safeBuffer is a bytes.Buffer safe for concurrent writes (used by logger in tests).
type safeBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func TestListenWithSocketOptions(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second
	cfg.IPTTL = 64
	cfg.IPTOS = 0x10

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := Dial(l.Addr().String(), dialCfg)
		if err != nil {
			t.Errorf("Dial: %v", err)
			return
		}
		c.Close()
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	serverConn.Close()
	wg.Wait()
}

func TestListenRejectCongestionMismatch(t *testing.T) {
	// Listener configured for file mode, dialer uses live mode
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second
	cfg.Congestion = CongestionFile

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second
	// Default congestion is "live" — mismatch with "file"

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Error("Dial should fail with congestion mismatch")
	}
}

func TestListenRejectMinVersion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second
	cfg.MinVersion = 0xFF0000 // impossibly high version

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Error("Dial should fail with MinVersion too high")
	}
}

func TestListenAcceptRejectFunc(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Set a reject function that returns a rejection code
	l.SetAcceptRejectFunc(func(req ConnRequest) RejectReason {
		return RejPeer // always reject
	})

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Error("Dial should fail when AcceptRejectFunc returns rejection")
	}
}

func TestListenAcceptFuncRejectAll(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Set accept function that rejects all
	l.SetAcceptFunc(func(req ConnRequest) bool {
		return false
	})

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Error("Dial should fail when AcceptFunc returns false")
	}
}

func TestListenEncryptionUnsecure(t *testing.T) {
	// Listener requires encryption, dialer does not send KM
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second
	cfg.Passphrase = "serverpassword"
	enforced := true
	cfg.EnforcedEncryption = &enforced

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Dialer has no passphrase
	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second
	// No Passphrase set

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Error("Dial should fail when server requires encryption but client has none")
	}
}

func TestListenCallerEncryptionNoServer(t *testing.T) {
	// Listener has no encryption, caller sends KM with enforced=true
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second
	// No Passphrase on server
	enforced := true
	cfg.EnforcedEncryption = &enforced

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Dialer sends encryption
	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second
	dialCfg.Passphrase = "clientpassword"

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Error("Dial should fail when caller has encryption but server does not (enforced)")
	}
}
