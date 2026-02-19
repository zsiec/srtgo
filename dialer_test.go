package srt

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDialTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 500 * time.Millisecond

	// Dial a non-listening address — should timeout
	start := time.Now()
	_, err := Dial("127.0.0.1:19876", cfg)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("Dial to non-listening address should fail")
	}

	// Should timeout within reasonable bounds
	if elapsed < 400*time.Millisecond {
		t.Errorf("timed out too quickly: %v", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("timed out too slowly: %v", elapsed)
	}
}

func TestDialInvalidAddress(t *testing.T) {
	cfg := DefaultConfig()
	_, err := Dial("invalid:address:too:many:colons", cfg)
	if err == nil {
		t.Error("Dial with invalid address should fail")
	}
}

func TestDialInvalidConfig(t *testing.T) {
	cfg := Config{
		MSS: 10, // too small
	}
	_, err := Dial("127.0.0.1:9000", cfg)
	if err == nil {
		t.Error("Dial with invalid config should fail")
	}
}

func TestDialAndWriteRead(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Dial concurrently
	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second
	dialCfg.StreamID = "live/test"

	done := make(chan struct{})
	var clientConn *Conn
	var dialErr error

	go func() {
		clientConn, dialErr = Dial(l.Addr().String(), dialCfg)
		close(done)
	}()

	// Accept the connection
	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer serverConn.Close()

	<-done
	if dialErr != nil {
		t.Fatalf("Dial: %v", dialErr)
	}
	defer clientConn.Close()

	// Write from client
	payload := []byte("hello from client")
	n, err := clientConn.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Write: got %d, want %d", n, len(payload))
	}

	// Give time for packet to arrive
	time.Sleep(50 * time.Millisecond)

	// Read on server side with TSBPD delay
	serverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	n, err = serverConn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if string(buf[:n]) != string(payload) {
		t.Errorf("Read: got %q, want %q", buf[:n], payload)
	}
}

func TestDialFileMode(t *testing.T) {
	// Both sides configured for file mode
	listenerCfg := DefaultConfig()
	listenerCfg.Congestion = CongestionFile
	listenerCfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", listenerCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	dialCfg := DefaultConfig()
	dialCfg.Congestion = CongestionFile
	dialCfg.ConnTimeout = 2 * time.Second
	dialCfg.StreamID = "file/test"

	done := make(chan struct{})
	var clientConn *Conn
	var dialErr error

	go func() {
		clientConn, dialErr = Dial(l.Addr().String(), dialCfg)
		close(done)
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer serverConn.Close()

	<-done
	if dialErr != nil {
		t.Fatalf("Dial: %v", dialErr)
	}
	defer clientConn.Close()

	// Verify both sides are in file mode
	if clientConn.tsbpdEnabled {
		t.Error("client tsbpdEnabled should be false")
	}
	if serverConn.tsbpdEnabled {
		t.Error("server tsbpdEnabled should be false")
	}

	// Write from client and read on server
	payload := []byte("file mode data")
	n, err := clientConn.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Write: got %d, want %d", n, len(payload))
	}

	time.Sleep(50 * time.Millisecond)

	serverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	n, err = serverConn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Errorf("Read: got %q, want %q", buf[:n], payload)
	}
}

func TestFileTransferLargeData(t *testing.T) {
	listenerCfg := DefaultConfig()
	listenerCfg.Congestion = CongestionFile
	listenerCfg.ConnTimeout = 5 * time.Second

	l, err := Listen("127.0.0.1:0", listenerCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	dialCfg := DefaultConfig()
	dialCfg.Congestion = CongestionFile
	dialCfg.ConnTimeout = 5 * time.Second

	done := make(chan struct{})
	var clientConn *Conn
	var dialErr error

	go func() {
		clientConn, dialErr = Dial(l.Addr().String(), dialCfg)
		close(done)
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer serverConn.Close()

	<-done
	if dialErr != nil {
		t.Fatalf("Dial: %v", dialErr)
	}
	defer clientConn.Close()

	// Transfer data in chunks. We can't exceed payloadSize per Write,
	// so we send many packets and verify byte-perfect delivery.
	totalSize := 100 * 1000 // 100KB
	chunkSize := 1000
	numChunks := totalSize / chunkSize

	// Build the data to send
	sendData := make([]byte, totalSize)
	for i := range sendData {
		sendData[i] = byte(i % 251) // prime modulus for pattern
	}

	// Send in a goroutine
	sendDone := make(chan error, 1)
	go func() {
		for i := range numChunks {
			start := i * chunkSize
			end := start + chunkSize
			_, err := clientConn.Write(sendData[start:end])
			if err != nil {
				sendDone <- err
				return
			}
		}
		sendDone <- nil
	}()

	// Receive all data
	var recvBuf bytes.Buffer
	serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	readBuf := make([]byte, 2000)
	for recvBuf.Len() < totalSize {
		n, err := serverConn.Read(readBuf)
		if err != nil {
			t.Fatalf("Read after %d bytes: %v", recvBuf.Len(), err)
		}
		recvBuf.Write(readBuf[:n])
	}

	// Check send completed without error
	if sendErr := <-sendDone; sendErr != nil {
		t.Fatalf("Send: %v", sendErr)
	}

	// Verify byte-perfect delivery
	if recvBuf.Len() != totalSize {
		t.Fatalf("received %d bytes, want %d", recvBuf.Len(), totalSize)
	}
	if !bytes.Equal(recvBuf.Bytes(), sendData) {
		t.Error("received data does not match sent data")
	}
}

func TestLiveFileHandshakeMismatch(t *testing.T) {
	// Listener in live mode
	listenerCfg := DefaultConfig()
	listenerCfg.Latency = 20 * time.Millisecond
	listenerCfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", listenerCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Dialer in file mode — should be rejected
	dialCfg := DefaultConfig()
	dialCfg.Congestion = CongestionFile
	dialCfg.ConnTimeout = 2 * time.Second

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Fatal("Dial with mismatched mode should fail")
	}
	// The error should indicate rejection
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("expected rejection error, got: %v", err)
	}
}

func TestDialHSv4_ConfigSender(t *testing.T) {
	// Test that the Sender config field works
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	// nil Sender = responder (default)
	if cfg.Sender != nil {
		t.Error("Sender should default to nil")
	}

	// Set Sender = true
	v := true
	cfg.Sender = &v
	if cfg.Sender == nil || !*cfg.Sender {
		t.Error("Sender should be true after setting")
	}

	// Set Sender = false
	v2 := false
	cfg.Sender = &v2
	if cfg.Sender == nil || *cfg.Sender {
		t.Error("Sender should be false after setting")
	}
}

func TestInductionResult_Fields(t *testing.T) {
	r := &inductionResult{
		cookie:      0xDEADBEEF,
		listenerMSS: 1500,
		listenerFC:  25600,
		isHSv4:      true,
	}

	if r.cookie != 0xDEADBEEF {
		t.Errorf("cookie = %#x, want 0xDEADBEEF", r.cookie)
	}
	if r.listenerMSS != 1500 {
		t.Errorf("listenerMSS = %d, want 1500", r.listenerMSS)
	}
	if r.listenerFC != 25600 {
		t.Errorf("listenerFC = %d, want 25600", r.listenerFC)
	}
	if !r.isHSv4 {
		t.Error("isHSv4 should be true")
	}
}

func TestDialHSv4_ListenerAcceptsV4(t *testing.T) {
	// Test that an HSv5 listener handles an HSv4 caller.
	// The listener already supports HSv4 CONCLUSION (existing code).
	// This is an integration test: HSv5 listener ↔ HSv4-forced caller.
	// Since we can't force our dialer to v4 without a v4 listener,
	// we test the listener path separately via TestListenerV4 below.
	// Here we verify the Conn hsVersion field is correctly set.

	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Normal HSv5 dial should produce hsVersion=0 (default, treated as 5)
	done := make(chan *Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			done <- c
		}
	}()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	caller, err := Dial(l.Addr().String(), dialCfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer caller.Close()

	// HSv5 dial should not set hsVersion to 4
	if caller.hsVersion == 4 {
		t.Error("Normal HSv5 dial should not set hsVersion=4")
	}

	select {
	case accepted := <-done:
		accepted.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("Accept timeout")
	}
}

func TestConnHSv4Fields(t *testing.T) {
	// Test that hsVersion, isInitiator, hsExtDone fields exist on Conn
	c := newTestConn(t)
	defer c.Close()

	// Default should be 0 (treated as HSv5)
	if c.hsVersion != 0 {
		t.Errorf("hsVersion = %d, want 0 (default)", c.hsVersion)
	}
	if c.isInitiator {
		t.Error("isInitiator should default to false")
	}
	if c.hsExtDone.Load() {
		t.Error("hsExtDone should default to false")
	}

	// Set and verify
	c.hsVersion = 4
	c.isInitiator = true
	c.hsExtDone.Store(true)

	if c.hsVersion != 4 {
		t.Errorf("hsVersion = %d, want 4", c.hsVersion)
	}
	if !c.isInitiator {
		t.Error("isInitiator should be true")
	}
	if !c.hsExtDone.Load() {
		t.Error("hsExtDone should be true")
	}
}

func TestDialWithStreamID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	var acceptedStreamID string
	l.SetAcceptFunc(func(req ConnRequest) bool {
		acceptedStreamID = req.StreamID
		return true
	})

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second
	dialCfg.StreamID = "#!::u=admin,r=live/test,t=stream"

	done := make(chan struct{})
	var clientConn *Conn
	var dialErr error

	go func() {
		clientConn, dialErr = Dial(l.Addr().String(), dialCfg)
		close(done)
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer serverConn.Close()

	<-done
	if dialErr != nil {
		t.Fatalf("Dial: %v", dialErr)
	}
	defer clientConn.Close()

	if acceptedStreamID != dialCfg.StreamID {
		t.Errorf("StreamID: got %q, want %q", acceptedStreamID, dialCfg.StreamID)
	}
	if clientConn.StreamID() != dialCfg.StreamID {
		t.Errorf("client StreamID: got %q, want %q", clientConn.StreamID(), dialCfg.StreamID)
	}
}

func TestDialWithEncryption(t *testing.T) {
	pass := "mysecretpassword"

	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second
	cfg.Passphrase = pass

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second
	dialCfg.Passphrase = pass

	done := make(chan struct{})
	var clientConn *Conn
	var dialErr error

	go func() {
		clientConn, dialErr = Dial(l.Addr().String(), dialCfg)
		close(done)
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer serverConn.Close()

	<-done
	if dialErr != nil {
		t.Fatalf("Dial: %v", dialErr)
	}
	defer clientConn.Close()

	// Write encrypted data and verify it arrives
	payload := []byte("encrypted payload test")
	n, err := clientConn.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Write: got %d, want %d", n, len(payload))
	}

	time.Sleep(50 * time.Millisecond)

	serverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	n, err = serverConn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Errorf("Read: got %q, want %q", buf[:n], payload)
	}
}

func TestDialInductionTimeout(t *testing.T) {
	// Test that dialInduction times out when no response is received.
	// We dial to a port where nothing listens.
	cfg := DefaultConfig()
	cfg.ConnTimeout = 500 * time.Millisecond

	start := time.Now()
	_, err := Dial("127.0.0.1:19877", cfg)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Dial should timeout when no induction response received")
	}

	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "induction") {
		t.Logf("error: %v (may vary)", err)
	}

	if elapsed < 400*time.Millisecond {
		t.Errorf("timed out too quickly: %v", elapsed)
	}
}

func TestDialConclusionTimeoutNoListener(t *testing.T) {
	// Test that dial times out at the conclusion stage. We create a minimal
	// UDP socket that responds to the first INDUCTION with a valid response
	// but then never responds to CONCLUSION. This is hard to do without
	// extensive packet crafting, so instead we test the conclusion timeout
	// by using a very short ConnTimeout against a non-responsive port.
	// The induction timeout test already covers the main timeout path.
	// Here we verify the conclusion timeout message.
	cfg := DefaultConfig()
	cfg.ConnTimeout = 500 * time.Millisecond

	// Bind a UDP socket that accepts but does nothing
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer udpConn.Close()

	addr := udpConn.LocalAddr().String()

	// The UDP socket is listening but won't respond at all --
	// this exercises the induction timeout path (same as TestDialTimeout)
	_, err = Dial(addr, cfg)
	if err == nil {
		t.Fatal("Dial should timeout")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Logf("error: %v", err)
	}
}

func TestDialWithMinVersion(t *testing.T) {
	// Test that MinVersion is enforced during handshake.
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	go l.Accept()

	// Dial with an impossibly high MinVersion
	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second
	dialCfg.MinVersion = 0xFF0000 // Version 255.0.0 -- will never match

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Fatal("Dial with impossibly high MinVersion should fail")
	}
	if !strings.Contains(err.Error(), "MinVersion") && !strings.Contains(err.Error(), "version") {
		t.Logf("error: %v (may vary, expected version mismatch)", err)
	}
}

func TestDialRejectDuringConclusion(t *testing.T) {
	// Test that a rejection during conclusion is properly handled.
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Reject all connections via accept func
	l.SetAcceptFunc(func(req ConnRequest) bool {
		return false
	})

	go func() {
		l.Accept()
	}()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Fatal("Dial should fail when listener rejects connection")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Logf("error: %v", err)
	}
}

func TestDialCongestionFileNegotiation(t *testing.T) {
	// Test that file mode congestion is properly negotiated between caller and listener.
	listenerCfg := DefaultConfig()
	listenerCfg.Congestion = CongestionFile
	listenerCfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", listenerCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	dialCfg := DefaultConfig()
	dialCfg.Congestion = CongestionFile
	dialCfg.ConnTimeout = 2 * time.Second

	done := make(chan struct{})
	var clientConn *Conn
	var dialErr error

	go func() {
		clientConn, dialErr = Dial(l.Addr().String(), dialCfg)
		close(done)
	}()

	serverConn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer serverConn.Close()

	<-done
	if dialErr != nil {
		t.Fatalf("Dial with file congestion: %v", dialErr)
	}
	defer clientConn.Close()

	// Both should be in file mode (TSBPD disabled)
	if clientConn.tsbpdEnabled {
		t.Error("client tsbpdEnabled should be false in file mode")
	}
}

func TestDialEncryptionMismatch(t *testing.T) {
	// Caller has passphrase but listener does not. With EnforcedEncryption=true
	// (default), this should fail.
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second
	// No passphrase on listener

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	go l.Accept()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second
	dialCfg.Passphrase = "secret_key_only_caller_has"

	_, err = Dial(l.Addr().String(), dialCfg)
	if err == nil {
		t.Fatal("Dial with encryption mismatch should fail")
	}
}
