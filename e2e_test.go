package srt

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

// e2eSetup creates a listener and a connected pair of Conns over localhost.
// It returns the server-side conn (accepted), client-side conn (dialed),
// and a cleanup function that closes both connections and the listener.
func e2eSetup(t *testing.T, listenerCfg, dialerCfg Config) (server, client *Conn, cleanup func()) {
	t.Helper()

	l, err := Listen("127.0.0.1:0", listenerCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	var (
		dialConn *Conn
		dialErr  error
		wg       sync.WaitGroup
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		dialConn, dialErr = Dial(l.Addr().String(), dialerCfg)
	}()

	server, err = l.Accept()
	if err != nil {
		l.Close()
		t.Fatalf("Accept: %v", err)
	}

	wg.Wait()
	if dialErr != nil {
		server.Close()
		l.Close()
		t.Fatalf("Dial: %v", dialErr)
	}

	client = dialConn
	cleanup = func() {
		client.Close()
		server.Close()
		l.Close()
	}
	return server, client, cleanup
}

// e2eSetupWithListener is like e2eSetup but also returns the listener,
// useful for tests that need to configure AcceptFunc.
func e2eSetupWithListener(t *testing.T, listenerCfg Config) (*Listener, func()) {
	t.Helper()

	l, err := Listen("127.0.0.1:0", listenerCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	return l, func() { l.Close() }
}

// TestE2EBulkTransfer transfers 1 MB of random data over localhost and
// verifies that the SHA-256 hash matches on both sides.
func TestE2EBulkTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping bulk transfer test in -short mode")
	}
	t.Parallel()

	const totalBytes = 1024 * 1024 // 1 MB
	const chunkSize = 1316         // typical SRT live payload

	listenerCfg := DefaultConfig()
	listenerCfg.Latency = 20 * time.Millisecond
	listenerCfg.ConnTimeout = 10 * time.Second
	listenerCfg.MaxBW = 1_000_000_000

	dialerCfg := DefaultConfig()
	dialerCfg.Latency = 20 * time.Millisecond
	dialerCfg.ConnTimeout = 10 * time.Second
	dialerCfg.MaxBW = 1_000_000_000

	server, client, cleanup := e2eSetup(t, listenerCfg, dialerCfg)
	defer cleanup()

	// Generate random payload
	payload := make([]byte, totalBytes)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	sendHash := sha256.Sum256(payload)

	// Receiver goroutine: read all bytes into a buffer
	type recvResult struct {
		data []byte
		err  error
	}
	recvCh := make(chan recvResult, 1)

	go func() {
		server.SetReadDeadline(time.Now().Add(60 * time.Second))
		received := make([]byte, 0, totalBytes)
		buf := make([]byte, 2048)
		for len(received) < totalBytes {
			n, err := server.Read(buf)
			if err != nil {
				recvCh <- recvResult{received, fmt.Errorf("Read after %d bytes: %w", len(received), err)}
				return
			}
			received = append(received, buf[:n]...)
		}
		recvCh <- recvResult{received, nil}
	}()

	// Sender: write in chunks
	client.SetWriteDeadline(time.Now().Add(60 * time.Second))
	for offset := 0; offset < totalBytes; offset += chunkSize {
		end := offset + chunkSize
		if end > totalBytes {
			end = totalBytes
		}
		if _, err := client.Write(payload[offset:end]); err != nil {
			t.Fatalf("Write at offset %d: %v", offset, err)
		}
	}

	// Wait for receiver
	result := <-recvCh
	if result.err != nil {
		t.Fatalf("Receiver: %v", result.err)
	}

	if len(result.data) < totalBytes {
		t.Fatalf("received %d bytes, want %d", len(result.data), totalBytes)
	}

	recvHash := sha256.Sum256(result.data[:totalBytes])
	if sendHash != recvHash {
		t.Fatal("SHA-256 mismatch: sent and received data differ")
	}

	// Verify stats
	time.Sleep(50 * time.Millisecond) // let stats settle
	clientStats := client.Stats(false)
	if clientStats.SentPackets == 0 {
		t.Error("client SentPackets should be > 0")
	}
	serverStats := server.Stats(false)
	if serverStats.RecvPackets == 0 {
		t.Error("server RecvPackets should be > 0")
	}
	if clientStats.RTT <= 0 {
		t.Errorf("RTT should be > 0, got %v", clientStats.RTT)
	}

	t.Logf("transferred %d bytes: sent_pkts=%d recv_pkts=%d rtt=%v",
		totalBytes, clientStats.SentPackets, serverStats.RecvPackets, clientStats.RTT)
}

// TestE2EEncryptedTransfer transfers 100 KB with AES-128 encryption enabled
// and verifies SHA-256 integrity and KM state.
func TestE2EEncryptedTransfer(t *testing.T) {
	t.Parallel()

	const totalBytes = 100 * 1024 // 100 KB
	const chunkSize = 1316

	passphrase := "test-encryption-key-32ch"

	listenerCfg := DefaultConfig()
	listenerCfg.Latency = 20 * time.Millisecond
	listenerCfg.ConnTimeout = 10 * time.Second
	listenerCfg.MaxBW = 1_000_000_000
	listenerCfg.Passphrase = passphrase

	dialerCfg := DefaultConfig()
	dialerCfg.Latency = 20 * time.Millisecond
	dialerCfg.ConnTimeout = 10 * time.Second
	dialerCfg.MaxBW = 1_000_000_000
	dialerCfg.Passphrase = passphrase

	server, client, cleanup := e2eSetup(t, listenerCfg, dialerCfg)
	defer cleanup()

	// Generate random payload
	payload := make([]byte, totalBytes)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	sendHash := sha256.Sum256(payload)

	// Receiver goroutine
	type recvResult struct {
		data []byte
		err  error
	}
	recvCh := make(chan recvResult, 1)

	go func() {
		server.SetReadDeadline(time.Now().Add(60 * time.Second))
		received := make([]byte, 0, totalBytes)
		buf := make([]byte, 2048)
		for len(received) < totalBytes {
			n, err := server.Read(buf)
			if err != nil {
				recvCh <- recvResult{received, fmt.Errorf("Read after %d bytes: %w", len(received), err)}
				return
			}
			received = append(received, buf[:n]...)
		}
		recvCh <- recvResult{received, nil}
	}()

	// Send in chunks
	client.SetWriteDeadline(time.Now().Add(60 * time.Second))
	for offset := 0; offset < totalBytes; offset += chunkSize {
		end := offset + chunkSize
		if end > totalBytes {
			end = totalBytes
		}
		if _, err := client.Write(payload[offset:end]); err != nil {
			t.Fatalf("Write at offset %d: %v", offset, err)
		}
	}

	// Wait for receiver
	result := <-recvCh
	if result.err != nil {
		t.Fatalf("Receiver: %v", result.err)
	}

	if len(result.data) < totalBytes {
		t.Fatalf("received %d bytes, want %d", len(result.data), totalBytes)
	}

	recvHash := sha256.Sum256(result.data[:totalBytes])
	if sendHash != recvHash {
		t.Fatal("SHA-256 mismatch: encrypted transfer data differs")
	}

	// Verify encryption state: SndKmState==2 means "secured"
	time.Sleep(50 * time.Millisecond)
	clientStats := client.Stats(false)
	if clientStats.SndKmState != 2 {
		t.Errorf("client SndKmState: got %d, want 2 (secured)", clientStats.SndKmState)
	}

	t.Logf("encrypted transfer OK: %d bytes, SndKmState=%d, SentKM=%d",
		totalBytes, clientStats.SndKmState, clientStats.SentKM)
}

// TestE2EFileMode transfers 500 KB using TransTypeFile (reliable, no TSBPD).
func TestE2EFileMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping file mode transfer test in -short mode")
	}
	t.Parallel()

	const totalBytes = 500 * 1024 // 500 KB
	const chunkSize = 1316

	listenerCfg := DefaultConfig()
	listenerCfg.Latency = 20 * time.Millisecond
	listenerCfg.ConnTimeout = 10 * time.Second
	listenerCfg.MaxBW = 1_000_000_000
	listenerCfg.TransType = TransTypeFile

	dialerCfg := DefaultConfig()
	dialerCfg.Latency = 20 * time.Millisecond
	dialerCfg.ConnTimeout = 10 * time.Second
	dialerCfg.MaxBW = 1_000_000_000
	dialerCfg.TransType = TransTypeFile

	server, client, cleanup := e2eSetup(t, listenerCfg, dialerCfg)
	defer cleanup()

	// Generate random payload
	payload := make([]byte, totalBytes)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	sendHash := sha256.Sum256(payload)

	// Receiver goroutine
	type recvResult struct {
		data []byte
		err  error
	}
	recvCh := make(chan recvResult, 1)

	go func() {
		server.SetReadDeadline(time.Now().Add(60 * time.Second))
		received := make([]byte, 0, totalBytes)
		buf := make([]byte, 2048)
		for len(received) < totalBytes {
			n, err := server.Read(buf)
			if err != nil {
				recvCh <- recvResult{received, fmt.Errorf("Read after %d bytes: %w", len(received), err)}
				return
			}
			received = append(received, buf[:n]...)
		}
		recvCh <- recvResult{received, nil}
	}()

	// Send in chunks
	client.SetWriteDeadline(time.Now().Add(60 * time.Second))
	for offset := 0; offset < totalBytes; offset += chunkSize {
		end := offset + chunkSize
		if end > totalBytes {
			end = totalBytes
		}
		if _, err := client.Write(payload[offset:end]); err != nil {
			t.Fatalf("Write at offset %d: %v", offset, err)
		}
	}

	// Wait for receiver
	result := <-recvCh
	if result.err != nil {
		t.Fatalf("Receiver: %v", result.err)
	}

	// File mode is fully reliable: all bytes must arrive
	if len(result.data) != totalBytes {
		t.Fatalf("received %d bytes, want exactly %d (file mode = reliable)", len(result.data), totalBytes)
	}

	recvHash := sha256.Sum256(result.data)
	if sendHash != recvHash {
		t.Fatal("SHA-256 mismatch: file mode transfer data differs")
	}

	t.Logf("file mode transfer OK: %d bytes verified", totalBytes)
}

// TestE2EStreamID verifies that stream ID negotiation works end-to-end,
// including acceptance and rejection based on stream ID.
func TestE2EStreamID(t *testing.T) {
	t.Parallel()

	listenerCfg := DefaultConfig()
	listenerCfg.Latency = 20 * time.Millisecond
	listenerCfg.ConnTimeout = 10 * time.Second

	l, lCleanup := e2eSetupWithListener(t, listenerCfg)
	defer lCleanup()

	// Accept only "test/my-stream"
	l.SetAcceptFunc(func(req ConnRequest) bool {
		return req.StreamID == "test/my-stream"
	})

	// --- Test 1: Correct stream ID is accepted ---
	dialerCfg := DefaultConfig()
	dialerCfg.Latency = 20 * time.Millisecond
	dialerCfg.ConnTimeout = 10 * time.Second
	dialerCfg.StreamID = "test/my-stream"

	var (
		dialConn *Conn
		dialErr  error
		wg       sync.WaitGroup
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		dialConn, dialErr = Dial(l.Addr().String(), dialerCfg)
	}()

	server, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	wg.Wait()
	if dialErr != nil {
		server.Close()
		t.Fatalf("Dial with correct StreamID: %v", dialErr)
	}

	// Verify stream ID on the server-side connection
	if got := server.StreamID(); got != "test/my-stream" {
		t.Errorf("server.StreamID() = %q, want %q", got, "test/my-stream")
	}

	// Verify we can exchange data
	payload := []byte("stream-id-test-payload")
	if _, err := dialConn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Errorf("got %q, want %q", buf[:n], payload)
	}

	dialConn.Close()
	server.Close()

	// --- Test 2: Wrong stream ID is rejected ---
	rejectCfg := DefaultConfig()
	rejectCfg.Latency = 20 * time.Millisecond
	rejectCfg.ConnTimeout = 2 * time.Second
	rejectCfg.StreamID = "wrong/stream-id"

	_, err = Dial(l.Addr().String(), rejectCfg)
	if err == nil {
		t.Fatal("Dial with wrong StreamID should fail")
	}
	t.Logf("rejected stream ID as expected: %v", err)
}

// TestE2EStatsAccuracy sends a known number of packets and verifies that
// stats counters match.
func TestE2EStatsAccuracy(t *testing.T) {
	t.Parallel()

	const numPackets = 100
	const packetSize = 100

	listenerCfg := DefaultConfig()
	listenerCfg.Latency = 20 * time.Millisecond
	listenerCfg.ConnTimeout = 10 * time.Second
	listenerCfg.MaxBW = 1_000_000_000

	dialerCfg := DefaultConfig()
	dialerCfg.Latency = 20 * time.Millisecond
	dialerCfg.ConnTimeout = 10 * time.Second
	dialerCfg.MaxBW = 1_000_000_000

	server, client, cleanup := e2eSetup(t, listenerCfg, dialerCfg)
	defer cleanup()

	// Drain receiver to prevent backpressure
	recvDone := make(chan int, 1)
	go func() {
		server.SetReadDeadline(time.Now().Add(60 * time.Second))
		buf := make([]byte, 1500)
		count := 0
		for count < numPackets {
			_, err := server.Read(buf)
			if err != nil {
				break
			}
			count++
		}
		recvDone <- count
	}()

	// Send exactly numPackets packets of packetSize bytes each
	payload := make([]byte, packetSize)
	for i := range numPackets {
		payload[0] = byte(i) // vary content slightly
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	// Wait for receiver to get all packets
	recvCount := <-recvDone

	// Let stats settle (ACKs must complete the round trip)
	time.Sleep(100 * time.Millisecond)

	// Verify sender stats
	clientStats := client.Stats(false)
	if clientStats.SentPackets != numPackets {
		t.Errorf("client SentPackets: got %d, want %d", clientStats.SentPackets, numPackets)
	}
	expectedBytes := uint64(numPackets * packetSize)
	if clientStats.SentBytes != expectedBytes {
		t.Errorf("client SentBytes: got %d, want %d", clientStats.SentBytes, expectedBytes)
	}

	// Verify receiver stats
	serverStats := server.Stats(false)
	if serverStats.RecvPackets == 0 {
		t.Error("server RecvPackets should be > 0")
	}

	// RTT should be reasonable for localhost (< 50ms)
	if clientStats.RTT <= 0 {
		t.Errorf("RTT should be positive, got %v", clientStats.RTT)
	}
	if clientStats.RTT > 50*time.Millisecond {
		t.Errorf("RTT too high for localhost: %v (want < 50ms)", clientStats.RTT)
	}

	t.Logf("stats: sent_pkts=%d sent_bytes=%d recv_pkts=%d recv_count=%d rtt=%v",
		clientStats.SentPackets, clientStats.SentBytes,
		serverStats.RecvPackets, recvCount, clientStats.RTT)
}

// TestE2EBidirectionalBulk sends 100 KB in each direction simultaneously
// and verifies SHA-256 integrity on both sides.
func TestE2EBidirectionalBulk(t *testing.T) {
	t.Parallel()

	const totalBytes = 100 * 1024 // 100 KB per direction
	const chunkSize = 1316

	listenerCfg := DefaultConfig()
	listenerCfg.Latency = 20 * time.Millisecond
	listenerCfg.ConnTimeout = 10 * time.Second
	listenerCfg.MaxBW = 1_000_000_000

	dialerCfg := DefaultConfig()
	dialerCfg.Latency = 20 * time.Millisecond
	dialerCfg.ConnTimeout = 10 * time.Second
	dialerCfg.MaxBW = 1_000_000_000

	server, client, cleanup := e2eSetup(t, listenerCfg, dialerCfg)
	defer cleanup()

	// Generate random payloads for each direction
	clientPayload := make([]byte, totalBytes)
	serverPayload := make([]byte, totalBytes)
	if _, err := io.ReadFull(rand.Reader, clientPayload); err != nil {
		t.Fatalf("rand.Read clientPayload: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, serverPayload); err != nil {
		t.Fatalf("rand.Read serverPayload: %v", err)
	}
	clientHash := sha256.Sum256(clientPayload)
	serverHash := sha256.Sum256(serverPayload)

	type result struct {
		data []byte
		err  error
	}

	// sendAll writes a full payload in chunks over a connection.
	sendAll := func(conn *Conn, data []byte) error {
		for offset := 0; offset < len(data); offset += chunkSize {
			end := offset + chunkSize
			if end > len(data) {
				end = len(data)
			}
			if _, err := conn.Write(data[offset:end]); err != nil {
				return fmt.Errorf("Write at offset %d: %w", offset, err)
			}
		}
		return nil
	}

	// recvAll reads totalBytes from a connection.
	recvAll := func(conn *Conn, total int) result {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		received := make([]byte, 0, total)
		buf := make([]byte, 2048)
		for len(received) < total {
			n, err := conn.Read(buf)
			if err != nil {
				return result{received, fmt.Errorf("Read after %d bytes: %w", len(received), err)}
			}
			received = append(received, buf[:n]...)
		}
		return result{received, nil}
	}

	var wg sync.WaitGroup

	// Client -> Server direction
	clientRecvCh := make(chan result, 1)
	serverRecvCh := make(chan result, 1)

	// Start receivers
	wg.Add(2)
	go func() {
		defer wg.Done()
		serverRecvCh <- recvAll(server, totalBytes) // server reads client data
	}()
	go func() {
		defer wg.Done()
		clientRecvCh <- recvAll(client, totalBytes) // client reads server data
	}()

	// Start senders
	var sendWg sync.WaitGroup
	sendWg.Add(2)

	var clientSendErr, serverSendErr error
	go func() {
		defer sendWg.Done()
		clientSendErr = sendAll(client, clientPayload)
	}()
	go func() {
		defer sendWg.Done()
		serverSendErr = sendAll(server, serverPayload)
	}()

	sendWg.Wait()
	if clientSendErr != nil {
		t.Fatalf("client send: %v", clientSendErr)
	}
	if serverSendErr != nil {
		t.Fatalf("server send: %v", serverSendErr)
	}

	// Wait for receivers
	wg.Wait()

	srvResult := <-serverRecvCh
	cliResult := <-clientRecvCh

	if srvResult.err != nil {
		t.Fatalf("server recv: %v", srvResult.err)
	}
	if cliResult.err != nil {
		t.Fatalf("client recv: %v", cliResult.err)
	}

	// Verify client -> server direction
	if len(srvResult.data) < totalBytes {
		t.Fatalf("server received %d bytes, want %d", len(srvResult.data), totalBytes)
	}
	srvRecvHash := sha256.Sum256(srvResult.data[:totalBytes])
	if clientHash != srvRecvHash {
		t.Fatal("SHA-256 mismatch: client->server data differs")
	}

	// Verify server -> client direction
	if len(cliResult.data) < totalBytes {
		t.Fatalf("client received %d bytes, want %d", len(cliResult.data), totalBytes)
	}
	cliRecvHash := sha256.Sum256(cliResult.data[:totalBytes])
	if serverHash != cliRecvHash {
		t.Fatal("SHA-256 mismatch: server->client data differs")
	}

	t.Logf("bidirectional transfer OK: %d bytes each direction", totalBytes)
}
