//go:build interop

// Interop test infrastructure for testing against C++ srt-live-transmit.
//
// Prerequisites:
//
//	brew install srt          # macOS
//	apt install srt-tools     # Ubuntu/Debian
//
// Run all interop tests:
//
//	go test -tags interop -run TestInterop -v -timeout 30m
//
// Run specific category:
//
//	go test -tags interop -run TestInterop/Encryption -v -timeout 10m

package srt

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Data sizes for interop tests. All live-mode sizes are multiples of 1316
// (the SRT default payload size) for clean packet alignment.
const (
	interopPayloadSize = 1316
	interopSmallData   = interopPayloadSize * 10   // ~13 KB
	interopMediumData  = interopPayloadSize * 100  // ~131 KB
	interopLargeData   = interopPayloadSize * 1000 // ~1.3 MB
	interopHugeData    = interopPayloadSize * 10000 // ~13 MB

	interopDefaultSeed    = 42
	interopCppStartDelay  = 500 * time.Millisecond
	interopProcessTimeout = 30 * time.Second
	interopAcceptTimeout  = 10 * time.Second
)

// ---------------------------------------------------------------------------
// interopEnv — test environment managing srt-live-transmit processes
// ---------------------------------------------------------------------------

type interopEnv struct {
	t           *testing.T
	srtTransmit string // path to srt-live-transmit
	tmpDir      string
	mu          sync.Mutex
	processes   []*srtProcess
}

type srtProcess struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    *bytes.Buffer
	stderr    *bytes.Buffer
	connected chan struct{} // closed when "connected" appears in stderr
	done      chan struct{}
	err       error
}

func newInteropEnv(t *testing.T) *interopEnv {
	t.Helper()
	path, err := exec.LookPath("srt-live-transmit")
	if err != nil {
		t.Skip("srt-live-transmit not found in PATH; install libsrt to run interop tests")
	}
	env := &interopEnv{
		t:           t,
		srtTransmit: path,
		tmpDir:      t.TempDir(),
	}
	t.Cleanup(env.cleanup)
	return env
}

func (e *interopEnv) cleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, p := range e.processes {
		if p.cmd.Process != nil {
			p.cmd.Process.Kill()
		}
	}
}

// exec starts srt-live-transmit with the given source, target, and extra flags.
// If stdinData is non-nil, it is fed to stdin in chunks after the SRT connection
// is established (detected by scanning stderr for "connected"). This is necessary
// because srt-live-transmit reads stdin eagerly and will shut down on EOF before
// the SRT connection can transmit the data.
// stdout is always captured in proc.stdout.
func (e *interopEnv) exec(ctx context.Context, source, target string, stdinData []byte, extraArgs ...string) *srtProcess {
	e.t.Helper()
	args := append(append([]string{}, extraArgs...), source, target)
	cmd := exec.CommandContext(ctx, e.srtTransmit, args...)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	stdin, err := cmd.StdinPipe()
	if err != nil {
		e.t.Fatalf("StdinPipe: %v", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		e.t.Fatalf("StderrPipe: %v", err)
	}

	var stderrBuf bytes.Buffer
	connected := make(chan struct{})

	proc := &srtProcess{
		cmd:       cmd,
		stdin:     stdin,
		stdout:    &stdout,
		stderr:    &stderrBuf,
		connected: connected,
		done:      make(chan struct{}),
	}

	if err := cmd.Start(); err != nil {
		e.t.Fatalf("Start srt-live-transmit %v: %v", args, err)
	}

	// Scan stderr for "connected" signal, capturing all output.
	connOnce := sync.Once{}
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			stderrBuf.WriteString(line + "\n")
			if strings.Contains(strings.ToLower(line), "connected") {
				connOnce.Do(func() { close(connected) })
			}
		}
		// If process exits without "connected", unblock waiters.
		connOnce.Do(func() { close(connected) })
	}()

	// Feed stdin data after SRT connection is established.
	if stdinData != nil {
		go func() {
			// Wait for connection, timeout fallback (for listener mode where C++
			// might need stdin data before accepting), or context cancellation.
			select {
			case <-connected:
			case <-time.After(2 * time.Second):
				// Fallback: start writing even if "connected" hasn't appeared.
				// This handles the case where C++ is a listener+sender and
				// needs stdin data available before accepting connections.
			case <-ctx.Done():
				stdin.Close()
				return
			}
			// Small additional delay for connection to stabilize.
			time.Sleep(100 * time.Millisecond)

			// Write in 64 KB chunks. Now that we gate on "connected", we
			// can feed stdin fast. A small delay every 64 KB prevents
			// overwhelming srt-live-transmit's read-ahead.
			const chunkSize = 65536
			const chunkDelay = 1 * time.Millisecond
			for len(stdinData) > 0 {
				n := chunkSize
				if n > len(stdinData) {
					n = len(stdinData)
				}
				if _, werr := stdin.Write(stdinData[:n]); werr != nil {
					break
				}
				stdinData = stdinData[n:]
				if len(stdinData) > 0 {
					time.Sleep(chunkDelay)
				}
			}
			// Keep stdin open briefly to let last packets drain.
			time.Sleep(500 * time.Millisecond)
			stdin.Close()
		}()
	} else {
		stdin.Close()
	}

	go func() {
		proc.err = cmd.Wait()
		close(proc.done)
	}()

	e.mu.Lock()
	e.processes = append(e.processes, proc)
	e.mu.Unlock()
	return proc
}

func (p *srtProcess) waitConnected(timeout time.Duration) bool {
	select {
	case <-p.connected:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (p *srtProcess) wait(timeout time.Duration) error {
	select {
	case <-p.done:
		return p.err
	case <-time.After(timeout):
		if p.cmd.Process != nil {
			p.cmd.Process.Kill()
		}
		return fmt.Errorf("srt-live-transmit timed out after %v (stderr: %s)", timeout, p.stderr.String())
	}
}

func (p *srtProcess) kill() {
	if p.cmd.Process != nil {
		p.cmd.Process.Kill()
	}
}

// stop gracefully terminates the process and waits for it to exit.
// This gives C++ time to flush stdout before dying.
func (p *srtProcess) stop() {
	if p.cmd.Process != nil {
		p.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
		p.kill()
		<-p.done
	}
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	return port
}

func generateTestData(size int, seed int64) []byte {
	rng := rand.New(rand.NewSource(seed))
	data := make([]byte, size)
	for i := 0; i < len(data); i += 8 {
		v := rng.Int63()
		remaining := len(data) - i
		if remaining > 8 {
			remaining = 8
		}
		for j := 0; j < remaining; j++ {
			data[i+j] = byte(v >> uint(j*8))
		}
	}
	return data
}

func sha256Hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// buildSRTURI builds an SRT URI with query-string options.
// Options are sorted by key for deterministic output.
func buildSRTURI(host string, port int, opts map[string]string) string {
	if host == "" {
		host = ""
	}
	uri := fmt.Sprintf("srt://%s:%d", host, port)
	if len(opts) == 0 {
		return uri
	}
	keys := make([]string, 0, len(opts))
	for k := range opts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + opts[k]
	}
	return uri + "?" + strings.Join(parts, "&")
}

// mergeOpts merges additional options into a base option map (non-destructive).
func mergeOpts(base, extra map[string]string) map[string]string {
	merged := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range extra {
		merged[k] = v
	}
	return merged
}

// ---------------------------------------------------------------------------
// Go-side data transfer helpers
// ---------------------------------------------------------------------------

// goReadAll reads data from conn until expected bytes are received, the done
// channel closes (peer process exited), or an error occurs. When expected > 0,
// it returns as soon as enough data is collected — no need to wait for the C++
// process to timeout.
func goReadAll(conn *Conn, done <-chan struct{}, expected int) ([]byte, error) {
	// Close conn when peer exits to unblock Read (fallback for when
	// we don't know the expected size or the transfer is short).
	go func() {
		<-done
		time.Sleep(200 * time.Millisecond)
		conn.Close()
	}()

	var buf bytes.Buffer
	tmp := make([]byte, 65536)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if expected > 0 && buf.Len() >= expected {
			conn.Close()
			return buf.Bytes(), nil
		}
		if err != nil {
			return buf.Bytes(), nil
		}
	}
}

// goWriteAll writes data in chunks of chunkSize. Use chunkSize=1316 for live mode.
func goWriteAll(conn *Conn, data []byte, chunkSize int) error {
	for len(data) > 0 {
		n := chunkSize
		if n > len(data) {
			n = len(data)
		}
		written, err := conn.Write(data[:n])
		if err != nil {
			return fmt.Errorf("Write: %w (sent %d/%d bytes)", err, len(data)-len(data[written:]), len(data))
		}
		data = data[written:]
	}
	return nil
}

func isExpectedClose(err error) bool {
	if err == nil || err == io.EOF {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "shutdown") ||
		strings.Contains(s, "closed") ||
		strings.Contains(s, "broken") ||
		strings.Contains(s, "reset") ||
		strings.Contains(s, "EOF")
}

// ---------------------------------------------------------------------------
// Transfer pattern helpers
//
// Four patterns covering all combinations of:
//   - SRT role: Go listens vs C++ listens
//   - Data direction: C++ sends vs Go sends
// ---------------------------------------------------------------------------

// cppChunkFlag returns the -chunk:N flag matching the payloadsize in cppOpts.
// This ensures srt-live-transmit reads stdin in matching chunk sizes.
func cppChunkFlag(cppOpts map[string]string) string {
	if ps, ok := cppOpts["payloadsize"]; ok {
		return "-chunk:" + ps
	}
	return "-chunk:1316"
}

// cppToGo_GoListens: Go listens, C++ dials and sends data via stdin→file://con.
// Returns data received by Go.
func (e *interopEnv) cppToGo_GoListens(
	t *testing.T, data []byte, goCfg Config, cppOpts map[string]string,
) []byte {
	t.Helper()
	port := freePort(t)

	goCfg.ConnTimeout = 5 * time.Second
	ln, err := Listen(fmt.Sprintf("127.0.0.1:%d", port), goCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), interopProcessTimeout)
	defer cancel()
	uri := buildSRTURI("127.0.0.1", port, cppOpts)
	proc := e.exec(ctx, "file://con", uri, data, "-to:10", cppChunkFlag(cppOpts))

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v (C++ stderr: %s)", err, proc.stderr.String())
	}

	received, err := goReadAll(conn, proc.done, len(data))
	if err != nil {
		t.Fatalf("goReadAll: %v (C++ stderr: %s)", err, proc.stderr.String())
	}
	proc.stop()
	return received
}

// cppToGo_CppListens: C++ listens and sends data via stdin→file://con, Go dials and reads.
// Returns data received by Go.
func (e *interopEnv) cppToGo_CppListens(
	t *testing.T, data []byte, goCfg Config, cppOpts map[string]string,
) []byte {
	t.Helper()
	port := freePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), interopProcessTimeout)
	defer cancel()

	opts := mergeOpts(cppOpts, map[string]string{"mode": "listener"})
	uri := buildSRTURI("", port, opts)
	proc := e.exec(ctx, "file://con", uri, data, "-to:10", cppChunkFlag(cppOpts))

	time.Sleep(interopCppStartDelay)

	goCfg.ConnTimeout = 5 * time.Second
	conn, err := Dial(fmt.Sprintf("127.0.0.1:%d", port), goCfg)
	if err != nil {
		t.Fatalf("Dial: %v (C++ stderr: %s)", err, proc.stderr.String())
	}

	received, err := goReadAll(conn, proc.done, len(data))
	if err != nil {
		t.Fatalf("goReadAll: %v (C++ stderr: %s)", err, proc.stderr.String())
	}
	proc.stop()
	return received
}

// goToCpp_GoListens: Go listens, C++ dials and receives data to stdout (file://con).
// Go accepts and writes data. Returns data captured from C++ stdout.
func (e *interopEnv) goToCpp_GoListens(
	t *testing.T, data []byte, goCfg Config, cppOpts map[string]string, chunkSize int,
) []byte {
	t.Helper()
	port := freePort(t)

	goCfg.ConnTimeout = 5 * time.Second
	ln, err := Listen(fmt.Sprintf("127.0.0.1:%d", port), goCfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), interopProcessTimeout)
	defer cancel()
	uri := buildSRTURI("127.0.0.1", port, cppOpts)
	proc := e.exec(ctx, uri, "file://con", nil, "-to:10", cppChunkFlag(cppOpts))

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v (C++ stderr: %s)", err, proc.stderr.String())
	}

	if err := goWriteAll(conn, data, chunkSize); err != nil {
		conn.Close()
		t.Fatalf("goWriteAll: %v (C++ stderr: %s)", err, proc.stderr.String())
	}
	// Let the SRT protocol drain before closing.
	time.Sleep(500 * time.Millisecond)
	conn.Close()

	// Give C++ a moment to flush received data to stdout, then stop.
	time.Sleep(200 * time.Millisecond)
	proc.stop()
	return proc.stdout.Bytes()
}

// goToCpp_CppListens: C++ listens and receives data to stdout (file://con), Go dials and writes.
// Returns data captured from C++ stdout.
func (e *interopEnv) goToCpp_CppListens(
	t *testing.T, data []byte, goCfg Config, cppOpts map[string]string, chunkSize int,
) []byte {
	t.Helper()
	port := freePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), interopProcessTimeout)
	defer cancel()

	opts := mergeOpts(cppOpts, map[string]string{"mode": "listener"})
	uri := buildSRTURI("", port, opts)
	proc := e.exec(ctx, uri, "file://con", nil, "-to:10", cppChunkFlag(cppOpts))

	time.Sleep(interopCppStartDelay)

	goCfg.ConnTimeout = 5 * time.Second
	conn, err := Dial(fmt.Sprintf("127.0.0.1:%d", port), goCfg)
	if err != nil {
		t.Fatalf("Dial: %v (C++ stderr: %s)", err, proc.stderr.String())
	}

	if err := goWriteAll(conn, data, chunkSize); err != nil {
		conn.Close()
		t.Fatalf("goWriteAll: %v (C++ stderr: %s)", err, proc.stderr.String())
	}
	time.Sleep(500 * time.Millisecond)
	conn.Close()

	// Give C++ a moment to flush received data to stdout, then stop.
	time.Sleep(200 * time.Millisecond)
	proc.stop()
	return proc.stdout.Bytes()
}

// ---------------------------------------------------------------------------
// Verification helpers
// ---------------------------------------------------------------------------

// verifyData checks that received data matches expected data exactly.
func verifyData(t *testing.T, received, expected []byte) {
	t.Helper()
	if len(received) != len(expected) {
		t.Errorf("length mismatch: got %d bytes, want %d bytes (diff %d, %.1f%%)",
			len(received), len(expected),
			len(expected)-len(received),
			float64(len(expected)-len(received))/float64(len(expected))*100)
	}
	if sha256Hash(received) != sha256Hash(expected) {
		t.Errorf("data corruption: SHA-256 mismatch\n  got:  %s\n  want: %s",
			sha256Hash(received), sha256Hash(expected))
		// Find first differing byte for debugging
		minLen := len(received)
		if len(expected) < minLen {
			minLen = len(expected)
		}
		for i := 0; i < minLen; i++ {
			if received[i] != expected[i] {
				t.Errorf("first difference at byte %d: got 0x%02x, want 0x%02x", i, received[i], expected[i])
				break
			}
		}
	}
}

// verifyDataLossy checks received data allowing some loss (for sustained live tests).
// maxLossPercent is 0.0-100.0.
func verifyDataLossy(t *testing.T, received, expected []byte, maxLossPercent float64) {
	t.Helper()
	if len(received) > len(expected) {
		t.Errorf("received more data than sent: got %d, sent %d", len(received), len(expected))
		return
	}
	lossBytes := len(expected) - len(received)
	lossPct := float64(lossBytes) / float64(len(expected)) * 100
	t.Logf("transfer: sent %d bytes, received %d bytes (loss %.2f%%)", len(expected), len(received), lossPct)
	if lossPct > maxLossPercent {
		t.Errorf("loss %.2f%% exceeds threshold %.1f%%", lossPct, maxLossPercent)
	}
	// If lengths match, verify content exactly
	if len(received) == len(expected) {
		if sha256Hash(received) != sha256Hash(expected) {
			t.Error("data corruption: SHA-256 mismatch despite matching lengths")
		}
		return
	}
	// When shorter: check that received is a valid prefix of expected.
	// This catches corruption, reordering, and garbage data.
	if len(received) > 0 && bytes.Equal(received, expected[:len(received)]) {
		t.Logf("integrity OK: received %d bytes match prefix of expected", len(received))
		return
	}
	// Prefix check failed — SRT may have dropped whole packets, creating
	// non-contiguous data. Fall back to chunk-aligned comparison: verify
	// each payload-sized chunk in received appears at the correct offset.
	const chunkSize = interopPayloadSize
	corrupt := 0
	checked := 0
	for off := 0; off+chunkSize <= len(received); off += chunkSize {
		checked++
		chunk := received[off : off+chunkSize]
		// Search for this chunk at any payload-aligned offset in expected
		found := false
		for eOff := 0; eOff+chunkSize <= len(expected); eOff += chunkSize {
			if bytes.Equal(chunk, expected[eOff:eOff+chunkSize]) {
				found = true
				break
			}
		}
		if !found {
			corrupt++
		}
	}
	if corrupt > 0 {
		t.Errorf("data integrity: %d/%d chunks (each %d bytes) not found in expected data", corrupt, checked, chunkSize)
	} else if checked > 0 {
		t.Logf("integrity OK: all %d chunks verified (non-prefix due to packet drops)", checked)
	}
}
