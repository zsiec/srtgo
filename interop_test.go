//go:build interop

// Package srt interop tests verify wire compatibility with the C++ reference
// implementation (libsrt's srt-live-transmit). They are gated behind the
// `interop` build tag and require srt-tools to be installed:
//
//	go test -tags interop -run TestInterop -v -count=1 -timeout 600s
//
// The Go side uses the public srt API in-process; srt-live-transmit is the
// libsrt peer. Tests run the Go->libsrt direction (the Go sender paces itself, so
// the libsrt receiver never drops) across plaintext, AES-CTR, AES-GCM, and FEC.
package srt_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	srt "github.com/zsiec/srtgo"
)

const (
	interopPass    = "interop-secret-pass" // >= 10 bytes
	interopLatency = 1500                  // ms; generous so the libsrt receiver buffers the whole transfer
)

// interopData is a deterministic payload the receiver can verify byte-for-byte.
func interopData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*131 + 7)
	}
	return b
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// interopCase parameters one cipher/FEC scenario for both the Go config and the
// matching srt-live-transmit URL query string.
type interopCase struct {
	name string
	url  string // extra srt:// query params (begins with &)
	cfg  func(*srt.Config)
}

func interopCases() []interopCase {
	return []interopCase{
		{"plaintext", "", nil},
		{"aes-ctr-128", "&passphrase=" + interopPass + "&pbkeylen=16", func(c *srt.Config) {
			c.Passphrase = interopPass
			c.KeyLength = 16
		}},
		{"aes-ctr-256", "&passphrase=" + interopPass + "&pbkeylen=32", func(c *srt.Config) {
			c.Passphrase = interopPass
			c.KeyLength = 32
		}},
		{"aes-gcm-128", "&passphrase=" + interopPass + "&pbkeylen=16&cryptomode=2", func(c *srt.Config) {
			c.Passphrase = interopPass
			c.KeyLength = 16
			c.CryptoMode = 2
		}},
		{"aes-gcm-256", "&passphrase=" + interopPass + "&pbkeylen=32&cryptomode=2", func(c *srt.Config) {
			c.Passphrase = interopPass
			c.KeyLength = 32
			c.CryptoMode = 2
		}},
		{"fec-cols10-rows5", "&packetfilter=fec,cols:10,rows:5", func(c *srt.Config) {
			c.PacketFilter = "fec,cols:10,rows:5"
		}},
	}
}

// TestInterop streams from the new srtgo stack to a real libsrt receiver and
// verifies the bytes arrive intact, across every cipher/FEC mode.
func TestInterop(t *testing.T) {
	bin, err := exec.LookPath("srt-live-transmit")
	if err != nil {
		t.Skip("srt-live-transmit not found; install srt-tools to run interop tests")
	}
	for _, tc := range interopCases() {
		tc := tc
		t.Run("go-to-libsrt/"+tc.name, func(t *testing.T) {
			goToLibsrt(t, bin, tc)
		})
	}
}

// goToLibsrt: srtgo dials and sends; libsrt (srt-live-transmit) listens and
// writes the received stream to stdout, which we compare against what we sent.
func goToLibsrt(t *testing.T, bin string, tc interopCase) {
	const total = 240 * 1024 // 240 KiB
	const chunk = 1200
	want := interopData(total)
	port := freeUDPPort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// libsrt SRT listener -> stdout.
	url := fmt.Sprintf("srt://:%d?latency=%d%s", port, interopLatency, tc.url)
	cmd := exec.CommandContext(ctx, bin, "-q", "-t", "8", url, "file://con")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start srt-live-transmit: %v", err)
	}
	defer func() { _ = cmd.Wait() }()

	time.Sleep(1500 * time.Millisecond) // let the libsrt listener bind

	cfg := srt.DefaultConfig()
	cfg.Latency = interopLatency * time.Millisecond
	cfg.ConnTimeout = 8 * time.Second
	if tc.cfg != nil {
		tc.cfg(&cfg)
	}
	conn, err := srt.Dial(fmt.Sprintf("127.0.0.1:%d", port), cfg)
	if err != nil {
		t.Fatalf("dial libsrt: %v", err)
	}
	for off := 0; off < len(want); off += chunk {
		end := off + chunk
		if end > len(want) {
			end = len(want)
		}
		if _, err := conn.Write(want[off:end]); err != nil {
			conn.Close()
			t.Fatalf("write at %d: %v", off, err)
		}
	}
	time.Sleep(2 * time.Second) // flush/retransmit window before closing
	conn.Close()
	_ = cmd.Wait() // srt-live-transmit exits on its -t timer / broken connection

	got := out.Bytes()
	if len(got) != len(want) {
		t.Fatalf("libsrt received %d bytes, want %d", len(got), len(want))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("received bytes differ from sent (len=%d)", len(got))
	}
}
