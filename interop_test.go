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
	"regexp"
	"strconv"
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
	// minVer is the minimum libsrt version required; the case is skipped on older
	// peers. AES-GCM (and the cryptomode URL param) is reliable only on 1.5.4+;
	// older libsrt rejects the GCM KMREQ ("NOSECRET").
	minVer [3]int
}

func interopCases() []interopCase {
	return []interopCase{
		{name: "plaintext"},
		{name: "aes-ctr-128", url: "&passphrase=" + interopPass + "&pbkeylen=16", cfg: func(c *srt.Config) {
			c.Passphrase = interopPass
			c.KeyLength = 16
		}},
		{name: "aes-ctr-256", url: "&passphrase=" + interopPass + "&pbkeylen=32", cfg: func(c *srt.Config) {
			c.Passphrase = interopPass
			c.KeyLength = 32
		}},
		{name: "aes-gcm-128", url: "&passphrase=" + interopPass + "&pbkeylen=16&cryptomode=2", minVer: [3]int{1, 5, 4}, cfg: func(c *srt.Config) {
			c.Passphrase = interopPass
			c.KeyLength = 16
			c.CryptoMode = 2
		}},
		{name: "aes-gcm-256", url: "&passphrase=" + interopPass + "&pbkeylen=32&cryptomode=2", minVer: [3]int{1, 5, 4}, cfg: func(c *srt.Config) {
			c.Passphrase = interopPass
			c.KeyLength = 32
			c.CryptoMode = 2
		}},
		{name: "fec-cols10-rows5", url: "&packetfilter=fec,cols:10,rows:5", cfg: func(c *srt.Config) {
			c.PacketFilter = "fec,cols:10,rows:5"
		}},
	}
}

// libsrtVersion parses "SRT Library version: X.Y.Z" from `srt-live-transmit
// -version`. ok is false if it can't be determined.
func libsrtVersion(bin string) (v [3]int, ok bool) {
	out, _ := exec.Command(bin, "-version").CombinedOutput()
	m := regexp.MustCompile(`SRT Library version:\s*(\d+)\.(\d+)\.(\d+)`).FindSubmatch(out)
	if m == nil {
		return v, false
	}
	for i := 0; i < 3; i++ {
		v[i], _ = strconv.Atoi(string(m[i+1]))
	}
	return v, true
}

// atLeast reports whether version v is >= want.
func atLeast(v, want [3]int) bool {
	for i := 0; i < 3; i++ {
		if v[i] != want[i] {
			return v[i] > want[i]
		}
	}
	return true
}

// TestInterop streams from the new srtgo stack to a real libsrt receiver and
// verifies the bytes arrive intact, across every cipher/FEC mode.
func TestInterop(t *testing.T) {
	bin, err := exec.LookPath("srt-live-transmit")
	if err != nil {
		t.Skip("srt-live-transmit not found; install srt-tools to run interop tests")
	}
	ver, verOK := libsrtVersion(bin)
	if verOK {
		t.Logf("libsrt version %d.%d.%d", ver[0], ver[1], ver[2])
	} else {
		t.Logf("libsrt version: unknown")
	}
	for _, tc := range interopCases() {
		tc := tc
		t.Run("go-to-libsrt/"+tc.name, func(t *testing.T) {
			if tc.minVer != [3]int{} && (!verOK || !atLeast(ver, tc.minVer)) {
				t.Skipf("needs libsrt >= %d.%d.%d (have %v); the older CI/apt libsrt lacks GCM/cryptomode support",
					tc.minVer[0], tc.minVer[1], tc.minVer[2], ver)
			}
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
	cmd := exec.CommandContext(ctx, bin, "-q", "-ll", "error", "-t", "8", url, "file://con")
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
