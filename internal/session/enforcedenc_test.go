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

// TestEnforcedEncryptionFallbackUDP proves SRTO_ENFORCEDENCRYPTION=false: an
// encrypted listener accepts an unencrypted caller (a crypto mismatch) and the
// connection runs in the clear. Without AllowUnencryptedFallback the same dial
// is rejected (encryption is enforced by default).
func TestEnforcedEncryptionFallbackUDP(t *testing.T) {
	dialUnencrypted := func(t *testing.T, fallback bool) (*session.Session, error) {
		t.Helper()
		luconn := mustUDP(t)
		ln, err := session.Listen(luconn, core.ListenerConfig{
			Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
			Passphrase: encPass, AllowUnencryptedFallback: fallback,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })

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
			// no Passphrase: an unencrypted caller
		}, nil, 3*time.Second)
		if err != nil {
			return nil, err
		}
		select {
		case recv := <-accepted:
			t.Cleanup(func() { recv.Close() })
			// Stream a few payloads to confirm the (unencrypted) data path works.
			go func() {
				for i := 0; i < 20; i++ {
					p := make([]byte, 500)
					binary.BigEndian.PutUint32(p, uint32(i))
					if caller.Write(p) != nil {
						return
					}
				}
			}()
			buf := make([]byte, 1000)
			for i := 0; i < 20; i++ {
				n, err := recv.Read(buf)
				if err != nil {
					return caller, fmt.Errorf("read %d: %w", i, err)
				}
				if n != 500 || binary.BigEndian.Uint32(buf) != uint32(i) {
					return caller, fmt.Errorf("payload mismatch at %d", i)
				}
			}
			return caller, nil
		case <-time.After(3 * time.Second):
			caller.Close()
			return nil, fmt.Errorf("listener did not accept")
		}
	}

	// With fallback: the unencrypted caller connects and streams.
	caller, err := dialUnencrypted(t, true)
	if err != nil {
		t.Fatalf("fallback dial should succeed unencrypted: %v", err)
	}
	caller.Close()

	// Without fallback (default): the encrypted listener rejects the plaintext caller.
	if _, err := dialUnencrypted(t, false); err == nil {
		t.Fatal("without fallback, an unencrypted caller must be rejected by an encrypted listener")
	}
}
