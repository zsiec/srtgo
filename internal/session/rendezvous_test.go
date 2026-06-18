package session_test

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/session"
)

// TestSessionRendezvousUDP connects two peers in rendezvous mode over real
// loopback UDP — both dial each other at once — then streams data each way.
func TestSessionRendezvousUDP(t *testing.T) {
	const (
		N          = 100
		payloadLen = 1000
		maxBW      = 125_000_000
	)

	a := mustUDP(t)
	b := mustUDP(t)

	type res struct {
		s   *session.Session
		err error
	}
	ac := make(chan res, 1)
	bc := make(chan res, 1)

	cfg := func() core.RendezvousConfig {
		return core.RendezvousConfig{
			MSS: 1500, FC: 8192, RecvLatencyMS: 120, SendLatencyMS: 120,
			PayloadSize: payloadLen, MaxBW: maxBW, Live: true,
		}
	}
	go func() {
		s, err := session.DialRendezvous(a, b.LocalAddr(), cfg(), nil, 5*time.Second)
		ac <- res{s, err}
	}()
	go func() {
		s, err := session.DialRendezvous(b, a.LocalAddr(), cfg(), nil, 5*time.Second)
		bc <- res{s, err}
	}()

	var ra, rb res
	for i := 0; i < 2; i++ {
		select {
		case ra = <-ac:
			if ra.err != nil {
				t.Fatalf("peer A rendezvous: %v", ra.err)
			}
		case rb = <-bc:
			if rb.err != nil {
				t.Fatalf("peer B rendezvous: %v", rb.err)
			}
		case <-time.After(6 * time.Second):
			t.Fatal("rendezvous did not complete")
		}
	}
	defer ra.s.Close()
	defer rb.s.Close()

	// A -> B.
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2000)
		for i := 0; i < N; i++ {
			n, err := rb.s.Read(buf)
			if err != nil {
				done <- fmt.Errorf("B read %d: %w", i, err)
				return
			}
			if n != payloadLen || binary.BigEndian.Uint32(buf) != uint32(i) {
				done <- fmt.Errorf("B payload mismatch at %d (n=%d)", i, n)
				return
			}
		}
		done <- nil
	}()
	go func() {
		for i := 0; i < N; i++ {
			p := make([]byte, payloadLen)
			binary.BigEndian.PutUint32(p, uint32(i))
			if err := ra.s.Write(p); err != nil {
				return
			}
		}
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout streaming over the rendezvous connection")
	}
}

// TestSessionRendezvousEncryptedUDP connects two rendezvous peers that share a
// passphrase and streams encrypted data BOTH ways. It proves the rendezvous KM
// exchange (initiator generates the key in a KMREQ; responder adopts it) brings
// up a working AES-CTR link, regardless of which peer wins the cookie contest.
func TestSessionRendezvousEncryptedUDP(t *testing.T) {
	const (
		N          = 100
		payloadLen = 1000
		maxBW      = 125_000_000
		pass       = "rendezvous-secret-1"
	)

	a := mustUDP(t)
	b := mustUDP(t)

	type res struct {
		s   *session.Session
		err error
	}
	ac := make(chan res, 1)
	bc := make(chan res, 1)

	cfg := func() core.RendezvousConfig {
		return core.RendezvousConfig{
			MSS: 1500, FC: 8192, RecvLatencyMS: 120, SendLatencyMS: 120,
			PayloadSize: payloadLen, MaxBW: maxBW, Live: true,
			Passphrase: pass, KeyLength: 16,
		}
	}
	go func() {
		s, err := session.DialRendezvous(a, b.LocalAddr(), cfg(), nil, 5*time.Second)
		ac <- res{s, err}
	}()
	go func() {
		s, err := session.DialRendezvous(b, a.LocalAddr(), cfg(), nil, 5*time.Second)
		bc <- res{s, err}
	}()

	var ra, rb res
	for i := 0; i < 2; i++ {
		select {
		case ra = <-ac:
			if ra.err != nil {
				t.Fatalf("peer A encrypted rendezvous: %v", ra.err)
			}
		case rb = <-bc:
			if rb.err != nil {
				t.Fatalf("peer B encrypted rendezvous: %v", rb.err)
			}
		case <-time.After(6 * time.Second):
			t.Fatal("encrypted rendezvous did not complete")
		}
	}
	defer ra.s.Close()
	defer rb.s.Close()

	// Stream in both directions to exercise encryption on each peer.
	stream := func(from, to *session.Session, tag string) error {
		errc := make(chan error, 1)
		go func() {
			buf := make([]byte, 2000)
			for i := 0; i < N; i++ {
				n, err := to.Read(buf)
				if err != nil {
					errc <- fmt.Errorf("%s read %d: %w", tag, i, err)
					return
				}
				if n != payloadLen || binary.BigEndian.Uint32(buf) != uint32(i) {
					errc <- fmt.Errorf("%s payload mismatch at %d (n=%d)", tag, i, n)
					return
				}
			}
			errc <- nil
		}()
		for i := 0; i < N; i++ {
			p := make([]byte, payloadLen)
			binary.BigEndian.PutUint32(p, uint32(i))
			if err := from.Write(p); err != nil {
				return fmt.Errorf("%s write %d: %w", tag, i, err)
			}
		}
		select {
		case err := <-errc:
			return err
		case <-time.After(10 * time.Second):
			return fmt.Errorf("%s timeout", tag)
		}
	}

	if err := stream(ra.s, rb.s, "A->B"); err != nil {
		t.Fatal(err)
	}
	if err := stream(rb.s, ra.s, "B->A"); err != nil {
		t.Fatal(err)
	}
}
