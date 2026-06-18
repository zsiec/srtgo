package core_test

import (
	"encoding/binary"
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
)

// TestSimRendezvous drives two rendezvous cores against each other over the
// in-memory link: both send WAVEHAND, the cookie contest assigns initiator and
// responder, they exchange CONCLUSION(HSREQ/HSRSP) + AGREEMENT, and both reach
// Connected with no caller/listener asymmetry. Then data flows both ways,
// proving the established data path works on a rendezvous-built connection.
func TestSimRendezvous(t *testing.T) {
	const (
		aSocket = 11
		bSocket = 22
		aISN    = 100
		bISN    = 9000
		aCookie = 1000 // larger cookie -> A is INITIATOR
		bCookie = 500  // smaller cookie -> B is RESPONDER
		n       = 50
	)
	base := clock.Timestamp(1_000_000)

	a := newSimHost(core.DialRendezvous(core.RendezvousConfig{
		SocketID: aSocket, ISN: aISN, Cookie: aCookie, PayloadSize: simPayload, MaxBW: 1 << 34,
	}, base))
	b := newSimHost(core.DialRendezvous(core.RendezvousConfig{
		SocketID: bSocket, ISN: bISN, Cookie: bCookie, PayloadSize: simPayload, MaxBW: 1 << 34,
	}, base))

	// Phase 1: drive the handshake until both peers connect.
	drive(t, a, b, base, nil, func() bool { return a.connected && b.connected })
	if !a.connected || !b.connected {
		t.Fatalf("rendezvous did not connect (a=%v b=%v)", a.connected, b.connected)
	}

	// Phase 2: A -> B data.
	for i := 0; i < n; i++ {
		a.c.Write(base, makePayload(i))
	}
	drive(t, a, b, base, nil, func() bool { return len(b.delivered) >= n })
	if got := len(b.delivered); got != n {
		t.Fatalf("A->B delivered %d/%d", got, n)
	}
	for i, p := range b.delivered {
		if binary.BigEndian.Uint32(p) != uint32(i) {
			t.Fatalf("A->B payload %d out of order: got %d", i, binary.BigEndian.Uint32(p))
		}
	}

	// Phase 3: B -> A data, proving the reverse direction is established too.
	for i := 0; i < n; i++ {
		b.c.Write(base, makePayload(i))
	}
	drive(t, a, b, base, nil, func() bool { return len(a.delivered) >= n })
	if got := len(a.delivered); got != n {
		t.Fatalf("B->A delivered %d/%d", got, n)
	}
}

// TestRdvCookieContestAntisymmetric checks the contest assigns exactly one
// initiator and one responder for distinct cookies (no double-initiator deadlock
// or double-responder stall), across a range of values.
func TestRdvCookieContestAntisymmetric(t *testing.T) {
	pairs := [][2]uint32{
		{1000, 500}, {500, 1000}, {1, 0xFFFFFFFF}, {0xFFFFFFFF, 1},
		{0x80000000, 0x7FFFFFFF}, {42, 43}, {0xDEADBEEF, 0x1234},
	}
	for _, p := range pairs {
		ab := core.RdvContestForTest(p[0], p[1])
		ba := core.RdvContestForTest(p[1], p[0])
		if ab == 0 || ba == 0 {
			t.Fatalf("cookies %#x/%#x produced a draw", p[0], p[1])
		}
		if ab == ba {
			t.Fatalf("cookies %#x/%#x gave the same role on both sides (%d)", p[0], p[1], ab)
		}
	}
}
