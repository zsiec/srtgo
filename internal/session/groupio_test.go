package session_test

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/session"
)

// TestGroupDialAcceptUDP forms a bonded broadcast group entirely over the
// handshake: the caller DialGroups two member links to a single listener, which
// AcceptGroups them into one group. One caller link is permanently dead (its
// data is dropped), so every payload can only arrive via the other link — yet
// the group must deliver all of them, once each, in order. This exercises the
// whole path: per-member handshake with a shared group ID + ISN, listener-side
// group formation on a shared mux, broadcast send, and cross-link dedup.
func TestGroupDialAcceptUDP(t *testing.T) {
	const (
		N          = 200
		payloadLen = 1000
		maxBW      = 125_000_000
	)

	luconn := mustUDP(t)
	ln, err := session.Listen(luconn, core.ListenerConfig{
		Live: true, MaxBW: maxBW, RecvLatencyMS: 120, SendLatencyMS: 120,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Two caller member sockets; the first link is dead from the start (its data
	// packets vanish — only handshake control gets through).
	raw0, conn1 := mustUDP(t), mustUDP(t)
	dead := &lossyConn{PacketConn: raw0, dropSeq: map[uint32]bool{}, permanent: true}
	dead.kill.Store(true)

	base := core.DialConfig{Live: true, MaxBW: maxBW, RecvLatencyMS: 120, SendLatencyMS: 120}

	type dialRes struct {
		g   *session.Group
		err error
	}
	dialed := make(chan dialRes, 1)
	go func() {
		g, err := session.DialGroup(core.GroupBroadcast, base, []session.GroupDialMember{
			{Conn: dead, RemoteAddr: ln.Addr(), Weight: 1},
			{Conn: conn1, RemoteAddr: ln.Addr(), Weight: 1},
		}, nil, 5*time.Second)
		dialed <- dialRes{g, err}
	}()

	rg, err := ln.AcceptGroup(core.GroupBroadcast, 2)
	if err != nil {
		t.Fatalf("AcceptGroup: %v", err)
	}
	defer rg.Close()

	dr := <-dialed
	if dr.err != nil {
		t.Fatalf("DialGroup: %v", dr.err)
	}
	sg := dr.g
	defer sg.Close()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2000)
		for i := 0; i < N; i++ {
			n, err := rg.Read(buf)
			if err != nil {
				done <- fmt.Errorf("group read %d: %w", i, err)
				return
			}
			if n != payloadLen || binary.BigEndian.Uint32(buf) != uint32(i) {
				done <- fmt.Errorf("group payload mismatch at %d (n=%d)", i, n)
				return
			}
		}
		done <- nil
	}()
	go func() {
		for i := 0; i < N; i++ {
			p := make([]byte, payloadLen)
			binary.BigEndian.PutUint32(p, uint32(i))
			if err := sg.Write(p); err != nil {
				return
			}
		}
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout: bonded group did not deliver all payloads over the surviving link")
	}
}
