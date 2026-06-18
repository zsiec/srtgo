package session_test

import (
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/session"
)

// TestGroupHandshakeFormation proves the handshake-level group negotiation: two
// callers advertising the same GroupID are accepted into one group and assigned
// the SAME shared send ISN (so their streams can later be deduplicated), while a
// non-group caller is accepted with GroupID 0. This is the protocol substrate
// for handshake-formed bonded groups.
func TestGroupHandshakeFormation(t *testing.T) {
	const groupID = 42

	luconn := mustUDP(t)
	ln, err := session.Listen(luconn, core.ListenerConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan *session.Session, 3)
	go func() {
		for i := 0; i < 3; i++ {
			s, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- s
		}
	}()

	dial := func(gid uint32) *session.Session {
		t.Helper()
		uconn := mustUDP(t)
		s, err := session.Dial(uconn, ln.Addr(), core.DialConfig{
			Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
			GroupID: gid, GroupType: 1, // broadcast
		}, nil, 5*time.Second)
		if err != nil {
			t.Fatalf("dial (group %d): %v", gid, err)
		}
		return s
	}

	// Two members of the same group, plus one non-group connection.
	m1 := dial(groupID)
	defer m1.Close()
	m2 := dial(groupID)
	defer m2.Close()
	solo := dial(0)
	defer solo.Close()

	// Collect the three accepted sessions and index them by their caller's group.
	byGroup := map[uint32][]*session.Session{}
	for i := 0; i < 3; i++ {
		select {
		case s := <-accepted:
			defer s.Close()
			byGroup[s.GroupID()] = append(byGroup[s.GroupID()], s)
		case <-time.After(5 * time.Second):
			t.Fatal("listener did not accept all connections")
		}
	}

	members := byGroup[groupID]
	if len(members) != 2 {
		t.Fatalf("group %d formed with %d members, want 2", groupID, len(members))
	}
	if members[0].SharedISN() != members[1].SharedISN() {
		t.Fatalf("group members got different shared ISNs: %d vs %d",
			members[0].SharedISN(), members[1].SharedISN())
	}
	if members[0].SharedISN() == 0 {
		t.Fatal("group shared ISN is zero")
	}
	if solos := byGroup[0]; len(solos) != 1 {
		t.Fatalf("expected 1 non-group connection, got %d", len(solos))
	}

	// Caller side reports its advertised group too.
	if m1.GroupID() != groupID || m2.GroupID() != groupID || solo.GroupID() != 0 {
		t.Fatalf("caller GroupIDs: m1=%d m2=%d solo=%d", m1.GroupID(), m2.GroupID(), solo.GroupID())
	}
}
