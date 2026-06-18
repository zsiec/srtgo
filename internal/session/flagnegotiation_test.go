package session_test

import (
	"net"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/session"
)

// TestPeerNakReportNegotiationUDP proves the bilateral SRT feature-flag
// negotiation: the listener advertises its computed flags in the CONCLUSION
// response (so the caller learns the listener does periodic NAK), and each side
// parses the other's advertised PeriodicNAK flag into peerNakReport. A caller
// with DisableNAKReport advertises no PeriodicNAK, which the listener observes.
func TestPeerNakReportNegotiationUDP(t *testing.T) {
	luconn := mustUDP(t)
	ln, err := session.Listen(luconn, core.ListenerConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
		// default: the listener does periodic NAK reporting
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

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
		DisableNAKReport: true, // this caller does NOT advertise periodic NAK
	}, nil, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer caller.Close()

	var recv *session.Session
	select {
	case recv = <-accepted:
		defer recv.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not accept")
	}

	// The caller parsed the listener's advertised flags: the listener does
	// periodic NAK, so the caller sees peerNakReport == true.
	cs, err := caller.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if !cs.PeerNakReport {
		t.Error("caller.PeerNakReport = false, want true (listener advertised periodic NAK)")
	}

	// The listener parsed the caller's advertised flags: this caller disabled NAK
	// reporting, so the listener sees peerNakReport == false.
	rs, err := recv.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if rs.PeerNakReport {
		t.Error("listener-side PeerNakReport = true, want false (caller advertised no periodic NAK)")
	}
}
