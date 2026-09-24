package core

import (
	"github.com/zsiec/srtgo/internal/clock"
	"testing"
)

func TestAsymmetricHandshakeLatency(t *testing.T) {
	caller, accepted, hs := testHandshake(t,
		DialConfig{CallerSocketID: 7, CallerISN: 100, Live: true, TLPktDrop: true, RecvLatencyMS: 1800, SendLatencyMS: 250},
		ListenerConfig{Live: true, TLPktDrop: true, RecvLatencyMS: 400, SendLatencyMS: 1500}, nil)
	if accepted == nil {
		t.Fatal("no accepted connection")
	}
	if hs.SRTHS.RecvTSBPDDelay != 400 || hs.SRTHS.SendTSBPDDelay != 1800 {
		t.Fatalf("HSRSP latency = %+v", hs.SRTHS)
	}
	for _, tc := range []struct {
		c          *Conn
		recv, peer clock.Microseconds
	}{
		{caller, 1800 * clock.Millisecond, 400 * clock.Millisecond},
		{accepted.Conn, 400 * clock.Millisecond, 1800 * clock.Millisecond},
	} {
		st := tc.c.Stats()
		if st.NegotiatedLatency != tc.recv || st.PeerLatency != tc.peer {
			t.Fatalf("local/peer latency = %d/%d, want %d/%d", st.NegotiatedLatency, st.PeerLatency, tc.recv, tc.peer)
		}
	}
	// The listener must retain data beyond its short local receive delay and
	// the 1s floor, until the caller's 1.8s receive window expires.
	c := accepted.Conn
	base := clock.Timestamp(2_000_000)
	c.Write(base, []byte("retain for peer"))
	c.HandleTimer(base.Add(1400*clock.Millisecond), TimerACK)
	if c.Stats().SentDropped != 0 {
		t.Fatal("dropped using local receive latency")
	}
	c.HandleTimer(base.Add(1850*clock.Millisecond), TimerACK)
	if c.Stats().SentDropped != 1 {
		t.Fatal("did not expire after peer receive latency")
	}
}

func TestRendezvousAsymmetricLatency(t *testing.T) {
	for _, cookies := range [][2]uint32{{1000, 500}, {500, 1000}} {
		a := DialRendezvous(RendezvousConfig{SocketID: 1, ISN: 100, Cookie: cookies[0], Live: true, RecvLatencyMS: 1800, SendLatencyMS: 250}, 1)
		b := DialRendezvous(RendezvousConfig{SocketID: 2, ISN: 200, Cookie: cookies[1], Live: true, RecvLatencyMS: 400, SendLatencyMS: 1500}, 1)
		for i := 0; i < 12; i++ {
			for _, pair := range [][2]*Conn{{a, b}, {b, a}} {
				for {
					out, ok := pair[0].PollOutput()
					if !ok {
						break
					}
					if sp, ok := out.(SendPacket); ok {
						pair[1].HandlePacket(2, sp.Packet)
						if sp.Owned {
							sp.Packet.Release()
						}
					}
				}
			}
			if a.state == stateConnected && b.state == stateConnected {
				break
			}
		}
		if a.state != stateConnected || b.state != stateConnected {
			t.Fatal("rendezvous did not connect")
		}
		if a.Stats().NegotiatedLatency != 1800*clock.Millisecond || a.Stats().PeerLatency != 400*clock.Millisecond || b.Stats().NegotiatedLatency != 400*clock.Millisecond || b.Stats().PeerLatency != 1800*clock.Millisecond {
			t.Fatalf("wrong directional latency: a=%+v b=%+v", a.Stats(), b.Stats())
		}
	}
}
