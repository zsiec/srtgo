package core

import (
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
)

// testHandshake exchanges real serialized handshake packets through the cores.
// mutateResponse can model a peer with an incompatible or malformed response.
func testHandshake(t *testing.T, dc DialConfig, lc ListenerConfig, mutateResponse func(*packet.CIFHandshake)) (*Conn, *Accepted, packet.CIFHandshake) {
	t.Helper()
	now := clock.Timestamp(1_000_000)
	caller := Dial(dc, now)
	listener := NewListener(lc, 1234, func(b []byte) {
		for i := range b {
			b[i] = byte(i + 10)
		}
	}, nil)
	var accepted *Accepted
	var response packet.CIFHandshake
	for turn := 0; turn < 8; turn++ {
		for {
			out, ok := caller.PollOutput()
			if !ok {
				break
			}
			if sp, ok := out.(SendPacket); ok {
				listener.HandlePacket(now, sp.Packet, "peer")
				if sp.Owned {
					sp.Packet.Release()
				}
			}
		}
		for {
			out, ok := listener.PollOutput()
			if !ok {
				break
			}
			sp := out.(SendTo)
			var hs packet.CIFHandshake
			if err := sp.Packet.UnmarshalCIF(&hs); err != nil {
				t.Fatal(err)
			}
			if hs.HandshakeType == packet.HandshakeTypeConclusion {
				if mutateResponse != nil {
					mutateResponse(&hs)
					if err := sp.Packet.MarshalCIF(&hs); err != nil {
						t.Fatal(err)
					}
				}
				response = hs
			}
			caller.HandlePacket(now, sp.Packet)
			sp.Packet.Release()
		}
		for {
			ev, ok := listener.PollEvent()
			if !ok {
				break
			}
			if a, ok := ev.(Accepted); ok {
				accepted = &a
			}
		}
		if caller.state == stateConnected || caller.state == stateFailed {
			return caller, accepted, response
		}
		now = now.Add(clock.Millisecond)
	}
	t.Fatal("handshake did not settle")
	return nil, nil, response
}

func TestListenerEchoesCallerISN(t *testing.T) {
	for _, v4 := range []bool{false, true} {
		for _, isn := range []seq.Number{0, 1, 123456, seq.Max} {
			c, a, hs := testHandshake(t, DialConfig{CallerSocketID: 7, CallerISN: isn, ForceHSv4: v4}, ListenerConfig{}, nil)
			if c.state != stateConnected || a == nil {
				t.Fatalf("v4=%v isn=%d: not connected", v4, isn)
			}
			if hs.InitialPacketSequenceNumber != isn.Value() || a.Conn.SendISN() != isn.Value() {
				t.Fatalf("v4=%v: response/send ISN = %d/%d, want %d", v4, hs.InitialPacketSequenceNumber, a.Conn.SendISN(), isn)
			}
		}
	}
}

func TestCallerRejectsChangedISN(t *testing.T) {
	for _, v4 := range []bool{false, true} {
		c, _, _ := testHandshake(t, DialConfig{CallerSocketID: 7, CallerISN: 100, ForceHSv4: v4}, ListenerConfig{}, func(hs *packet.CIFHandshake) { hs.InitialPacketSequenceNumber = 101 })
		if c.state != stateFailed {
			t.Fatalf("v4=%v: accepted a changed ISN", v4)
		}
	}
}

func TestGroupHandshakePreservesSharedISN(t *testing.T) {
	c, a, hs := testHandshake(t, DialConfig{CallerSocketID: 7, CallerISN: 1234, GroupID: 42, GroupType: 1}, ListenerConfig{}, nil)
	if c.state != stateConnected || a == nil || a.SharedISN != 1234 || hs.InitialPacketSequenceNumber != 1234 {
		t.Fatalf("group did not preserve caller ISN: accepted=%+v response=%+v", a, hs)
	}
}
