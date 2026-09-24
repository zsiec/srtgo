package core

import (
	"errors"
	"testing"

	"github.com/zsiec/srtgo/internal/congestion"
	"github.com/zsiec/srtgo/internal/packet"
)

func requireCongestionRejection(t *testing.T, c *Conn) {
	t.Helper()
	if c.state != stateFailed {
		t.Fatal("incompatible controller was accepted")
	}
	for {
		ev, ok := c.PollEvent()
		if !ok {
			break
		}
		if failed, ok := ev.(Failed); ok {
			var rej RejectError
			if !errors.As(failed.Err, &rej) || rej.Code != rejCongestion {
				t.Fatalf("failure = %v, want rejection 1013", failed.Err)
			}
			return
		}
	}
	t.Fatal("no failure event")
}

func TestListenerRejectsIncompatibleCongestion(t *testing.T) {
	for _, pair := range [][2]string{{"live", "file"}, {"file", "live"}, {"unknown", "live"}} {
		c, a, _ := testHandshake(t, DialConfig{CallerSocketID: 7, CallerISN: 100, Congestion: pair[0]}, ListenerConfig{Congestion: pair[1]}, nil)
		requireCongestionRejection(t, c)
		if a != nil {
			t.Fatal("incompatible caller was accepted by listener")
		}
	}
}

func TestCallerChecksCongestionResponse(t *testing.T) {
	for _, tc := range []struct {
		local, peer     string
		present, wantOK bool
	}{
		{"live", "live", true, true}, {"file", "file", true, true},
		{"live", "", false, true}, {"file", "", false, false},
		{"live", "file", true, false}, {"file", "live", true, false},
		{"live", "unknown", true, false}, {"live", "", true, false},
	} {
		t.Run(tc.local+"/"+tc.peer, func(t *testing.T) {
			c, _, _ := testHandshake(t, DialConfig{CallerSocketID: 7, CallerISN: 100, Congestion: tc.local}, ListenerConfig{Congestion: tc.local}, func(hs *packet.CIFHandshake) { hs.HasCongestion = tc.present; hs.CongestionType = tc.peer })
			if tc.wantOK {
				if c.state != stateConnected {
					t.Fatal("compatible response rejected")
				}
			} else {
				requireCongestionRejection(t, c)
			}
		})
	}
}

func TestRendezvousChecksCongestion(t *testing.T) {
	c := DialRendezvous(RendezvousConfig{SocketID: 7, ISN: 100, Cookie: 10, Congestion: "file"}, 1)
	c.handleRendezvous(2, &packet.CIFHandshake{SRTSocketID: 8, HandshakeType: packet.HandshakeTypeConclusion, ExtensionField: 1}, 0)
	requireCongestionRejection(t, c) // absent CC extension means live
}

func TestRendezvousUsesNegotiatedController(t *testing.T) {
	c := DialRendezvous(RendezvousConfig{SocketID: 7, ISN: 100, Cookie: 10, Congestion: "file"}, 1)
	c.rdv.peerSocketID = 8
	c.rdv.peerISN = 200
	c.rendezvousEstablish(2)
	if _, ok := c.sendCC.(*congestion.FileCC); !ok {
		t.Fatalf("file rendezvous installed %T", c.sendCC)
	}
}

func TestRendezvousDelayedWavehand(t *testing.T) {
	for _, state := range []rdvState{rdvFine, rdvInitiated} {
		c := DialRendezvous(RendezvousConfig{SocketID: 7, ISN: 100, Cookie: 10}, 1)
		c.rdv.rstate = state
		c.rdv.peerSocketID = 8
		c.rdv.side = rdvResponder
		c.rdv.haveTrans = true
		c.rdv.lastTrans = rdvTransition{newState: state, rspType: packet.HandshakeTypeConclusion, needsExt: true, needsHSRSP: true}
		c.handleRendezvous(2, &packet.CIFHandshake{SRTSocketID: 8, HandshakeType: packet.HandshakeTypeWavehand, SynCookie: 20}, 0)
		if c.state == stateFailed || c.rdv.rstate != state {
			t.Fatalf("delayed wavehand changed state %d", state)
		}
	}
}
