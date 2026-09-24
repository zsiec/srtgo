package core

import (
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/seq"
)

func TestHandshakePayloadSize(t *testing.T) {
	for _, v4 := range []bool{false, true} {
		for _, tc := range []struct {
			name, cc               string
			callerMSS, listenerMSS uint32
			payload, want          int
		}{
			{"live-default", "live", 1500, 1500, 0, 1316},
			{"file-default", "file", 1500, 1500, 0, 1456},
			{"smaller-listener", "live", 1500, 1200, 0, 1156},
			{"smaller-caller", "live", 1100, 1500, 0, 1056},
			{"explicit", "live", 1500, 1500, 1000, 1000},
			{"explicit-clamped", "live", 1500, 1200, 1400, 1156},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c, a, hs := testHandshake(t, DialConfig{CallerSocketID: 7, CallerISN: 100, ForceHSv4: v4, MSS: tc.callerMSS, PayloadSize: tc.payload, Congestion: tc.cc}, ListenerConfig{MSS: tc.listenerMSS, PayloadSize: tc.payload, Congestion: tc.cc}, nil)
				if a == nil || c.state != stateConnected {
					t.Fatal("not connected")
				}
				if hs.MaxTransmissionUnitSize != min(tc.callerMSS, tc.listenerMSS) {
					t.Fatalf("negotiated MSS %d", hs.MaxTransmissionUnitSize)
				}
				for _, conn := range []*Conn{c, a.Conn} {
					if conn.payloadSize != tc.want {
						t.Fatalf("v4=%v payload %d, want %d", v4, conn.payloadSize, tc.want)
					}
					conn.Write(2_000_000, make([]byte, tc.want+1))
					conn.HandleTimer(clock.Timestamp(2_000_000).Add(clock.Second), TimerSndPacing)
					sizes := []int{}
					for {
						out, ok := conn.PollOutput()
						if !ok {
							break
						}
						if sp, ok := out.(SendPacket); ok {
							if !sp.Packet.Header.IsControl {
								sizes = append(sizes, len(sp.Packet.Data))
							}
							if sp.Owned {
								sp.Packet.Release()
							}
						}
					}
					if len(sizes) != 2 || sizes[0] != tc.want || sizes[1] != 1 {
						t.Fatalf("wire payload sizes %v, want [%d 1]", sizes, tc.want)
					}
				}
			})
		}
	}
}

func TestRendezvousPayloadSizeUsesPeerMSS(t *testing.T) {
	for _, cc := range []string{"live", "file"} {
		a := DialRendezvous(RendezvousConfig{SocketID: 1, ISN: seq.Number(100), Cookie: 1000, MSS: 1500, Congestion: cc}, 1)
		b := DialRendezvous(RendezvousConfig{SocketID: 2, ISN: seq.Number(200), Cookie: 500, MSS: 1200, Congestion: cc}, 1)
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
		if a.state != stateConnected || b.state != stateConnected || a.payloadSize != 1156 || b.payloadSize != 1156 {
			t.Fatalf("%s rendezvous payload %d/%d states %d/%d", cc, a.payloadSize, b.payloadSize, a.state, b.state)
		}
	}
}
