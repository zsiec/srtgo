package core

import (
	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/congestion"
	"testing"
)

func TestHandshakeBandwidthOptions(t *testing.T) {
	for _, v4 := range []bool{false, true} {
		c, a, _ := testHandshake(t, DialConfig{CallerSocketID: 7, CallerISN: 100, ForceHSv4: v4, InputBW: 100000, OverheadBW: 50}, ListenerConfig{InputBW: 200000, OverheadBW: 100}, nil)
		for _, tc := range []struct {
			c    *Conn
			want int64
		}{{c, 150000}, {a.Conn, 400000}} {
			if got := tc.c.Stats().MaxBW; got != tc.want {
				t.Fatalf("v4=%v bandwidth=%d want %d", v4, got, tc.want)
			}
		}
	}
	c := DialRendezvous(RendezvousConfig{SocketID: 7, ISN: 100, Cookie: 10, InputBW: 300000, OverheadBW: 50}, 1)
	c.rdv.peerSocketID = 8
	c.rendezvousEstablish(2)
	if got := c.Stats().MaxBW; got != 450000 {
		t.Fatalf("rendezvous bandwidth=%d", got)
	}
}

func TestLiveBandwidthUpdates(t *testing.T) {
	c := NewEstablished(Config{PayloadSize: 1316, InputBW: 100000, OverheadBW: 50}, 1)
	check := func(want int64) {
		t.Helper()
		st := c.Stats()
		if st.MaxBW != want || st.PktSndPeriodMicros != max(int64(1), 1360*1000000/want) {
			t.Fatalf("bandwidth=%d interval=%d want %d", st.MaxBW, st.PktSndPeriodMicros, want)
		}
	}
	check(150000)
	c.SetInputBW(200000)
	check(300000)
	c.SetOverhead(100)
	check(400000)
	c.SetMaxBW(900000)
	check(900000)
	c.SetInputBW(300000)
	c.SetOverhead(50)
	check(900000)
	c.SetMaxBW(0)
	check(450000)
	c.SetMinInputBW(1000000)
	check(450000) // declared input takes precedence
	c.SetInputBW(0)
	check(1500000)
	c.SetMinInputBW(0)
	check(congestion.DefaultMaxBW)
}

func TestAutomaticInputBandwidthFloor(t *testing.T) {
	c := NewEstablished(Config{Live: true, PayloadSize: 100, MinInputBW: 1000, OverheadBW: 50}, 1)
	// 2000 application bytes over exactly one second. ACKs/retransmits do not
	// count as new input; only Write contributes to the rate estimate.
	for i := 0; i < 20; i++ {
		c.Write(clock.Timestamp(1+i*50000), make([]byte, 100))
	}
	c.HandleTimer(clock.Timestamp(1).Add(clock.Second), TimerACK)
	if got := c.Stats().MaxBW; got != 3000 {
		t.Fatalf("sampled bandwidth=%d want 3000", got)
	}
	c.SetMinInputBW(4000)
	if got := c.Stats().MaxBW; got != 6000 {
		t.Fatalf("floor bandwidth=%d want 6000", got)
	}
	c.HandleTimer(clock.Timestamp(1).Add(2*clock.Second), TimerACK)
	if got := c.Stats().MaxBW; got != 6000 {
		t.Fatalf("idle bandwidth=%d want 6000", got)
	}
	c.SetMinInputBW(0)
	if got := c.Stats().MaxBW; got != 3000 {
		t.Fatalf("retained sample=%d want 3000", got)
	}
}

func TestFileBandwidthRemainsExplicit(t *testing.T) {
	c := NewEstablished(Config{Congestion: "file", MaxBW: 900000, InputBW: 100000, OverheadBW: 50}, 1)
	c.SetInputBW(200000)
	c.SetOverhead(100)
	c.SetMinInputBW(1000000)
	if got := c.Stats().MaxBW; got != 900000 {
		t.Fatalf("file max=%d", got)
	}
	c.SetMaxBW(500000)
	if got := c.Stats().MaxBW; got != 500000 {
		t.Fatalf("file max=%d", got)
	}
}
