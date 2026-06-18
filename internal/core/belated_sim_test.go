package core_test

import (
	"encoding/binary"
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/packet"
)

// TestRecvBelatedStats drives a live receiver core: it delivers a run of packets
// (advancing the read frontier), then re-injects an already-delivered one. That
// packet is belated, so RecvBelated and the EWMA AvgBelatedMicros must register.
func TestRecvBelatedStats(t *testing.T) {
	const (
		rcvISN     = 100
		n          = 12
		intervalUs = clock.Microseconds(10_000) // 10ms
		delay      = clock.Microseconds(120_000)
	)
	base := clock.Timestamp(1_000_000)
	rcv := core.NewEstablished(core.Config{
		PeerSocketID: 1, PayloadSize: simPayload, SendISN: 9000, RecvISN: rcvISN,
		MaxBW: 1 << 34, Live: true, TsbpdDelay: delay,
	}, base)

	timers := map[core.TimerID]clock.Timestamp{}
	delivered := map[uint32]bool{}
	drain := func() {
		for {
			o, ok := rcv.PollOutput()
			if !ok {
				break
			}
			switch v := o.(type) {
			case core.SetTimer:
				timers[v.ID] = v.Deadline
			case core.ClearTimer:
				delete(timers, v.ID)
			case core.SendPacket:
				if v.Owned {
					v.Packet.Release()
				}
			}
		}
		for {
			e, ok := rcv.PollEvent()
			if !ok {
				break
			}
			if d, ok := e.(core.DataReceived); ok {
				delivered[binary.BigEndian.Uint32(d.Data)] = true
			}
		}
	}
	mkpkt := func(i int) packet.Packet {
		ts := uint32(int64(intervalUs) * int64(i))
		payload := make([]byte, simPayload)
		binary.BigEndian.PutUint32(payload, uint32(i))
		return packet.NewData(nil, uint32(rcvISN+i), ts, 1, payload)
	}

	drain()
	now := base
	for i := 0; i < n; i++ {
		rcv.HandlePacket(now, mkpkt(i))
		drain()
		now = now.Add(intervalUs)
	}
	// Advance time, firing the TSBPD timers, until every packet has played out.
	for step := 0; step < 1000 && len(delivered) < n; step++ {
		now = now.Add(intervalUs)
		for id, dl := range timers {
			if !dl.After(now) {
				delete(timers, id)
				rcv.HandleTimer(now, id)
			}
		}
		drain()
	}
	if len(delivered) < n {
		t.Fatalf("only %d/%d packets delivered before belated injection", len(delivered), n)
	}

	// Re-inject an already-delivered packet — its sequence is now behind the read
	// frontier, so it is belated.
	now = now.Add(50_000)
	rcv.HandlePacket(now, mkpkt(3))
	drain()

	st := rcv.Stats()
	if st.RecvBelated == 0 {
		t.Fatalf("RecvBelated = 0, want >= 1")
	}
	if st.AvgBelatedMicros <= 0 {
		t.Fatalf("AvgBelatedMicros = %d, want > 0 (late vs play deadline)", st.AvgBelatedMicros)
	}
}
