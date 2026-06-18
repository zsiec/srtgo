package core_test

import (
	"encoding/binary"
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
)

// TestSimTailLossRecovery proves the RTO/EXP blind-retransmit path. The last few
// packets of the stream (the "tail") are dropped on first transmission. Because
// nothing arrives after them, the receiver never advances past them and never
// detects a gap — so it sends NO NAK for the tail, and reactive retransmission
// can't recover it. Only the sender's EXP timer (blind-retransmit of unacked
// packets after the RTO elapses with no ACK progress) recovers them. Without it
// this stream would stall forever.
func TestSimTailLossRecovery(t *testing.T) {
	const (
		sndISN      = 100
		rcvISN      = 5000
		numPayloads = 100
		tail        = 5 // last `tail` packets dropped once
	)
	base := clock.Timestamp(1_000_000)

	sender := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: 2, PayloadSize: simPayload, SendISN: sndISN, RecvISN: rcvISN, MaxBW: 1 << 34,
	}, base))
	receiver := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: 1, PayloadSize: simPayload, SendISN: rcvISN, RecvISN: sndISN, MaxBW: 1 << 34,
	}, base))

	for i := 0; i < numPayloads; i++ {
		sender.c.Write(base, makePayload(i))
	}

	// Drop only the tail sequence numbers, once each (their retransmissions pass).
	drop := map[uint32]bool{}
	for s := uint32(sndISN + numPayloads - tail); s < sndISN+numPayloads; s++ {
		drop[s] = true
	}

	drive(t, sender, receiver, base, dropOnce(drop), func() bool {
		return len(receiver.delivered) >= numPayloads
	})

	if got := len(receiver.delivered); got != numPayloads {
		t.Fatalf("delivered %d/%d — tail loss not recovered (EXP blind-retransmit failed)", got, numPayloads)
	}
	for i, p := range receiver.delivered {
		if binary.BigEndian.Uint32(p) != uint32(i) {
			t.Fatalf("payload %d out of order: got %d", i, binary.BigEndian.Uint32(p))
		}
	}
	// The recovery must have come from a retransmission, and (since the tail is
	// never a detected gap) the receiver should not have NAK'd it.
	if st := sender.c.Stats(); st.RetransPackets < tail {
		t.Fatalf("RetransPackets=%d, want >= %d (the tail must be blind-retransmitted)", st.RetransPackets, tail)
	}
	if st := receiver.c.Stats(); st.SentNAKs != 0 {
		t.Fatalf("receiver sent %d NAKs; the lost tail is never a detected gap, so recovery must be RTO-driven", st.SentNAKs)
	}
}
