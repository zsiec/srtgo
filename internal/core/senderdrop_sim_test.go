package core_test

import (
	"encoding/binary"
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/packet"
)

// TestSenderDropTLPKTDrop proves the live-mode TLPKTDROP path: a sender that has
// been unable to advance (no ACKs) abandons the head packets older than the drop
// threshold and emits a DROPREQ for exactly that sequence range.
func TestSenderDropTLPKTDrop(t *testing.T) {
	const (
		payloadSize = 100
		sndISN      = 100
		n           = 5
	)
	base := clock.Timestamp(1_000_000)

	c := core.NewEstablished(core.Config{
		PeerSocketID: 2, PayloadSize: payloadSize, SendISN: sndISN, RecvISN: 5000,
		MaxBW: 1 << 34, Live: true, TsbpdDelay: 120 * clock.Millisecond, TLPktDrop: true,
	}, base)

	// Drain the construction effects (ACK/NAK timers).
	drainOutputs(c)

	// Send n packets, each 1ms apart so the live-CC pacer transmits every one
	// immediately (rather than queuing all but the first). With no peer they all
	// sit unacked in the send buffer, sent within a 5ms window near base.
	for i := 0; i < n; i++ {
		c.Write(base.Add(clock.Microseconds(i)*clock.Millisecond), []byte("payload-data"))
		drainOutputs(c)
	}

	// The drop threshold is max(120ms, 1s)+20ms = 1.02s. Advance past it and fire
	// the periodic ACK heartbeat, which runs the sender-drop check.
	now := base.Add(1100 * clock.Millisecond)
	c.HandleTimer(now, core.TimerACK)

	// A single DROPREQ must cover the whole abandoned range [100, 104].
	var dropReqs []packet.CIFDropReq
	for {
		o, ok := c.PollOutput()
		if !ok {
			break
		}
		sp, ok := o.(core.SendPacket)
		if !ok {
			continue
		}
		if sp.Packet.Header.IsControl && sp.Packet.Header.ControlType == packet.CtrlTypeDropReq {
			var dr packet.CIFDropReq
			if err := dr.UnmarshalCIF(sp.Packet.Data); err == nil {
				dropReqs = append(dropReqs, dr)
			}
		}
		if sp.Owned {
			sp.Packet.Release()
		}
	}
	if len(dropReqs) != 1 {
		t.Fatalf("emitted %d DROPREQs, want 1", len(dropReqs))
	}
	if dropReqs[0].FirstSeqNo != sndISN || dropReqs[0].LastSeqNo != sndISN+n-1 {
		t.Fatalf("DROPREQ range [%d,%d], want [%d,%d]",
			dropReqs[0].FirstSeqNo, dropReqs[0].LastSeqNo, sndISN, sndISN+n-1)
	}
	if st := c.Stats(); st.SentDropped != n {
		t.Fatalf("SentDropped = %d, want %d", st.SentDropped, n)
	}
}

// drainOutputs discards all currently pending outputs (releasing owned packets).
func drainOutputs(c *core.Conn) {
	for {
		o, ok := c.PollOutput()
		if !ok {
			return
		}
		if sp, ok := o.(core.SendPacket); ok && sp.Owned {
			sp.Packet.Release()
		}
	}
}

// TestSimMessageTTL proves per-message TTL end-to-end in message mode (which has
// no TSBPD too-late drop, so a gap can ONLY clear via a DROPREQ). One message is
// given a short TTL and its single packet is permanently lost; after the TTL
// expires the sender drops it and tells the receiver to skip it, so the receiver
// delivers every other message in order — without that DROPREQ the reliable
// stream would block on the gap forever.
func TestSimMessageTTL(t *testing.T) {
	const (
		payloadSize = 100
		sndISN      = 100
		rcvISN      = 5000
		numMsgs     = 12
		lost        = 5 // this message's packet is permanently dropped
	)
	base := clock.Timestamp(1_000_000)

	sender := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: 2, PayloadSize: payloadSize, SendISN: sndISN, RecvISN: rcvISN,
		MaxBW: 1 << 34, Message: true,
	}, base))
	receiver := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: 1, PayloadSize: payloadSize, SendISN: rcvISN, RecvISN: sndISN,
		MaxBW: 1 << 34, Message: true,
	}, base))

	// One small (single-packet) message per index, so message i occupies sequence
	// number sndISN+i. The lost message carries a short TTL; the rest are reliable.
	for i := 0; i < numMsgs; i++ {
		b := make([]byte, 8)
		binary.BigEndian.PutUint32(b, uint32(i))
		if i == lost {
			sender.c.WriteMsg(base, b, core.MsgOptions{InOrder: true, TTL: 150 * clock.Millisecond})
		} else {
			sender.c.Write(base, b)
		}
	}

	lostSeq := uint32(sndISN + lost)
	drive(t, sender, receiver, base, func(s uint32) bool { return s == lostSeq }, func() bool {
		return len(receiver.delivered) >= numMsgs-1
	})

	if got := len(receiver.delivered); got != numMsgs-1 {
		t.Fatalf("delivered %d messages, want %d (the TTL'd message must be skipped)", got, numMsgs-1)
	}
	// Delivered indices must be every message except the lost one, in order.
	want := 0
	for _, m := range receiver.delivered {
		if want == lost {
			want++ // the lost message is skipped
		}
		if got := binary.BigEndian.Uint32(m); got != uint32(want) {
			t.Fatalf("out-of-order delivery: got index %d, want %d", got, want)
		}
		want++
	}
	if st := sender.c.Stats(); st.SentDropped != 1 {
		t.Fatalf("sender SentDropped = %d, want 1 (only the TTL'd message)", st.SentDropped)
	}
	if st := receiver.c.Stats(); st.RecvDropped == 0 {
		t.Fatal("receiver RecvDropped = 0, want >=1 (the skipped message)")
	}
}
