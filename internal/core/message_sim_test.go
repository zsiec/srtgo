package core_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/packet"
)

// This file proves message-mode framing: a payload larger than one packet is
// fragmented into PB_FIRST..PB_LAST sharing one message number, and the receiver
// reassembles and delivers each complete message as one unit with the right
// per-message metadata — recovering dropped fragments via ARQ along the way.

const msgPayloadSize = 100 // small, so messages span several packets

// TestSimMessageMode streams variable-length messages (1..5 packets each)
// through two message-mode cores over the lossy in-memory link, dropping a few
// fragments once. Every message must be reassembled byte-for-byte, in order,
// with a distinct increasing message number, the correct boundary (PB_SINGLE for
// a one-packet message, PB_FIRST otherwise), and the message's first sequence
// number.
func TestSimMessageMode(t *testing.T) {
	const (
		sndSocketID = 1
		rcvSocketID = 2
		sndISN      = 100
		rcvISN      = 5000
		numMsgs     = 60
	)
	base := clock.Timestamp(1_000_000)

	sender := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: rcvSocketID, PayloadSize: msgPayloadSize,
		SendISN: sndISN, RecvISN: rcvISN, MaxBW: 1 << 34, Message: true,
	}, base))
	receiver := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: sndSocketID, PayloadSize: msgPayloadSize,
		SendISN: rcvISN, RecvISN: sndISN, MaxBW: 1 << 34, Message: true,
	}, base))

	// Build messages of varying multi-packet sizes. Tag the index at the front
	// and the length at the back so a mis-assembled or truncated message is
	// caught by the byte-for-byte comparison.
	msgs := make([][]byte, numMsgs)
	wantBoundary := make([]int, numMsgs)
	wantSeq := make([]uint32, numMsgs)
	seq := uint32(sndISN)
	for i := range msgs {
		nfrag := (i % 5) + 1                                        // 1..5 packets
		size := (nfrag-1)*msgPayloadSize + (i%msgPayloadSize)/2 + 8 // partial last fragment
		m := make([]byte, size)
		binary.BigEndian.PutUint32(m, uint32(i))
		binary.BigEndian.PutUint32(m[size-4:], uint32(size))
		msgs[i] = m

		frags := (size + msgPayloadSize - 1) / msgPayloadSize
		if frags == 1 {
			wantBoundary[i] = int(packet.PositionSingle)
		} else {
			wantBoundary[i] = int(packet.PositionFirst)
		}
		wantSeq[i] = seq
		seq += uint32(frags)

		sender.c.Write(base, m)
	}

	// Drop a few forward data packets once; ARQ retransmission recovers them,
	// so even a message missing a middle fragment is eventually delivered whole.
	dropFwd := map[uint32]bool{103: true, 104: true, 150: true, 222: true}

	drive(t, sender, receiver, base, dropOnce(dropFwd), func() bool {
		return len(receiver.delivered) >= numMsgs
	})

	if got := len(receiver.delivered); got != numMsgs {
		t.Fatalf("delivered %d/%d messages", got, numMsgs)
	}
	for i := range msgs {
		if !bytes.Equal(receiver.delivered[i], msgs[i]) {
			t.Fatalf("message %d mismatch: got %d bytes, want %d", i, len(receiver.delivered[i]), len(msgs[i]))
		}
		meta := receiver.recvMeta[i]
		if meta.MsgNo != uint32(i+1) {
			t.Fatalf("message %d: MsgNo=%d want %d", i, meta.MsgNo, i+1)
		}
		if meta.Boundary != wantBoundary[i] {
			t.Fatalf("message %d: Boundary=%d want %d", i, meta.Boundary, wantBoundary[i])
		}
		if meta.Seq != wantSeq[i] {
			t.Fatalf("message %d: Seq=%d want %d", i, meta.Seq, wantSeq[i])
		}
	}

	// The loss must have been recovered by retransmission (no too-late drop in
	// message mode), and at least some messages must have spanned >1 packet.
	if st := sender.c.Stats(); st.RetransPackets == 0 {
		t.Fatal("expected retransmissions to recover the dropped fragments")
	}
	multi := 0
	for i := range wantBoundary {
		if wantBoundary[i] == int(packet.PositionFirst) {
			multi++
		}
	}
	if multi == 0 {
		t.Fatal("test built no multi-packet messages")
	}
}

// drainData returns the first emitted data packet's header, draining outputs.
func firstDataHeader(t *testing.T, c *core.Conn) packet.Header {
	t.Helper()
	for {
		o, ok := c.PollOutput()
		if !ok {
			t.Fatal("no data packet emitted")
		}
		sp, ok := o.(core.SendPacket)
		if !ok {
			continue
		}
		h := sp.Packet.Header
		if sp.Owned {
			sp.Packet.Release()
		}
		if !h.IsControl {
			return h
		}
	}
}

// TestWriteMsgSrcTime proves an explicit MsgOptions.SrcTime overrides the wire
// timestamp, while a zero SrcTime defers to the live wire time.
func TestWriteMsgSrcTime(t *testing.T) {
	base := clock.Timestamp(1_000_000)
	c := core.NewEstablished(core.Config{
		PeerSocketID: 2, PayloadSize: msgPayloadSize, SendISN: 100, RecvISN: 5000, MaxBW: 1 << 34,
	}, base)
	// Drain the construction effects (ACK/NAK timers) first.
	for {
		if _, ok := c.PollOutput(); !ok {
			break
		}
	}

	const srcTS = 0xDEADBEEF
	c.WriteMsg(base, []byte("hello"), core.MsgOptions{SrcTime: srcTS, InOrder: true})
	if h := firstDataHeader(t, c); h.Timestamp != srcTS {
		t.Fatalf("SrcTime override: wire timestamp=%#x want %#x", h.Timestamp, uint32(srcTS))
	}
}

// TestWriteMsgInOrderBit proves the InOrder option sets the packet's Order bit.
func TestWriteMsgInOrderBit(t *testing.T) {
	base := clock.Timestamp(1_000_000)
	for _, inOrder := range []bool{true, false} {
		c := core.NewEstablished(core.Config{
			PeerSocketID: 2, PayloadSize: msgPayloadSize, SendISN: 100, RecvISN: 5000,
			MaxBW: 1 << 34, Message: true,
		}, base)
		for {
			if _, ok := c.PollOutput(); !ok {
				break
			}
		}
		c.WriteMsg(base, []byte("payload"), core.MsgOptions{InOrder: inOrder})
		if h := firstDataHeader(t, c); h.Order != inOrder {
			t.Fatalf("InOrder=%v: Order bit=%v", inOrder, h.Order)
		}
	}
}
