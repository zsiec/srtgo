package session_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/session"
)

// TestSessionMessageModeUDP drives two real message-mode sessions over loopback
// UDP, dropping a few data packets on the sender's socket. The sender writes
// variable-length messages (1..4 packets each) via WriteMsg; the receiver reads
// them with ReadMsg and must get every message reassembled byte-for-byte, in
// order, with the right per-message metadata (message number, first sequence
// number, and boundary) — proving the message-framing path end-to-end through
// the I/O host, including ARQ recovery of a dropped fragment.
func TestSessionMessageModeUDP(t *testing.T) {
	const (
		N          = 40
		payloadLen = 200
		sndID      = 1
		rcvID      = 2
		maxBW      = 125_000_000
	)

	rawS, rConn := mustUDP(t), mustUDP(t)
	// Drop these data sequence numbers once each (sender ISN is 100); their
	// retransmissions get through, so the affected messages still complete.
	sConn := &lossyConn{
		PacketConn: rawS,
		dropSeq:    map[uint32]bool{104: true, 105: true, 130: true, 175: true},
	}
	sMux, rMux := mux.New(sConn, 1500), mux.New(rConn, 1500)
	sRecv := sMux.Register(sndID)
	rRecv := rMux.Register(rcvID)

	receiver := session.NewEstablished(rMux, rRecv, true, rawS.LocalAddr(), core.Config{
		PeerSocketID: sndID, PayloadSize: payloadLen, SendISN: 9000, RecvISN: 100,
		MaxBW: maxBW, Message: true,
	}, clock.NewRealClock())
	sender := session.NewEstablished(sMux, sRecv, true, rConn.LocalAddr(), core.Config{
		PeerSocketID: rcvID, PayloadSize: payloadLen, SendISN: 100, RecvISN: 9000,
		MaxBW: maxBW, Message: true,
	}, clock.NewRealClock())
	defer sender.Close()
	defer receiver.Close()

	// Build the messages and their expected metadata up front.
	msgs := make([][]byte, N)
	wantBoundary := make([]int, N)
	wantSeq := make([]uint32, N)
	seq := uint32(100)
	for i := range msgs {
		nfrag := (i % 4) + 1
		size := (nfrag-1)*payloadLen + (payloadLen / 2) + 8
		m := make([]byte, size)
		binary.BigEndian.PutUint32(m, uint32(i))
		binary.BigEndian.PutUint32(m[size-4:], uint32(size))
		msgs[i] = m

		if nfrag == 1 {
			wantBoundary[i] = int(packet.PositionSingle)
		} else {
			wantBoundary[i] = int(packet.PositionFirst)
		}
		wantSeq[i] = seq
		seq += uint32(nfrag)
	}

	go func() {
		for i := range msgs {
			if err := sender.WriteMsg(msgs[i], core.MsgOptions{InOrder: true}); err != nil {
				return
			}
		}
	}()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4*payloadLen+64)
		for i := 0; i < N; i++ {
			n, meta, err := receiver.ReadMsg(buf)
			if err != nil {
				done <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			if !bytes.Equal(buf[:n], msgs[i]) {
				done <- fmt.Errorf("message %d mismatch: got %d bytes want %d", i, n, len(msgs[i]))
				return
			}
			if meta.MsgNo != uint32(i+1) {
				done <- fmt.Errorf("message %d: MsgNo=%d want %d", i, meta.MsgNo, i+1)
				return
			}
			if meta.Boundary != wantBoundary[i] {
				done <- fmt.Errorf("message %d: Boundary=%d want %d", i, meta.Boundary, wantBoundary[i])
				return
			}
			if meta.Seq != wantSeq[i] {
				done <- fmt.Errorf("message %d: Seq=%d want %d", i, meta.Seq, wantSeq[i])
				return
			}
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for message delivery")
	}
}

// TestSessionMessageTTLUDP drives two real message-mode sessions over loopback
// UDP. One message is sent with a short per-message TTL and its packet is
// permanently dropped on the sender's socket. Message mode is reliable (no TSBPD
// too-late drop), so the only way past the gap is the sender abandoning the
// message after its TTL and telling the receiver to skip it with a DROPREQ — the
// receiver must then deliver every other message, in order, end-to-end.
func TestSessionMessageTTLUDP(t *testing.T) {
	const (
		N          = 10
		payloadLen = 200
		lost       = 4 // this message's (single) packet is permanently dropped
		sndID      = 1
		rcvID      = 2
		maxBW      = 125_000_000
	)

	rawS, rConn := mustUDP(t), mustUDP(t)
	// Permanently drop the lost message's sequence number (sender ISN is 100, one
	// packet per small message, so message i is sequence 100+i).
	sConn := &lossyConn{
		PacketConn: rawS,
		dropSeq:    map[uint32]bool{100 + lost: true},
		permanent:  true,
	}
	sMux, rMux := mux.New(sConn, 1500), mux.New(rConn, 1500)
	sRecv := sMux.Register(sndID)
	rRecv := rMux.Register(rcvID)

	receiver := session.NewEstablished(rMux, rRecv, true, rawS.LocalAddr(), core.Config{
		PeerSocketID: sndID, PayloadSize: payloadLen, SendISN: 9000, RecvISN: 100,
		MaxBW: maxBW, Message: true,
	}, clock.NewRealClock())
	sender := session.NewEstablished(sMux, sRecv, true, rConn.LocalAddr(), core.Config{
		PeerSocketID: rcvID, PayloadSize: payloadLen, SendISN: 100, RecvISN: 9000,
		MaxBW: maxBW, Message: true,
	}, clock.NewRealClock())
	defer sender.Close()
	defer receiver.Close()

	go func() {
		for i := 0; i < N; i++ {
			b := make([]byte, 8)
			binary.BigEndian.PutUint32(b, uint32(i))
			opts := core.MsgOptions{InOrder: true}
			if i == lost {
				opts.TTL = clock.FromDuration(200 * time.Millisecond)
			}
			_ = sender.WriteMsg(b, opts)
		}
	}()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		want := 0
		for got := 0; got < N-1; got++ {
			n, _, err := receiver.ReadMsg(buf)
			if err != nil {
				done <- fmt.Errorf("read %d: %w", got, err)
				return
			}
			if want == lost {
				want++ // the TTL'd message is skipped
			}
			if n != 8 || binary.BigEndian.Uint32(buf) != uint32(want) {
				done <- fmt.Errorf("read %d: got index %d (len %d), want %d", got, binary.BigEndian.Uint32(buf), n, want)
				return
			}
			want++
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for TTL drop + skip")
	}

	if st, err := sender.Stats(); err == nil && st.SentDropped == 0 {
		t.Fatal("sender SentDropped = 0, want >=1 (the TTL'd message)")
	}
}
