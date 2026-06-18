package session_test

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/session"
)

// TestSessionPeerIdleUnblocksRead proves dead-peer detection at the session
// level: once the peer stops sending entirely, the receiver's idle timeout fires
// (a core Failed event), the event loop tears down, and a blocked Read returns
// an error instead of hanging forever.
func TestSessionPeerIdleUnblocksRead(t *testing.T) {
	const (
		N          = 20
		payloadLen = 600
		sndID      = 1
		rcvID      = 2
		maxBW      = 125_000_000
	)

	sConn, rConn := mustUDP(t), mustUDP(t)
	sMux, rMux := mux.New(sConn, 1500), mux.New(rConn, 1500)
	sRecv := sMux.Register(sndID)
	rRecv := rMux.Register(rcvID)

	// The receiver enables a short dead-peer timeout.
	receiver := session.NewEstablished(rMux, rRecv, true, sConn.LocalAddr(), core.Config{
		PeerSocketID: sndID, PayloadSize: payloadLen, SendISN: 9000, RecvISN: 100,
		MaxBW: maxBW, PeerIdleTimeout: 300 * clock.Millisecond,
	}, clock.NewRealClock())
	sender := session.NewEstablished(sMux, sRecv, true, rConn.LocalAddr(), core.Config{
		PeerSocketID: rcvID, PayloadSize: payloadLen, SendISN: 100, RecvISN: 9000, MaxBW: maxBW,
	}, clock.NewRealClock())
	defer receiver.Close()

	// Stream a few payloads so the connection is demonstrably alive.
	go func() {
		for i := 0; i < N; i++ {
			p := make([]byte, payloadLen)
			binary.BigEndian.PutUint32(p, uint32(i))
			if err := sender.Write(p); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 2000)
	for i := 0; i < N; i++ {
		if _, err := receiver.Read(buf); err != nil {
			t.Fatalf("read %d before kill: %v", i, err)
		}
	}

	// Kill the peer: it stops sending anything. The receiver should give up after
	// its idle timeout and a blocked Read must return an error (not hang).
	sender.Close()

	done := make(chan error, 1)
	go func() {
		_, err := receiver.Read(buf)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Read returned nil after the peer went idle; want an error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read hung after the peer went idle (dead-peer detection did not fire)")
	}
}
