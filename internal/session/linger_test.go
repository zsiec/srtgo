package session_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/session"
)

// TestSessionLingerShutdownUDP proves graceful close: with a linger configured,
// Close drains in-flight data before sending SHUTDOWN, so the receiver gets
// every payload; and once the SHUTDOWN arrives the receiver's Read returns EOF
// promptly instead of hanging until an idle timeout.
func TestSessionLingerShutdownUDP(t *testing.T) {
	const (
		N          = 200
		payloadLen = 600
		sndID      = 1
		rcvID      = 2
		maxBW      = 125_000_000
	)

	sConn, rConn := mustUDP(t), mustUDP(t)
	sMux, rMux := mux.New(sConn, 1500), mux.New(rConn, 1500)
	sRecv := sMux.Register(sndID)
	rRecv := rMux.Register(rcvID)

	receiver := session.NewEstablished(rMux, rRecv, true, sConn.LocalAddr(), core.Config{
		PeerSocketID: sndID, PayloadSize: payloadLen, SendISN: 9000, RecvISN: 100, MaxBW: maxBW,
	}, clock.NewRealClock())
	defer receiver.Close()
	sender := session.NewEstablished(sMux, sRecv, true, rConn.LocalAddr(), core.Config{
		PeerSocketID: rcvID, PayloadSize: payloadLen, SendISN: 100, RecvISN: 9000, MaxBW: maxBW,
	}, clock.NewRealClock())
	sender.SetLinger(3 * time.Second)

	// Write everything, then close with linger — the drain must deliver all N.
	for i := 0; i < N; i++ {
		p := make([]byte, payloadLen)
		binary.BigEndian.PutUint32(p, uint32(i))
		if err := sender.Write(p); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	go sender.Close() // lingers (drains) then sends SHUTDOWN

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2000)
		for i := 0; i < N; i++ {
			n, err := receiver.Read(buf)
			if err != nil {
				done <- err
				return
			}
			if n != payloadLen || binary.BigEndian.Uint32(buf) != uint32(i) {
				done <- fmt.Errorf("payload mismatch at %d (n=%d)", i, n)
				return
			}
		}
		// All N received; the peer's SHUTDOWN should now surface as EOF.
		_, err := receiver.Read(buf)
		if !errors.Is(err, io.EOF) {
			done <- fmt.Errorf("after close: Read err = %v, want io.EOF", err)
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout: linger/SHUTDOWN did not deliver all payloads + EOF")
	}
}
