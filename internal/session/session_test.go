package session_test

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/session"
)

// lossyConn wraps a PacketConn and drops outgoing data packets whose sequence
// number is in dropSeq — but only the first time each is seen, so the
// retransmission gets through. The control-flag bit (high bit of byte 0)
// distinguishes data from control packets on the wire.
type lossyConn struct {
	net.PacketConn
	mu      sync.Mutex
	dropSeq map[uint32]bool
}

func (c *lossyConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) >= 4 && b[0]&0x80 == 0 { // data packet
		seqNo := binary.BigEndian.Uint32(b[0:4]) & 0x7FFFFFFF
		c.mu.Lock()
		drop := c.dropSeq[seqNo]
		if drop {
			delete(c.dropSeq, seqNo)
		}
		c.mu.Unlock()
		if drop {
			return len(b), nil // pretend the write succeeded; packet vanishes
		}
	}
	return c.PacketConn.WriteTo(b, addr)
}

func mustUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestSessionUDPLoopback drives two real sessions over loopback UDP: the
// sender streams N payloads, the receiver reads them back in order. This
// exercises the full I/O host — mux read loop, event loop, OS timer wheel,
// token-bucket pacing — driving the pure core over real sockets.
func TestSessionUDPLoopback(t *testing.T) {
	const (
		N          = 500
		payloadLen = 1200
		sndID      = 1
		rcvID      = 2
		maxBW      = 125_000_000 // ~1 Gbps so the stream finishes quickly
	)

	sConn, rConn := mustUDP(t), mustUDP(t)
	sMux, rMux := mux.New(sConn, 1500), mux.New(rConn, 1500)
	sRecv := sMux.Register(sndID)
	rRecv := rMux.Register(rcvID)

	receiver := session.NewEstablished(rMux, rRecv, true, sConn.LocalAddr(), core.Config{
		PeerSocketID: sndID, PayloadSize: payloadLen, SendISN: 9000, RecvISN: 100, MaxBW: maxBW,
	}, clock.NewRealClock())
	sender := session.NewEstablished(sMux, sRecv, true, rConn.LocalAddr(), core.Config{
		PeerSocketID: rcvID, PayloadSize: payloadLen, SendISN: 100, RecvISN: 9000, MaxBW: maxBW,
	}, clock.NewRealClock())
	defer sender.Close()
	defer receiver.Close()

	go func() {
		for i := 0; i < N; i++ {
			p := make([]byte, payloadLen)
			binary.BigEndian.PutUint32(p, uint32(i))
			if err := sender.Write(p); err != nil {
				return
			}
		}
	}()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2000)
		for i := 0; i < N; i++ {
			n, err := receiver.Read(buf)
			if err != nil {
				done <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			if n != payloadLen {
				done <- fmt.Errorf("read %d: got len %d want %d", i, n, payloadLen)
				return
			}
			if got := binary.BigEndian.Uint32(buf); got != uint32(i) {
				done <- fmt.Errorf("payload out of order at %d: got index %d", i, got)
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
		t.Fatal("timeout waiting for delivery")
	}
}

// TestSessionUDPLossRecovery drops several data packets on the sender's socket
// and confirms the receiver still gets every payload in order — proving
// NAK/retransmit recovery works end-to-end through the real driver (OS timer
// wheel + sockets), not just the deterministic core simulation.
func TestSessionUDPLossRecovery(t *testing.T) {
	const (
		N          = 600
		payloadLen = 1200
		sndID      = 1
		rcvID      = 2
		maxBW      = 125_000_000
	)

	rawS, rConn := mustUDP(t), mustUDP(t)
	// Drop these data sequence numbers once each (ISN is 100).
	sConn := &lossyConn{
		PacketConn: rawS,
		dropSeq:    map[uint32]bool{105: true, 106: true, 150: true, 333: true, 480: true, 599: true},
	}
	sMux, rMux := mux.New(sConn, 1500), mux.New(rConn, 1500)
	sRecv := sMux.Register(sndID)
	rRecv := rMux.Register(rcvID)

	receiver := session.NewEstablished(rMux, rRecv, true, rawS.LocalAddr(), core.Config{
		PeerSocketID: sndID, PayloadSize: payloadLen, SendISN: 9000, RecvISN: 100, MaxBW: maxBW,
	}, clock.NewRealClock())
	sender := session.NewEstablished(sMux, sRecv, true, rConn.LocalAddr(), core.Config{
		PeerSocketID: rcvID, PayloadSize: payloadLen, SendISN: 100, RecvISN: 9000, MaxBW: maxBW,
	}, clock.NewRealClock())
	defer sender.Close()
	defer receiver.Close()

	go func() {
		for i := 0; i < N; i++ {
			p := make([]byte, payloadLen)
			binary.BigEndian.PutUint32(p, uint32(i))
			if err := sender.Write(p); err != nil {
				return
			}
		}
	}()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2000)
		for i := 0; i < N; i++ {
			n, err := receiver.Read(buf)
			if err != nil {
				done <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			if n != payloadLen || binary.BigEndian.Uint32(buf) != uint32(i) {
				done <- fmt.Errorf("payload mismatch at %d", i)
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
		t.Fatal("timeout: loss not recovered")
	}
}
