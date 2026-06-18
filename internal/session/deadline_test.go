package session_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/session"
)

// TestSessionReadDeadlineNonBlocking checks net.Conn deadline and non-blocking
// (SRTO_RCVSYN) semantics on Read, using a peerless session (no data ever
// arrives, so Read would block forever without these).
func TestSessionReadDeadlineNonBlocking(t *testing.T) {
	uconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	m := mux.New(uconn, 1500)
	recvC := m.Register(1)
	s := session.NewEstablished(m, recvC, true, uconn.LocalAddr(),
		core.Config{PeerSocketID: 2, PayloadSize: 1200, SendISN: 100, RecvISN: 200, MaxBW: 1 << 30}, nil)
	defer s.Close()

	buf := make([]byte, 256)

	// Deadline already in the past -> immediate timeout.
	_ = s.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := s.Read(buf); !isTimeout(err) {
		t.Fatalf("past deadline: got %v, want a timeout", err)
	}

	// Deadline in the future, no data -> timeout at roughly the deadline.
	_ = s.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	start := time.Now()
	if _, err := s.Read(buf); !isTimeout(err) {
		t.Fatalf("future deadline: got %v, want a timeout", err)
	}
	if d := time.Since(start); d < 40*time.Millisecond {
		t.Errorf("Read returned after %v, expected to wait ~60ms for the deadline", d)
	}

	// Clear the deadline; non-blocking Read with no data -> ErrWouldBlock.
	_ = s.SetReadDeadline(time.Time{})
	s.SetReadBlocking(false)
	if _, err := s.Read(buf); !errors.Is(err, session.ErrWouldBlock) {
		t.Fatalf("non-blocking read: got %v, want ErrWouldBlock", err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
