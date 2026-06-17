// Package session is the I/O host for the Sans-I/O SRT core. It owns the UDP
// multiplexer, the real clock, the timer wheel, and exactly one event-loop
// goroutine that drives a pure core.Conn.
//
// The loop is the only goroutine that touches the core. It reads the real
// clock once per wake-up, feeds the core (HandlePacket / HandleTimer / Write),
// then drains the core's effects (send datagrams, arm/clear timers) and events
// (delivered payloads, close). This mirrors ristgo's internal/session and
// srtrust's driver. Per connection there are two goroutines — the mux read
// loop and this event loop — versus three in the legacy design.
package session

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/packet"
)

// ErrClosed is returned by Read/Write after the session is closed.
var ErrClosed = errors.New("session: closed")

// Session drives one established core.Conn over a mux. Construct it with
// NewEstablished; Write/Read/Close are safe to call from other goroutines.
type Session struct {
	mux        *mux.Mux
	ownsMux    bool
	remoteAddr net.Addr
	clk        clock.Clock
	core       *core.Conn

	recvC  <-chan packet.Packet
	writeC chan []byte
	readC  chan []byte

	quit     chan struct{} // closed by Close to ask the loop to stop
	loopDone chan struct{} // closed by the loop on exit

	timers    map[core.TimerID]clock.Timestamp
	closeOnce sync.Once
}

// NewEstablished builds a session for an already-connected core (handshake is
// out of scope for this phase) and starts its event loop.
//
//   - m / recvC: the multiplexer and this connection's inbound packet channel.
//   - ownsMux: if true, Close also closes the mux (client owns its socket).
//   - remoteAddr: where outgoing packets are written.
//   - cfg: the negotiated connection parameters.
//   - clk: the clock (RealClock in production, MockClock in tests).
func NewEstablished(m *mux.Mux, recvC <-chan packet.Packet, ownsMux bool, remoteAddr net.Addr, cfg core.Config, clk clock.Clock) *Session {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	s := &Session{
		mux:        m,
		ownsMux:    ownsMux,
		remoteAddr: remoteAddr,
		clk:        clk,
		core:       core.NewEstablished(cfg, clk.Now()),
		recvC:      recvC,
		writeC:     make(chan []byte, 256),
		readC:      make(chan []byte, 2048),
		quit:       make(chan struct{}),
		loopDone:   make(chan struct{}),
		timers:     make(map[core.TimerID]clock.Timestamp),
	}
	go s.loop()
	return s
}

// Write queues a payload for transmission. It blocks if the internal queue is
// full (natural backpressure) and returns ErrClosed once the session is closed.
func (s *Session) Write(p []byte) error {
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case s.writeC <- cp:
		return nil
	case <-s.loopDone:
		return ErrClosed
	}
}

// Read returns the next delivered payload, copied into b, blocking until data
// is available. It returns io.EOF once the session is closed and drained.
func (s *Session) Read(b []byte) (int, error) {
	select {
	case data := <-s.readC:
		return copy(b, data), nil
	case <-s.loopDone:
		// Drain anything already delivered before the loop exited.
		select {
		case data := <-s.readC:
			return copy(b, data), nil
		default:
			return 0, io.EOF
		}
	}
}

// Close stops the event loop and, if the session owns the mux, closes it.
func (s *Session) Close() error {
	s.closeOnce.Do(func() { close(s.quit) })
	<-s.loopDone
	if s.ownsMux {
		return s.mux.Close()
	}
	return nil
}

// RemoteAddr returns the peer address.
func (s *Session) RemoteAddr() net.Addr { return s.remoteAddr }

// LocalAddr returns the local socket address.
func (s *Session) LocalAddr() net.Addr { return s.mux.LocalAddr() }

// ---- event loop ----

func (s *Session) loop() {
	defer close(s.loopDone)

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	var backlog [][]byte

	// Drain the effects the constructor queued (initial ACK/NAK timers).
	backlog = s.drain(s.clk.Now(), timer, backlog)

	for {
		backlog = s.flushBacklog(backlog)

		select {
		case <-s.quit:
			return

		case p, ok := <-s.recvC:
			if !ok {
				return
			}
			now := s.clk.Now()
			s.core.HandlePacket(now, p)
			backlog = s.drain(now, timer, backlog)

		case payload := <-s.writeC:
			now := s.clk.Now()
			s.core.Write(now, payload)
			backlog = s.drain(now, timer, backlog)

		case <-timer.C:
			now := s.clk.Now()
			s.fireTimers(now)
			backlog = s.drain(now, timer, backlog)
		}
	}
}

// fireTimers delivers every timer whose deadline has passed to the core. The
// re-arm a fired timer requests arrives as a SetTimer effect drained afterward.
func (s *Session) fireTimers(now clock.Timestamp) {
	for id, deadline := range s.timers {
		if !deadline.After(now) {
			delete(s.timers, id)
			s.core.HandleTimer(now, id)
		}
	}
}

// drain executes all pending core effects and queues delivered payloads, then
// re-arms the OS timer to the earliest pending deadline.
func (s *Session) drain(now clock.Timestamp, timer *time.Timer, backlog [][]byte) [][]byte {
	for {
		out, ok := s.core.PollOutput()
		if !ok {
			break
		}
		switch v := out.(type) {
		case core.SendPacket:
			v.Packet.Header.Addr = s.remoteAddr
			_ = s.mux.Send(v.Packet)
			if v.Owned {
				v.Packet.Release()
			}
		case core.SetTimer:
			s.timers[v.ID] = v.Deadline
		case core.ClearTimer:
			delete(s.timers, v.ID)
		}
	}
	for {
		ev, ok := s.core.PollEvent()
		if !ok {
			break
		}
		switch e := ev.(type) {
		case core.DataReceived:
			select {
			case s.readC <- e.Data:
			default:
				backlog = append(backlog, e.Data)
			}
		case core.Closed, core.Failed:
			// Connection ended; the loop will exit on the next quit or EOF.
		}
	}
	s.rearm(timer, now)
	return backlog
}

// flushBacklog pushes as many backlogged deliveries into readC as fit without
// blocking, so a slow Reader never stalls the protocol loop.
func (s *Session) flushBacklog(backlog [][]byte) [][]byte {
	i := 0
	for i < len(backlog) {
		select {
		case s.readC <- backlog[i]:
			i++
		default:
			return backlog[i:]
		}
	}
	return backlog[:0]
}

// rearm resets the OS timer to fire at the soonest pending core deadline.
func (s *Session) rearm(timer *time.Timer, now clock.Timestamp) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	earliest, ok := s.earliest()
	if !ok {
		return // no timers armed
	}
	d := earliest.Sub(now)
	if d < 0 {
		d = 0
	}
	timer.Reset(d.Duration())
}

func (s *Session) earliest() (clock.Timestamp, bool) {
	var best clock.Timestamp
	have := false
	for _, deadline := range s.timers {
		if !have || deadline.Before(best) {
			best, have = deadline, true
		}
	}
	return best, have
}
