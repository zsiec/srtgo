package core_test

import (
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/packet"
)

// newLivenessConn builds a connected core with dead-peer detection enabled and
// drains the construction effects.
func newLivenessConn(t *testing.T, base clock.Timestamp, idle clock.Microseconds) *core.Conn {
	t.Helper()
	c := core.NewEstablished(core.Config{
		PeerSocketID: 2, PayloadSize: 1200, SendISN: 100, RecvISN: 5000,
		MaxBW: 1 << 34, PeerIdleTimeout: idle,
	}, base)
	drainOutputs(c)
	return c
}

func failedEvent(c *core.Conn) (core.Failed, bool) {
	for {
		e, ok := c.PollEvent()
		if !ok {
			return core.Failed{}, false
		}
		if f, ok := e.(core.Failed); ok {
			return f, true
		}
	}
}

// TestPeerIdleTimeout proves a connection declares the peer dead (a Failed event
// carrying ErrPeerIdle) once no packet has arrived for the idle timeout, and
// does not fire early.
func TestPeerIdleTimeout(t *testing.T) {
	base := clock.Timestamp(1_000_000)
	const idle = 200 * clock.Millisecond
	c := newLivenessConn(t, base, idle)

	// Before the timeout, the idle check just re-arms — no failure.
	c.HandleTimer(base.Add(100*clock.Millisecond), core.TimerPeerIdle)
	if _, failed := failedEvent(c); failed {
		t.Fatal("peer declared dead before the idle timeout elapsed")
	}

	// Past the timeout with nothing received, the peer is declared dead.
	c.HandleTimer(base.Add(idle+10*clock.Millisecond), core.TimerPeerIdle)
	f, failed := failedEvent(c)
	if !failed {
		t.Fatal("expected a Failed event after the idle timeout")
	}
	if f.Err != core.ErrPeerIdle {
		t.Fatalf("Failed.Err = %v, want ErrPeerIdle", f.Err)
	}
}

// TestPeerIdleResetByPacket proves an arriving packet refreshes the liveness
// clock so the peer is not declared dead while it is still responding.
func TestPeerIdleResetByPacket(t *testing.T) {
	base := clock.Timestamp(1_000_000)
	const idle = 200 * clock.Millisecond
	c := newLivenessConn(t, base, idle)

	// A keepalive arrives at +150ms, refreshing liveness.
	ka := packet.NewControl(nil, packet.CtrlTypeKeepalive, 100, 0)
	ka.SetData([]byte{0, 0, 0, 0})
	c.HandlePacket(base.Add(150*clock.Millisecond), ka)
	drainOutputs(c)

	// At +250ms (>200ms since start, but only 100ms since the keepalive) the peer
	// is still alive.
	c.HandleTimer(base.Add(250*clock.Millisecond), core.TimerPeerIdle)
	if _, failed := failedEvent(c); failed {
		t.Fatal("peer declared dead despite a recent keepalive")
	}

	// 200ms after the keepalive, with nothing further, it is declared dead.
	c.HandleTimer(base.Add(360*clock.Millisecond), core.TimerPeerIdle)
	if _, failed := failedEvent(c); !failed {
		t.Fatal("expected the peer to be declared dead 200ms after the last packet")
	}
}

// TestIdleKeepalive proves an idle connection (nothing sent) emits a KEEPALIVE
// when the keepalive timer fires, and stays quiet right after sending data.
func TestIdleKeepalive(t *testing.T) {
	base := clock.Timestamp(1_000_000)
	c := newLivenessConn(t, base, 5*clock.Second)

	// Idle for the keepalive interval -> a KEEPALIVE goes out.
	c.HandleTimer(base.Add(1*clock.Second), core.TimerKeepalive)
	if !hasKeepalive(c) {
		t.Fatal("expected a KEEPALIVE after an idle keepalive interval")
	}

	// Send data, then fire the keepalive timer immediately: nothing to keep alive.
	c.Write(base.Add(1*clock.Second), []byte("data"))
	drainOutputs(c)
	c.HandleTimer(base.Add(1*clock.Second), core.TimerKeepalive)
	if hasKeepalive(c) {
		t.Fatal("sent a KEEPALIVE right after data was transmitted")
	}
}

// hasKeepalive reports whether a KEEPALIVE control packet is among the pending
// outputs, draining them (releasing owned packets).
func hasKeepalive(c *core.Conn) bool {
	found := false
	for {
		o, ok := c.PollOutput()
		if !ok {
			return found
		}
		if sp, ok := o.(core.SendPacket); ok {
			if sp.Packet.Header.IsControl && sp.Packet.Header.ControlType == packet.CtrlTypeKeepalive {
				found = true
			}
			if sp.Owned {
				sp.Packet.Release()
			}
		}
	}
}
