package srt

import (
	"net"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/seq"
)

// newTestConn creates a minimal Conn suitable for Watcher testing.
func newTestConn(t *testing.T) *Conn {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	m := mux.New(udpConn, 1500)

	clk := clock.NewRealClock()
	isn := seq.Number(1)
	recvCh := m.Register(1)

	conn := newConn(ConnConfig{
		SocketID:        1,
		PeerSocketID:    2,
		IsServer:        true,
		Mux:             m,
		OwnsMux:         true,
		RecvChan:        recvCh,
		Clock:           clk,
		SendISN:         isn,
		RecvISN:         isn,
		SendBufSize:     1024,
		RecvBufSize:     1024,
		FC:              1024,
		PayloadSize:     1316,
		PeerIdleTimeout: 5 * time.Second,
		Linger:          1 * time.Second,
	})
	return conn
}

func TestWatcherAddRemove(t *testing.T) {
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)
	defer c.Close()

	if err := w.Add(c); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Double add should fail
	if err := w.Add(c); err == nil {
		t.Error("expected error on double add")
	}

	if err := w.Remove(c); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// Double remove should fail
	if err := w.Remove(c); err == nil {
		t.Error("expected error on double remove")
	}
}

func TestWatcherNilConn(t *testing.T) {
	w := NewWatcher()
	defer w.Close()

	if err := w.Add(nil); err == nil {
		t.Error("expected error for nil conn Add")
	}
	if err := w.Remove(nil); err == nil {
		t.Error("expected error for nil conn Remove")
	}
}

func TestWatcherReadEvent(t *testing.T) {
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)
	defer c.Close()

	if err := w.Add(c); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Signal read readiness
	c.signalReadReady()

	// Wait should return a read event
	done := make(chan Event, 1)
	go func() {
		ev, err := w.Wait()
		if err != nil {
			t.Errorf("Wait: %v", err)
			return
		}
		done <- ev
	}()

	select {
	case ev := <-done:
		if ev.Type != EventRead {
			t.Errorf("got event type %v, want EventRead", ev.Type)
		}
		if ev.Conn != c {
			t.Error("event conn mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for read event")
	}
}

func TestWatcherWriteEvent(t *testing.T) {
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)
	defer c.Close()

	if err := w.Add(c); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Signal write readiness
	c.signalWriteReady()

	done := make(chan Event, 1)
	go func() {
		ev, err := w.Wait()
		if err != nil {
			t.Errorf("Wait: %v", err)
			return
		}
		done <- ev
	}()

	select {
	case ev := <-done:
		if ev.Type != EventWrite {
			t.Errorf("got event type %v, want EventWrite", ev.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for write event")
	}
}

func TestWatcherErrorEvent(t *testing.T) {
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)

	if err := w.Add(c); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Close the connection — should trigger error event
	c.Close()

	done := make(chan Event, 1)
	go func() {
		ev, err := w.Wait()
		if err != nil {
			t.Errorf("Wait: %v", err)
			return
		}
		done <- ev
	}()

	select {
	case ev := <-done:
		if ev.Type != EventError {
			t.Errorf("got event type %v, want EventError", ev.Type)
		}
		if ev.Err == nil {
			t.Error("expected non-nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for error event")
	}
}

func TestWatcherClose(t *testing.T) {
	w := NewWatcher()

	c := newTestConn(t)
	defer c.Close()

	if err := w.Add(c); err != nil {
		t.Fatalf("Add: %v", err)
	}

	w.Close()

	// Wait after close should return error
	_, err := w.Wait()
	if err == nil {
		t.Error("expected error from Wait after Close")
	}

	// Add after close should return error
	if err := w.Add(c); err == nil {
		t.Error("expected error from Add after Close")
	}

	// Double close should not panic
	w.Close()
}

func TestWatcherRemoveStopsEvents(t *testing.T) {
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)
	defer c.Close()

	if err := w.Add(c); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := w.Remove(c); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// Signal after remove — should NOT generate an event since
	// watchReadReady was set to nil by unregisterWatch
	c.signalReadReady()

	// Brief sleep to check no event arrives
	select {
	case ev := <-w.eventCh:
		t.Errorf("unexpected event after remove: %v", ev)
	case <-time.After(100 * time.Millisecond):
		// Good — no event
	}
}

func TestWatcherDoesNotStealSignals(t *testing.T) {
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)
	defer c.Close()

	if err := w.Add(c); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Signal read readiness
	c.signalReadReady()

	// Both the watcher and the conn's readReady should be signaled
	select {
	case <-c.readReady:
		// Good — Conn.Read() would still work
	case <-time.After(time.Second):
		t.Fatal("readReady channel not signaled — watcher stole the signal")
	}
}

func TestWatcherMultipleConns(t *testing.T) {
	w := NewWatcher()
	defer w.Close()

	c1 := newTestConn(t)
	defer c1.Close()
	c2 := newTestConn(t)
	defer c2.Close()

	if err := w.Add(c1); err != nil {
		t.Fatalf("Add c1: %v", err)
	}
	if err := w.Add(c2); err != nil {
		t.Fatalf("Add c2: %v", err)
	}

	// Signal both
	c1.signalReadReady()
	c2.signalReadReady()

	// Should receive events from both
	seen := make(map[*Conn]bool)
	for i := 0; i < 2; i++ {
		select {
		case ev := <-w.eventCh:
			seen[ev.Conn] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for event %d", i+1)
		}
	}

	if !seen[c1] || !seen[c2] {
		t.Error("did not receive events from both connections")
	}
}

func TestEventTypeString(t *testing.T) {
	tests := []struct {
		et   EventType
		want string
	}{
		{EventRead, "read"},
		{EventWrite, "write"},
		{EventError, "error"},
		{EventType(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.et.String(); got != tt.want {
			t.Errorf("EventType(%d).String() = %q, want %q", int(tt.et), got, tt.want)
		}
	}
}
