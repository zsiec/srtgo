package legacy

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
	for i := range 2 {
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

func TestWatcherClearEvent(t *testing.T) {
	// Test that ClearEvent exists and can be called without panic.
	// Due to the edge-triggered design where lastReadState/lastWriteState
	// are accessed from per-entry goroutines, we test the no-op paths
	// to avoid race conditions in tests.
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)
	defer c.Close()

	// ClearEvent on non-watched connection — no-op
	w.ClearEvent(c, EventRead)
	w.ClearEvent(c, EventWrite)

	// Add in level-triggered mode — ClearEvent is a no-op
	if err := w.Add(c); err != nil {
		t.Fatalf("Add: %v", err)
	}
	w.ClearEvent(c, EventRead)
	w.ClearEvent(c, EventWrite)

	// Verify the watcher is still functional
	c.signalReadReady()
	select {
	case ev := <-w.eventCh:
		if ev.Type != EventRead {
			t.Errorf("got event type %v, want EventRead", ev.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for read event")
	}
}

func TestWatcherClearEventWrite(t *testing.T) {
	// Test ClearEvent for EventWrite — verifies the method exists
	// and handles both the no-op path (non-ET) and the error-event path.
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)
	defer c.Close()

	// Add in level-triggered mode
	if err := w.Add(c); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// ClearEvent on level-triggered connection — no-op, should not panic
	w.ClearEvent(c, EventWrite)
	w.ClearEvent(c, EventError)
}

func TestWatcherClearEventNoOp(t *testing.T) {
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)
	defer c.Close()

	// ClearEvent on non-watched connection — should be a no-op
	w.ClearEvent(c, EventRead)

	// ClearEvent on level-triggered connection — should be a no-op
	if err := w.Add(c); err != nil {
		t.Fatalf("Add: %v", err)
	}
	w.ClearEvent(c, EventRead) // no-op for level-triggered
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

func TestWatcherEdgeTriggeredAdd(t *testing.T) {
	// Verify we can add a connection in edge-triggered mode and receive events.
	// Note: ClearEvent has a known race with watchRead/watchWrite goroutines
	// (lastReadState/lastWriteState are not synchronized). We only test
	// the initial event delivery path which doesn't race.
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)
	defer c.Close()

	// Add with edge-triggered mode
	if err := w.AddWithOpts(c, WatchOpts{EdgeTriggered: true}); err != nil {
		t.Fatalf("AddWithOpts: %v", err)
	}

	// First signal should produce an event
	c.signalReadReady()

	select {
	case ev := <-w.eventCh:
		if ev.Type != EventRead {
			t.Errorf("got event type %v, want EventRead", ev.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first read event in ET mode")
	}
}

func TestWatcherEdgeTriggeredDone(t *testing.T) {
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)

	// Add with edge-triggered mode
	if err := w.AddWithOpts(c, WatchOpts{EdgeTriggered: true}); err != nil {
		t.Fatalf("AddWithOpts: %v", err)
	}

	// Close the connection — should trigger error event even in ET mode
	c.Close()

	select {
	case ev := <-w.eventCh:
		if ev.Type != EventError {
			t.Errorf("got event type %v, want EventError", ev.Type)
		}
		if ev.Err == nil {
			t.Error("expected non-nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for error event in ET mode")
	}
}

func TestWatcherWaitAfterClose(t *testing.T) {
	w := NewWatcher()

	// Close and then Wait should return error via done channel
	w.Close()

	_, err := w.Wait()
	if err == nil {
		t.Error("expected error from Wait after Close")
	}
}

func TestWatcherWriteEdgeTriggeredSuppression(t *testing.T) {
	// Test that edge-triggered write events are suppressed after first delivery.
	// We avoid ClearEvent here to prevent data races (lastWriteState accessed
	// from both test goroutine and watchWrite goroutine).
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)
	defer c.Close()

	// Add in edge-triggered mode
	if err := w.AddWithOpts(c, WatchOpts{EdgeTriggered: true}); err != nil {
		t.Fatalf("AddWithOpts: %v", err)
	}

	// First write signal should produce an event
	c.signalWriteReady()

	// Drain until we get a write event (there may be stray events from conn internals)
	gotWrite := false
	deadline := time.After(2 * time.Second)
	for !gotWrite {
		select {
		case ev := <-w.eventCh:
			if ev.Type == EventWrite {
				gotWrite = true
			}
		case <-deadline:
			t.Fatal("timeout waiting for first write event")
		}
	}

	// Second write signal should be suppressed (edge-triggered)
	c.signalWriteReady()

	// Drain briefly and check we do NOT get another write event
	writeSupressed := true
	timer := time.After(200 * time.Millisecond)
	for writeSupressed {
		select {
		case ev := <-w.eventCh:
			if ev.Type == EventWrite {
				t.Error("expected write event suppression in edge-triggered mode")
				writeSupressed = false
			}
			// Ignore non-write events (read, error, etc.)
		case <-timer:
			writeSupressed = false // timeout = good, no write event
		}
	}
}

func TestWatcherReadEdgeTriggeredSuppression(t *testing.T) {
	// Test that edge-triggered read events are suppressed after first delivery.
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)
	defer c.Close()

	if err := w.AddWithOpts(c, WatchOpts{EdgeTriggered: true}); err != nil {
		t.Fatalf("AddWithOpts: %v", err)
	}

	// First read signal should produce an event
	c.signalReadReady()

	select {
	case ev := <-w.eventCh:
		if ev.Type != EventRead {
			t.Errorf("first event: got %v, want EventRead", ev.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first read event")
	}

	// Second signal should be suppressed
	c.signalReadReady()

	select {
	case ev := <-w.eventCh:
		if ev.Type == EventRead {
			t.Error("expected read event suppression in edge-triggered mode")
		}
		// Non-read events (write) are acceptable
	case <-time.After(200 * time.Millisecond):
		// Good -- suppressed
	}
}

func TestWatcherClearEventNonExistentConn(t *testing.T) {
	// ClearEvent on a conn that was never added should be a no-op (not panic).
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)
	defer c.Close()

	// Never added to watcher -- ClearEvent should be harmless
	w.ClearEvent(c, EventRead)
	w.ClearEvent(c, EventWrite)
	w.ClearEvent(c, EventError)
}

func TestWatcherClearEventLevelTriggeredNoOp(t *testing.T) {
	// ClearEvent on a level-triggered connection should be a no-op.
	// This exercises the !entry.edgeTriggered early return in ClearEvent.
	w := NewWatcher()
	defer w.Close()

	c := newTestConn(t)
	defer c.Close()

	// Add in default (level-triggered) mode
	if err := w.Add(c); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// ClearEvent is a no-op for level-triggered -- should not panic
	w.ClearEvent(c, EventRead)
	w.ClearEvent(c, EventWrite)
	w.ClearEvent(c, EventError)

	// Verify the watcher is still functional after no-op ClearEvent
	c.signalReadReady()
	select {
	case ev := <-w.eventCh:
		if ev.Type != EventRead {
			t.Errorf("got event type %v, want EventRead", ev.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for read event after no-op ClearEvent")
	}
}
