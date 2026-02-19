package srt

import (
	"errors"
	"sync"
)

// EventType identifies the kind of readiness event.
type EventType int

const (
	// EventRead indicates data is available for reading.
	EventRead EventType = iota
	// EventWrite indicates send buffer space is available.
	EventWrite
	// EventError indicates the connection has encountered an error or closed.
	EventError
)

// String returns a human-readable name for the event type.
func (e EventType) String() string {
	switch e {
	case EventRead:
		return "read"
	case EventWrite:
		return "write"
	case EventError:
		return "error"
	default:
		return "unknown"
	}
}

// Event represents a readiness notification from a watched connection.
type Event struct {
	// Conn is the connection that generated the event.
	Conn *Conn
	// Type indicates what kind of readiness triggered the event.
	Type EventType
	// Err is non-nil for EventError, describing why the connection failed.
	Err error
}

// WatchOpts configures per-connection options when adding to a Watcher.
type WatchOpts struct {
	// EdgeTriggered enables edge-triggered mode (like epoll EPOLLET).
	// When true, events fire only on state transitions (e.g., not-readable -> readable),
	// not while the condition persists. After an ET event is delivered, it will not
	// fire again until the condition clears and re-triggers.
	// Default: false (level-triggered, matching standard epoll behavior).
	EdgeTriggered bool
}

// Watcher monitors multiple SRT connections for readiness events.
// It provides an epoll-like interface for event-driven I/O multiplexing.
//
// Usage:
//
//	w := srt.NewWatcher()
//	defer w.Close()
//	w.Add(conn1)
//	w.Add(conn2)
//	for {
//	    event, err := w.Wait()
//	    if err != nil { break }
//	    switch event.Type {
//	    case srt.EventRead:
//	        event.Conn.Read(buf)
//	    case srt.EventError:
//	        event.Conn.Close()
//	    }
//	}
type Watcher struct {
	mu      sync.Mutex
	entries map[*Conn]*watchEntry
	eventCh chan Event
	done    chan struct{}
	closed  bool
}

type watchEntry struct {
	conn          *Conn
	cancel        chan struct{} // closed to stop per-conn goroutines
	edgeTriggered bool          // true = edge-triggered mode (ET)

	// Edge-triggered state: tracks last-notified event state per type.
	// Only accessed from the per-entry goroutines (one per event type),
	// so no synchronization is needed.
	lastReadState  bool // true = last notified as readable
	lastWriteState bool // true = last notified as writable
}

// NewWatcher creates a Watcher ready to monitor connections.
func NewWatcher() *Watcher {
	return &Watcher{
		entries: make(map[*Conn]*watchEntry),
		eventCh: make(chan Event, 64),
		done:    make(chan struct{}),
	}
}

// Add registers a connection with the Watcher using default options
// (level-triggered mode). Events for this connection will be delivered
// via Wait(). A connection may only be added to one Watcher.
func (w *Watcher) Add(conn *Conn) error {
	return w.AddWithOpts(conn, WatchOpts{})
}

// AddWithOpts registers a connection with the Watcher using the specified
// options. When opts.EdgeTriggered is true, events fire only on state
// transitions (not-ready -> ready), matching epoll EPOLLET semantics.
func (w *Watcher) AddWithOpts(conn *Conn, opts WatchOpts) error {
	if conn == nil {
		return errors.New("srt: nil connection")
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return errors.New("srt: watcher closed")
	}

	if _, exists := w.entries[conn]; exists {
		return errors.New("srt: connection already watched")
	}

	readCh, writeCh := conn.registerWatch()

	entry := &watchEntry{
		conn:          conn,
		cancel:        make(chan struct{}),
		edgeTriggered: opts.EdgeTriggered,
	}
	w.entries[conn] = entry

	// Spawn goroutines to fan-in per-conn signals to the shared event channel.
	go w.watchRead(entry, readCh)
	go w.watchWrite(entry, writeCh)
	go w.watchDone(entry)

	return nil
}

// Remove unregisters a connection. No further events will be delivered for it.
func (w *Watcher) Remove(conn *Conn) error {
	if conn == nil {
		return errors.New("srt: nil connection")
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	entry, exists := w.entries[conn]
	if !exists {
		return errors.New("srt: connection not watched")
	}

	close(entry.cancel)
	conn.unregisterWatch()
	delete(w.entries, conn)
	return nil
}

// Wait blocks until an event is available and returns it.
// Returns an error if the Watcher has been closed.
func (w *Watcher) Wait() (Event, error) {
	select {
	case ev, ok := <-w.eventCh:
		if !ok {
			return Event{}, errors.New("srt: watcher closed")
		}
		return ev, nil
	case <-w.done:
		return Event{}, errors.New("srt: watcher closed")
	}
}

// Close shuts down the Watcher and releases all resources.
// Any pending Wait() calls will return an error.
func (w *Watcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true
	close(w.done)

	for conn, entry := range w.entries {
		close(entry.cancel)
		conn.unregisterWatch()
	}
	w.entries = nil
	return nil
}

func (w *Watcher) watchRead(entry *watchEntry, readCh <-chan struct{}) {
	for {
		select {
		case <-readCh:
			if entry.edgeTriggered {
				// Edge-triggered: only emit when transitioning from not-ready to ready.
				if entry.lastReadState {
					// Already notified as readable — suppress until cleared.
					continue
				}
				entry.lastReadState = true
			}
			w.emit(Event{Conn: entry.conn, Type: EventRead})
		case <-entry.cancel:
			return
		case <-w.done:
			return
		}
	}
}

func (w *Watcher) watchWrite(entry *watchEntry, writeCh <-chan struct{}) {
	for {
		select {
		case <-writeCh:
			if entry.edgeTriggered {
				// Edge-triggered: only emit when transitioning from not-ready to ready.
				if entry.lastWriteState {
					// Already notified as writable — suppress until cleared.
					continue
				}
				entry.lastWriteState = true
			}
			w.emit(Event{Conn: entry.conn, Type: EventWrite})
		case <-entry.cancel:
			return
		case <-w.done:
			return
		}
	}
}

func (w *Watcher) watchDone(entry *watchEntry) {
	select {
	case <-entry.conn.done:
		err := entry.conn.getShutdownErr()
		if err == nil {
			err = errors.New("srt: connection closed")
		}
		w.emit(Event{Conn: entry.conn, Type: EventError, Err: err})
	case <-entry.cancel:
		return
	case <-w.done:
		return
	}
}

func (w *Watcher) emit(ev Event) {
	select {
	case w.eventCh <- ev:
	case <-w.done:
	}
}

// ClearEvent resets the edge-triggered state for the specified event type on
// the given connection. After calling ClearEvent, the next occurrence of the
// event will fire again in edge-triggered mode. This is a no-op for
// level-triggered connections.
//
// Typical usage: after processing a read event in ET mode, call
// ClearEvent(conn, EventRead) to re-arm the trigger.
func (w *Watcher) ClearEvent(conn *Conn, eventType EventType) {
	w.mu.Lock()
	entry, exists := w.entries[conn]
	w.mu.Unlock()

	if !exists || !entry.edgeTriggered {
		return
	}

	switch eventType {
	case EventRead:
		entry.lastReadState = false
	case EventWrite:
		entry.lastWriteState = false
	}
}
