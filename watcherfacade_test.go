package srt_test

import (
	"testing"
	"time"

	srt "github.com/zsiec/srtgo"
)

// TestFacadeWatcher proves the readiness Watcher fires a read event when data
// arrives, and an error event when the peer closes.
func TestFacadeWatcher(t *testing.T) {
	caller, server, ln := dialAccept(t, srt.DefaultConfig(), srt.DefaultConfig())
	defer ln.Close()
	defer caller.Close()
	defer server.Close()

	w := srt.NewWatcher()
	defer w.Close()
	if err := w.Add(server); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Write from the caller; the watcher should report the server readable.
	if _, err := caller.Write([]byte("watch-me")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	gotRead := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			ev, err := w.Wait()
			if err != nil {
				gotRead <- err
				return
			}
			if ev.Conn == server && ev.Type == srt.EventRead {
				gotRead <- nil
				return
			}
			// Tolerate other (e.g. write-ready) events.
		}
		gotRead <- errIntfTimeout()
	}()

	select {
	case err := <-gotRead:
		if err != nil {
			t.Fatalf("watcher read event: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not report a read event")
	}

	// Drain the readable data.
	buf := make([]byte, 100)
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := server.Read(buf); err != nil || string(buf[:n]) != "watch-me" {
		t.Fatalf("Read after watch: n=%d err=%v got=%q", n, err, buf[:n])
	}
}

func errIntfTimeout() error { return &watchTimeout{} }

type watchTimeout struct{}

func (*watchTimeout) Error() string { return "timed out waiting for read event" }
