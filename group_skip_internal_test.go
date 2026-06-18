package srt

import (
	"encoding/binary"
	"testing"
	"time"
)

// TestBalancingReorderSkip is a white-box test of the balancing reorder buffer's
// gap handling: it feeds the group's receive channel a sequence with a permanent
// hole (message 3 never arrives, as if its link died) and verifies the reader
// delivers in order and then skips the missing message within the bounded window
// rather than stalling forever.
func TestBalancingReorderSkip(t *testing.T) {
	g := NewGroup(GroupBalancing)
	defer g.Close()

	// msgNo 3 is omitted — the link that owned it is presumed dead.
	feed := []uint32{1, 2, 4, 5, 6}
	go func() {
		for _, m := range feed {
			data := make([]byte, 4)
			binary.BigEndian.PutUint32(data, m)
			select {
			case g.recvCh <- recvResult{n: 4, msgNo: m, data: data}:
			case <-g.done:
				return
			}
		}
	}()

	buf := make([]byte, 64)
	var got []uint32
	deadline := time.Now().Add(5 * time.Second)
	for len(got) < len(feed) {
		if time.Now().After(deadline) {
			t.Fatalf("reader stalled at %v (want it to skip the missing msg 3)", got)
		}
		n, err := g.readBalancing(buf)
		if err != nil {
			t.Fatalf("readBalancing: %v", err)
		}
		got = append(got, binary.BigEndian.Uint32(buf[:n]))
	}

	want := []uint32{1, 2, 4, 5, 6}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delivery order = %v, want %v (in-order then skip the gap)", got, want)
		}
	}
}
