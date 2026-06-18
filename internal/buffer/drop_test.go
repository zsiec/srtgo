package buffer

import (
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
)

// TestSendBufferDropTooLateSendThreshold drops the contiguous run of head
// packets older than the threshold and stops at the first one still within it.
func TestSendBufferDropTooLateSendThreshold(t *testing.T) {
	sb := NewSendBuffer(64, seq.Number(100))

	// Push 5 packets at staggered send times: 100..102 are old, 103..104 recent.
	sendAt := []clock.Timestamp{1000, 1100, 1200, 5000, 5100}
	for i, at := range sendAt {
		p := packet.NewData(nil, uint32(100+i), 0, 0, []byte("payload"))
		if !sb.Push(p, at) {
			t.Fatalf("Push(%d) failed", 100+i)
		}
	}

	// now=3000, thresh=1000us: packets sent at/before 2000 (100,101,102) are too
	// late; 103 (sent 5000) is in the future relative to now and survives.
	dropped, first, last := sb.DropTooLateSend(3000, 1000)
	if dropped != 3 {
		t.Fatalf("dropped %d, want 3", dropped)
	}
	if first != seq.Number(100) || last != seq.Number(102) {
		t.Fatalf("dropped range [%d,%d], want [100,102]", first, last)
	}
	if sb.Size() != 2 {
		t.Fatalf("Size after drop = %d, want 2", sb.Size())
	}
	if sb.StartSeq() != seq.Number(103) {
		t.Fatalf("StartSeq after drop = %d, want 103", sb.StartSeq())
	}

	// Nothing else is past the threshold yet.
	if d, _, _ := sb.DropTooLateSend(3000, 1000); d != 0 {
		t.Fatalf("second drop removed %d, want 0", d)
	}
}

// TestSendBufferDropTooLateSendTTL drops a head packet once its per-message TTL
// expires even when the age-based threshold is disabled (thresh==0), and leaves
// a younger TTL'd packet alone.
func TestSendBufferDropTooLateSendTTL(t *testing.T) {
	sb := NewSendBuffer(64, seq.Number(0))

	p0 := packet.NewData(nil, 0, 0, 0, []byte("a"))
	sb.Push(p0, 1000)
	sb.SetMsgTTL(50 * 1000 * 1000) // 50ms in nanoseconds
	p1 := packet.NewData(nil, 1, 0, 0, []byte("b"))
	sb.Push(p1, 1000)
	sb.SetMsgTTL(50 * 1000 * 1000)

	// thresh=0 disables age-based drop. At now=1000+60ms the first packet's TTL
	// (50ms) has expired; once it goes, the second is also 60ms old and expires.
	now := clock.Timestamp(1000).Add(60 * clock.Millisecond)
	dropped, first, last := sb.DropTooLateSend(now, 0)
	if dropped != 2 {
		t.Fatalf("TTL drop removed %d, want 2", dropped)
	}
	if first != seq.Number(0) || last != seq.Number(1) {
		t.Fatalf("TTL dropped range [%d,%d], want [0,1]", first, last)
	}

	// A fresh TTL'd packet within its TTL is not dropped.
	p2 := packet.NewData(nil, 2, 0, 0, []byte("c"))
	sb.Push(p2, now)
	sb.SetMsgTTL(50 * 1000 * 1000)
	if d, _, _ := sb.DropTooLateSend(now.Add(10*clock.Millisecond), 0); d != 0 {
		t.Fatalf("dropped a packet still within its TTL: %d", d)
	}
}
