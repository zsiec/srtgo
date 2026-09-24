package session

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/core"
)

func TestDeliveryQueueFIFO(t *testing.T) {
	q := newDeliveryQueue(2, 2, 100)
	for i := byte(0); i < 4; i++ {
		q.push(delivery{data: []byte{i}}, true)
	}
	d, _, _ := q.pop()
	if d.data[0] != 0 {
		t.Fatal("wrong head")
	}
	// A ready slot opens while older backlog still exists.
	q.push(delivery{data: []byte{4}}, true)
	for i := byte(1); i <= 4; i++ {
		d, ok, _ := q.pop()
		if !ok || d.data[0] != i {
			t.Fatalf("got %v want %d", d.data, i)
		}
	}
	for _, d := range q.buf {
		if d.data != nil {
			t.Fatal("popped payload retained")
		}
	}
	if q.bytes != 0 {
		t.Fatal("queued bytes not released")
	}
}

func TestDeliveryQueueLiveLimitsAndCounters(t *testing.T) {
	q := newDeliveryQueue(2, 2, 10)
	for _, v := range []string{"aa", "bbb", "cccc", "d", "e"} {
		q.push(delivery{data: []byte(v)[:len(v):len(v)]}, true)
	}
	st := q.stats(core.Stats{RecvDropped: 7, RecvDroppedBytes: 99})
	if st.AppReadDropped != 1 || st.AppReadDropBytes != 2 || st.RecvDropped != 8 || st.RecvDroppedBytes != 101 || st.AppReadQueue != 2 || st.AppReadBacklog != 2 {
		t.Fatalf("drop stats: %+v", st)
	}
	// Byte pressure can require multiple evictions even before the message limit.
	q.push(delivery{data: []byte("12345678")[:8:8]}, true)
	st = q.stats(core.Stats{})
	if st.AppReadDropped != 3 || st.AppReadDropBytes != 9 {
		t.Fatalf("byte drops: %+v", st)
	}
	for _, want := range []string{"d", "e", "12345678"} {
		d, ok, _ := q.pop()
		if !ok || string(d.data) != want {
			t.Fatalf("got %q want %q", d.data, want)
		}
	}
}

func TestDeliveryQueueDefaultBound(t *testing.T) {
	q := newDeliveryQueue(sessionReadQueueSize, sessionDeliveryBacklogSize, sessionDeliveryByteLimit)
	for i := 0; i < sessionReadQueueSize+sessionDeliveryBacklogSize+10; i++ {
		q.push(delivery{data: []byte{byte(i)}}, true)
	}
	st := q.stats(core.Stats{})
	if st.AppReadDropped != 10 || st.AppReadQueue != 32768 || st.AppReadBacklog != 65536 {
		t.Fatalf("default limits: %+v", st)
	}
}

func TestDeliveryQueueBoundsRetainedCapacity(t *testing.T) {
	q := newDeliveryQueue(2, 2, 10)
	b := make([]byte, 1, 11)
	q.push(delivery{data: b}, true)
	if q.ready() || q.stats(core.Stats{}).AppReadDropBytes != 1 {
		t.Fatal("retained oversized backing array")
	}
}

func readTestSession(q *deliveryQueue) *Session {
	s := &Session{deliveries: q, loopDone: make(chan struct{})}
	s.rcvSyn.Store(true)
	return s
}

func TestDeliveryReliableOverflowAndCloseDrain(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		q := newDeliveryQueue(1, 2, 100)
		s := readTestSession(q)
		for _, v := range []string{"a", "b", "c"} {
			if !q.push(delivery{data: []byte(v)[:len(v):len(v)]}, false) {
				t.Fatal("early overflow")
			}
		}
		if overflow && q.push(delivery{data: []byte("d")}, false) {
			t.Fatal("reliable overflow succeeded")
		}
		close(s.loopDone)
		buf := make([]byte, 10)
		for _, want := range []string{"a", "b", "c"} {
			n, err := s.Read(buf)
			if err != nil || string(buf[:n]) != want {
				t.Fatalf("drain=%q,%v", buf[:n], err)
			}
		}
		want := io.EOF
		if overflow {
			want = ErrReceiveOverflow
		}
		if _, err := s.Read(buf); !errors.Is(err, want) {
			t.Fatalf("terminal error=%v want %v", err, want)
		}
	}
}

func TestDeliveryReaderNotifications(t *testing.T) {
	s := readTestSession(newDeliveryQueue(1, 8, 100))
	s.SetReadDeadline(time.Now().Add(3 * time.Second))
	var wg sync.WaitGroup
	results := make(chan byte, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := make([]byte, 1)
			n, err := s.Read(b)
			if err != nil || n != 1 {
				t.Errorf("read=%d,%v", n, err)
				return
			}
			results <- b[0]
		}()
	}
	for i := byte(0); i < 8; i++ {
		s.deliveries.push(delivery{data: []byte{i}}, false)
	}
	wg.Wait()
	close(results)
	seen := map[byte]bool{}
	for v := range results {
		if seen[v] {
			t.Fatalf("duplicate %d", v)
		}
		seen[v] = true
	}
	if len(seen) != 8 {
		t.Fatal("missed a reader notification")
	}
}
