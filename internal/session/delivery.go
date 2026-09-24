package session

import (
	"errors"
	"sync"

	"github.com/zsiec/srtgo/internal/core"
)

const (
	sessionReadQueueSize       = 32768
	sessionDeliveryBacklogSize = 65536
	sessionDeliveryByteLimit   = 128 << 20
)

// ErrReceiveOverflow indicates that a reliable receiver exhausted its bounded
// application queue. Previously queued messages remain readable before this
// error; the connection is closed instead of silently losing reliable data.
var ErrReceiveOverflow = errors.New("srt: application receive queue overflow")

// deliveryQueue is one FIFO for the ready tier and overflow backlog. Using a
// shared ring prevents newly delivered data from bypassing older backlog data.
// The ring grows lazily and releases payload references as entries leave it.
type deliveryQueue struct {
	mu                              sync.Mutex
	buf                             []delivery
	head, size, bytes               int
	readyLimit, capacity, byteLimit int
	changed                         chan struct{}
	err                             error
	dropped, dropBytes              uint64
}

func newDeliveryQueue(ready, backlog, bytes int) *deliveryQueue {
	return &deliveryQueue{readyLimit: ready, capacity: ready + backlog, byteLimit: bytes, changed: make(chan struct{}, 1)}
}

func (q *deliveryQueue) popLocked() delivery {
	d := q.buf[q.head]
	q.buf[q.head] = delivery{}
	q.head = (q.head + 1) % len(q.buf)
	q.size--
	q.bytes -= cap(d.data)
	return d
}

func (q *deliveryQueue) discard(d delivery) {
	q.dropped++
	q.dropBytes += uint64(len(d.data))
	core.PutPayload(d.data)
}

// push takes ownership in all cases. Live overload evicts the oldest data;
// reliable overload preserves the queued prefix and fails the connection.
func (q *deliveryQueue) push(d delivery, live bool) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		q.discard(d)
		return false
	}
	fits := func() bool { return q.size < q.capacity && cap(d.data) <= q.byteLimit-q.bytes }
	if !fits() && !live {
		q.err = ErrReceiveOverflow
		q.discard(d)
		return false
	}
	if cap(d.data) > q.byteLimit || q.capacity == 0 {
		q.discard(d)
		return true
	}
	for !fits() {
		q.discard(q.popLocked())
	}
	if q.size == len(q.buf) {
		n := min(q.capacity, max(64, len(q.buf)*2))
		buf := make([]delivery, n)
		for i := 0; i < q.size; i++ {
			buf[i] = q.buf[(q.head+i)%len(q.buf)]
		}
		q.buf = buf
		q.head = 0
	}
	q.buf[(q.head+q.size)%len(q.buf)] = d
	q.size++
	q.bytes += cap(d.data)
	signal(q.changed)
	return true
}

func (q *deliveryQueue) pop() (delivery, bool, <-chan struct{}) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.size == 0 {
		return delivery{}, false, q.changed
	}
	d := q.popLocked()
	if q.size > 0 {
		signal(q.changed)
	}
	return d, true, q.changed
}

func (q *deliveryQueue) readError() error { q.mu.Lock(); defer q.mu.Unlock(); return q.err }
func (q *deliveryQueue) ready() bool      { q.mu.Lock(); defer q.mu.Unlock(); return q.size > 0 }

func (q *deliveryQueue) stats(st core.Stats) core.Stats {
	q.mu.Lock()
	defer q.mu.Unlock()
	st.RecvDropped += q.dropped
	st.RecvDroppedBytes += q.dropBytes
	st.AppReadDropped = q.dropped
	st.AppReadDropBytes = q.dropBytes
	st.AppReadQueue = min(q.size, q.readyLimit)
	st.AppReadBacklog = max(0, q.size-q.readyLimit)
	return st
}
