package core

// fifo is a simple single-consumer FIFO queue used for the core's output,
// event, and pending-send channels. The host drains it via the matching Poll
// method until empty. It is not safe for concurrent use: the host serializes
// all access to a Conn.
//
// It amortizes allocation by reusing the backing array — when the queue drains
// empty, head resets to 0 and the slice is truncated to length 0 (keeping
// capacity), so steady-state pushes hit the existing array.
type fifo[T any] struct {
	items []T
	head  int
}

// push appends v to the back of the queue.
func (q *fifo[T]) push(v T) {
	q.items = append(q.items, v)
}

// pop removes and returns the front element. ok is false when the queue is
// empty, at which point the backing array is reset for reuse.
func (q *fifo[T]) pop() (v T, ok bool) {
	if q.head >= len(q.items) {
		q.reset()
		return v, false
	}
	v = q.items[q.head]
	var zero T
	q.items[q.head] = zero // drop reference so GC can reclaim
	q.head++
	if q.head >= len(q.items) {
		q.reset()
	}
	return v, true
}

// len reports the number of elements still queued.
func (q *fifo[T]) len() int { return len(q.items) - q.head }

func (q *fifo[T]) reset() {
	q.items = q.items[:0]
	q.head = 0
}
