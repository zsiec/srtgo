// Package buffer provides ring-buffer-based send and receive buffers for SRT.
//
// Both buffers use power-of-2 sizing with bitmask indexing for O(1) access
// by sequence number. This replaces the container/list approach used in
// datarhei/gosrt which requires O(n) scans for ACK and NAK processing.
package buffer

import (
	"sync"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
)

// sendEntry holds a packet in the send buffer.
type sendEntry struct {
	pkt        packet.Packet
	used       bool            // whether this slot contains a valid packet
	sentAt     clock.Timestamp // when the packet was pushed
	rexmitTime clock.Timestamp // last retransmission time (zero = never retransmitted)
	msgTTL     int64           // per-message TTL in nanoseconds (0 = none, from MsgCtrl)
}

// SendBuffer is a ring buffer for sent packets awaiting ACK.
// It supports O(1) insertion, ACK processing (advancing the base pointer),
// and NAK-based retransmission lookup.
type SendBuffer struct {
	mu       sync.Mutex
	entries  []sendEntry
	mask     int        // capacity - 1 for fast modulo
	startSeq seq.Number // sequence number at entries[0]
	nextSeq  seq.Number // next sequence number to be inserted
	size     int        // number of used entries (unacked packets)
}

// NewSendBuffer creates a send buffer with the given capacity (rounded up to
// next power of 2) starting at the given initial sequence number.
func NewSendBuffer(capacity int, initialSeq seq.Number) *SendBuffer {
	cap2 := nextPow2(capacity)
	return &SendBuffer{
		entries:  make([]sendEntry, cap2),
		mask:     cap2 - 1,
		startSeq: initialSeq,
		nextSeq:  initialSeq,
	}
}

// Push adds a packet to the send buffer. Returns false if the buffer is full.
func (sb *SendBuffer) Push(p packet.Packet, sentAt ...clock.Timestamp) bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.size >= len(sb.entries) {
		return false
	}

	var ts clock.Timestamp
	if len(sentAt) > 0 {
		ts = sentAt[0]
	}

	idx := int(uint32(sb.nextSeq)) & sb.mask
	sb.entries[idx] = sendEntry{pkt: p, used: true, sentAt: ts}
	sb.nextSeq = sb.nextSeq.Inc()
	sb.size++

	return true
}

// PushBatch atomically adds multiple packets to the send buffer.
// Returns false if the buffer doesn't have enough space for all packets.
// All fragments of a multi-packet message are added under a single lock.
func (sb *SendBuffer) PushBatch(pkts []packet.Packet, sentAt clock.Timestamp) bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.size+len(pkts) > len(sb.entries) {
		return false
	}

	for _, p := range pkts {
		idx := int(uint32(sb.nextSeq)) & sb.mask
		sb.entries[idx] = sendEntry{pkt: p, used: true, sentAt: sentAt}
		sb.nextSeq = sb.nextSeq.Inc()
		sb.size++
	}
	return true
}

// ACK acknowledges all packets up to (but not including) ackSeq.
// Returns the number of newly acknowledged packets.
// Released packets have their buffers returned to the pool.
func (sb *SendBuffer) ACK(ackSeq seq.Number) int {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	count := 0
	for sb.startSeq.LessThan(ackSeq) && sb.size > 0 {
		idx := int(uint32(sb.startSeq)) & sb.mask
		if sb.entries[idx].used {
			sb.entries[idx].pkt.Release()
			sb.entries[idx] = sendEntry{}
			count++
			sb.size--
		}
		sb.startSeq = sb.startSeq.Inc()
	}

	return count
}

// NAK retrieves packets for retransmission based on the loss list.
// Returns cloned packets that the caller owns (must Release after sending).
func (sb *SendBuffer) NAK(lossSeqs []uint32) []packet.Packet {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	var retransmit []packet.Packet
	for _, seqNo := range lossSeqs {
		s := seq.Number(seqNo)
		if s.LessThan(sb.startSeq) || sb.nextSeq.LessThanOrEqual(s) {
			continue // out of range
		}
		idx := int(seqNo) & sb.mask
		if sb.entries[idx].used {
			clone := sb.entries[idx].pkt.Clone()
			clone.Header.Retransmitted = true
			retransmit = append(retransmit, clone)
		}
	}
	return retransmit
}

// NAKTimed retrieves packets for retransmission with a timing gate that prevents
// re-retransmission within one RTT of the last retransmit for each packet.
// If the packet was retransmitted more recently than (now - (SRTT - 4*RTTVar)),
// it is skipped.
// The now parameter is the current time, rtt is the smoothed RTT in microseconds,
// and rttVar is the RTT variance in microseconds.
func (sb *SendBuffer) NAKTimed(lossSeqs []uint32, now clock.Timestamp, rtt, rttVar clock.Microseconds) []packet.Packet {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// time_nak = now - (SRTT - 4*RTTVar)
	// A packet's last rexmit time must be before time_nak to be eligible.
	rexmitGate := rtt - 4*rttVar
	if rexmitGate < 0 {
		rexmitGate = 0
	}
	timeNAK := now.Add(-rexmitGate)

	var retransmit []packet.Packet
	for _, seqNo := range lossSeqs {
		s := seq.Number(seqNo)
		if s.LessThan(sb.startSeq) || sb.nextSeq.LessThanOrEqual(s) {
			continue // out of range
		}
		idx := int(seqNo) & sb.mask
		if !sb.entries[idx].used {
			continue
		}
		// If tsLastRexmit >= time_nak, skip
		if !sb.entries[idx].rexmitTime.IsZero() && !sb.entries[idx].rexmitTime.Before(timeNAK) {
			continue // retransmitted too recently
		}

		clone := sb.entries[idx].pkt.Clone()
		clone.Header.Retransmitted = true
		retransmit = append(retransmit, clone)
		// Record the retransmission time.
		sb.entries[idx].rexmitTime = now
	}
	return retransmit
}

// Get retrieves a packet by sequence number for retransmission.
// Returns a clone that the caller owns.
func (sb *SendBuffer) Get(seqNo seq.Number) (packet.Packet, bool) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if seqNo.LessThan(sb.startSeq) || sb.nextSeq.LessThanOrEqual(seqNo) {
		return packet.Packet{}, false
	}

	idx := int(uint32(seqNo)) & sb.mask
	if !sb.entries[idx].used {
		return packet.Packet{}, false
	}

	return sb.entries[idx].pkt.Clone(), true
}

// Size returns the number of unacknowledged packets in the buffer.
func (sb *SendBuffer) Size() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.size
}

// Capacity returns the total buffer capacity.
func (sb *SendBuffer) Capacity() int {
	return len(sb.entries)
}

// Available returns the number of free slots.
func (sb *SendBuffer) Available() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return len(sb.entries) - sb.size
}

// StartSeq returns the oldest unacknowledged sequence number.
func (sb *SendBuffer) StartSeq() seq.Number {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.startSeq
}

// NextSeq returns the next sequence number to be used for insertion.
func (sb *SendBuffer) NextSeq() seq.Number {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.nextSeq
}

// OverrideNextSeq adjusts the send buffer's next sequence number to match
// a group's current scheduling sequence. This is used when activating an
// idle member in a bonding group so that all members share the same
// sequence number space.
//
// When the buffer is empty, both startSeq and nextSeq are set.
// When the buffer has packets, only nextSeq is advanced (keeping
// existing in-flight packets tracked).
// Returns true if the override was applied.
func (sb *SendBuffer) OverrideNextSeq(nextSeq seq.Number) bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.size == 0 {
		// Empty buffer: reset both pointers.
		sb.startSeq = nextSeq
		sb.nextSeq = nextSeq
	} else {
		// Non-empty buffer: only advance nextSeq.
		// Existing buffered packets retain their sequence slots.
		// The gap between the old nextSeq and new nextSeq will be treated
		// as lost by the receiver.
		sb.nextSeq = nextSeq
	}
	return true
}

// OldestSendTime returns the send timestamp of the oldest unacked packet.
// Returns zero if the buffer is empty.
func (sb *SendBuffer) OldestSendTime() clock.Timestamp {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.size == 0 {
		return 0
	}

	idx := int(uint32(sb.startSeq)) & sb.mask
	return sb.entries[idx].sentAt
}

// DropUntil drops (releases) packets from startSeq up to (but not including)
// the given sequence number. Returns the number of dropped packets.
// Used for too-late packet drops where the sender gives up on retransmission.
func (sb *SendBuffer) DropUntil(upTo seq.Number) int {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	count := 0
	for sb.startSeq.LessThan(upTo) && sb.size > 0 {
		idx := int(uint32(sb.startSeq)) & sb.mask
		if sb.entries[idx].used {
			sb.entries[idx].pkt.Release()
			sb.entries[idx] = sendEntry{}
			count++
			sb.size--
		}
		sb.startSeq = sb.startSeq.Inc()
	}
	return count
}

// GetAllUnacked returns cloned packets for all unacknowledged entries in the buffer.
// Used for LATEREXMIT blind retransmission on RTO when the loss list is empty.
// The caller owns the returned packets and must Release them.
func (sb *SendBuffer) GetAllUnacked() []packet.Packet {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.size == 0 {
		return nil
	}

	var pkts []packet.Packet
	s := sb.startSeq
	for s.LessThan(sb.nextSeq) {
		idx := int(uint32(s)) & sb.mask
		if sb.entries[idx].used {
			clone := sb.entries[idx].pkt.Clone()
			clone.Header.Retransmitted = true
			pkts = append(pkts, clone)
		}
		s = s.Inc()
	}
	return pkts
}

// DropExpiredTTL drops packets whose per-message TTL has expired.
// Returns the number of dropped packets. The caller should report dropped
// counts to the stats counters.
func (sb *SendBuffer) DropExpiredTTL(now clock.Timestamp) int {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	dropped := 0
	s := sb.startSeq
	for s.LessThan(sb.nextSeq) {
		idx := int(uint32(s)) & sb.mask
		e := &sb.entries[idx]
		if e.used && e.msgTTL > 0 {
			elapsed := int64(now) - int64(e.sentAt)
			if elapsed > e.msgTTL/1000 { // msgTTL is nanoseconds, timestamps are microseconds
				e.pkt.Release()
				*e = sendEntry{}
				dropped++
				sb.size--
			}
		}
		s = s.Inc()
	}
	// Advance startSeq past any released entries at the front
	for sb.startSeq.LessThan(sb.nextSeq) {
		idx := int(uint32(sb.startSeq)) & sb.mask
		if sb.entries[idx].used {
			break
		}
		sb.startSeq = sb.startSeq.Inc()
	}
	return dropped
}

// SetMsgTTL sets the per-message TTL (in nanoseconds) for the last pushed entry.
// Called immediately after Push to associate TTL with the most recently pushed packet.
func (sb *SendBuffer) SetMsgTTL(ttl int64) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.size == 0 {
		return
	}
	prevSeq := sb.nextSeq.Dec()
	idx := int(uint32(prevSeq)) & sb.mask
	if sb.entries[idx].used {
		sb.entries[idx].msgTTL = ttl
	}
}

// SetMsgTTLBatch sets the per-message TTL (in nanoseconds) for the last n pushed
// entries. Called after PushBatch to associate TTL with all fragments of a
// multi-packet message.
func (sb *SendBuffer) SetMsgTTLBatch(ttl int64, n int) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.size == 0 || n <= 0 {
		return
	}
	for i := 0; i < n; i++ {
		s := sb.nextSeq.Add(uint32(-n + i))
		idx := int(uint32(s)) & sb.mask
		if sb.entries[idx].used {
			sb.entries[idx].msgTTL = ttl
		}
	}
}

// nextPow2 returns the smallest power of 2 >= n.
func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	return n + 1
}
