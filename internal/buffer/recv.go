package buffer

import (
	"sync"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
)

// EntryState tracks the state of a receive buffer slot.
type EntryState uint8

const (
	EntryEmpty     EntryState = iota // slot is empty (packet not received)
	EntryAvailable                   // packet received, not yet read by app
	EntryRead                        // packet has been read by app
	EntryDrop                        // packet has been dropped (e.g., via DROPREQ or too-late)
)

// recvEntry holds a packet in the receive buffer.
type recvEntry struct {
	pkt       packet.Packet
	state     EntryState
	arrivalTS clock.Timestamp // when the packet arrived (for TSBPD)
}

// RecvBuffer is a ring buffer for received packets.
// It supports O(1) insertion, sequential reading with TSBPD timing,
// and gap detection for NAK generation.
type RecvBuffer struct {
	mu       sync.Mutex
	entries  []recvEntry
	mask     int
	startSeq seq.Number // oldest un-read sequence number
	maxSeq   seq.Number // highest sequence number received + 1
	size     int        // count of Available entries

	// Out-of-order message reading support (message API mode only).
	// Packets with Order=false can be read out of order when no in-order data
	// is available. This is used in file transfer mode where messages can arrive
	// and be consumed out of sequence order.
	numOutOfOrderPkts int  // count of stored packets with Order flag = false
	firstReadableOOO  int  // buffer index of first complete out-of-order message (-1 = none)
	messageAPI        bool // true if message API mode is enabled (enables OOO reading)

	// onRead is called when a packet is read from the buffer, passing its timestamp.
	// Used to update the TSBPD time base on read.
	onRead func(pktTimestamp uint32)

	// onDrop is called when an available packet is dropped, passing its timestamp.
	// Used to update the TSBPD time base on drop.
	onDrop func(pktTimestamp uint32)

	// lossListBuf is a reusable buffer for GenerateLossList to avoid per-call allocation.
	lossListBuf []uint32
}

// NewRecvBuffer creates a receive buffer with the given capacity (rounded up
// to next power of 2) starting at the given initial sequence number.
func NewRecvBuffer(capacity int, initialSeq seq.Number) *RecvBuffer {
	cap2 := nextPow2(capacity)
	return &RecvBuffer{
		entries:          make([]recvEntry, cap2),
		mask:             cap2 - 1,
		startSeq:         initialSeq,
		maxSeq:           initialSeq,
		firstReadableOOO: -1,
	}
}

// SetMessageAPI enables message API mode, which allows out-of-order message
// reading. When enabled, packets with the Order flag set to false can be
// read out of order if no in-order data is available.
func (rb *RecvBuffer) SetMessageAPI(enabled bool) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.messageAPI = enabled
}

// SetOnRead sets a callback invoked when a packet is read from the buffer.
// The callback receives the packet's SRT timestamp for TSBPD wrap tracking.
func (rb *RecvBuffer) SetOnRead(fn func(pktTimestamp uint32)) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.onRead = fn
}

// SetOnDrop sets a callback invoked when an available packet is dropped.
// The callback receives the packet's SRT timestamp for TSBPD wrap tracking.
func (rb *RecvBuffer) SetOnDrop(fn func(pktTimestamp uint32)) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.onDrop = fn
}

// releaseFillerEntries advances past any Drop or Read entries at the head
// of the buffer.
func (rb *RecvBuffer) releaseFillerEntries() {
	// Safety: don't advance past maxSeq (the farthest received).
	for rb.startSeq.LessThan(rb.maxSeq) {
		idx := int(uint32(rb.startSeq)) & rb.mask
		st := rb.entries[idx].state
		if st != EntryDrop && st != EntryRead {
			break
		}
		rb.entries[idx] = recvEntry{}
		rb.startSeq = rb.startSeq.Inc()
	}
}

// InsertResult describes the outcome of inserting a packet into the RecvBuffer.
type InsertResult struct {
	Inserted bool
	// GapStart and GapEnd describe a newly detected gap (both zero if no gap).
	// The gap is [GapStart, GapEnd] inclusive — these are the missing sequence numbers.
	GapStart uint32
	GapEnd   uint32
}

// HasGap returns true if a gap was detected during insertion.
func (r InsertResult) HasGap() bool {
	return r.Inserted && (r.GapStart != 0 || r.GapEnd != 0)
}

// Insert adds a received packet to the buffer. Returns an InsertResult
// indicating whether the packet was inserted and whether a new gap was detected.
// A gap is reported when the packet extends beyond maxSeq, revealing missing
// sequence numbers in [maxSeq, seqNo-1].
func (rb *RecvBuffer) Insert(p packet.Packet, arrivalTS clock.Timestamp) InsertResult {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	s := seq.Number(p.Header.SequenceNumber)

	// Too old — already ACK'd/read past this
	if s.LessThan(rb.startSeq) {
		return InsertResult{}
	}

	// Too far ahead — would exceed buffer capacity.
	// One slot is reserved to distinguish full from empty.
	dist := rb.startSeq.Distance(s)
	if dist < 0 || int(dist) >= len(rb.entries)-1 {
		return InsertResult{}
	}

	idx := int(uint32(s)) & rb.mask

	// Duplicate check
	if rb.entries[idx].state != EntryEmpty {
		return InsertResult{}
	}

	// Detect new gap: if this packet is beyond maxSeq (and we've received
	// at least one packet), the range [maxSeq, s-1] is missing.
	var result InsertResult
	result.Inserted = true
	if rb.maxSeq != rb.startSeq && rb.maxSeq.LessThan(s) {
		result.GapStart = rb.maxSeq.Value()
		result.GapEnd = s.Dec().Value()
	}

	rb.entries[idx] = recvEntry{
		pkt:       p,
		state:     EntryAvailable,
		arrivalTS: arrivalTS,
	}
	rb.size++

	// Advance maxSeq if this packet extends the range
	next := s.Inc()
	if rb.maxSeq.LessThan(next) || rb.maxSeq == rb.startSeq {
		rb.maxSeq = next
	}

	// If the packet's "in order" flag is zero, it can be read out of order.
	// Only applicable in message API mode (TSBPD disables OOO).
	if rb.messageAPI && !p.Header.Order {
		rb.numOutOfOrderPkts++
		rb.onInsertNotInOrderPacket(idx)
	}

	return result
}

// ReadNext returns the next in-order packet from the buffer.
// Returns false if the next packet is not available.
func (rb *RecvBuffer) ReadNext() (packet.Packet, bool) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	idx := int(uint32(rb.startSeq)) & rb.mask
	if rb.entries[idx].state != EntryAvailable {
		return packet.Packet{}, false
	}

	p := rb.entries[idx].pkt
	rb.entries[idx] = recvEntry{} // clear the slot
	rb.startSeq = rb.startSeq.Inc()
	rb.size--

	return p, true
}

// ReadMessage returns all packets forming the next complete message.
// For single-packet messages (PP_SINGLE), returns a single packet.
// For multi-packet messages, waits until all packets from PP_FIRST through
// PP_LAST are contiguously available, then returns them all.
//
// When message API mode is enabled and no in-order message is available,
// falls back to reading the first complete out-of-order message (packets
// with Order=false). Out-of-order reads mark entries as EntryRead but do
// NOT advance startSeq.
func (rb *RecvBuffer) ReadMessage() ([]packet.Packet, bool) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	return rb.readMessageLocked()
}

// readMessageLocked is the internal implementation of ReadMessage, called
// with rb.mu held.
func (rb *RecvBuffer) readMessageLocked() ([]packet.Packet, bool) {
	// Check if in-order reading is possible.
	canReadInOrder := rb.canReadInOrder()

	if !canReadInOrder && rb.firstReadableOOO < 0 {
		return nil, false
	}

	if canReadInOrder {
		return rb.readMessageInOrder()
	}

	// Fall back to out-of-order reading.
	return rb.readMessageOutOfOrder()
}

// canReadInOrder returns true if the head of the buffer has an available packet.
func (rb *RecvBuffer) canReadInOrder() bool {
	idx := int(uint32(rb.startSeq)) & rb.mask
	return rb.entries[idx].state == EntryAvailable
}

// readMessageInOrder reads the next in-order message from the buffer head,
// advancing startSeq. Called with rb.mu held.
func (rb *RecvBuffer) readMessageInOrder() ([]packet.Packet, bool) {
	idx := int(uint32(rb.startSeq)) & rb.mask
	pp := rb.entries[idx].pkt.Header.PacketPosition

	// Single-packet message
	if pp == packet.PositionSingle {
		p := rb.entries[idx].pkt
		if rb.numOutOfOrderPkts > 0 && !p.Header.Order {
			rb.numOutOfOrderPkts--
		}
		rb.entries[idx] = recvEntry{}
		rb.startSeq = rb.startSeq.Inc()
		rb.size--
		rb.releaseFillerEntries()
		// After in-order read, rescan OOO in case all in-order data is now
		// consumed and an OOO message is next.
		if rb.messageAPI {
			rb.updateFirstReadableOutOfOrder()
		}
		return []packet.Packet{p}, true
	}

	// Multi-packet message: must start with PP_FIRST
	if pp != packet.PositionFirst {
		// Not the first packet of a message — skip this corrupted packet
		if rb.numOutOfOrderPkts > 0 && !rb.entries[idx].pkt.Header.Order {
			rb.numOutOfOrderPkts--
		}
		rb.entries[idx].pkt.Release()
		rb.entries[idx] = recvEntry{}
		rb.startSeq = rb.startSeq.Inc()
		rb.size--
		rb.releaseFillerEntries()
		if rb.messageAPI {
			rb.updateFirstReadableOutOfOrder()
		}
		return nil, false
	}

	// Scan forward to find PP_LAST, verifying all packets are available
	// and belong to the same message (matching MessageNumber).
	s := rb.startSeq
	msgNo := rb.entries[idx].pkt.Header.MessageNumber
	var count int
	for {
		si := int(uint32(s)) & rb.mask
		if rb.entries[si].state != EntryAvailable {
			return nil, false // gap — message not complete yet
		}
		// Validate all packets belong to the same message
		if rb.entries[si].pkt.Header.MessageNumber != msgNo {
			// Different message number — corrupted sequence. Skip the first packet.
			if rb.numOutOfOrderPkts > 0 && !rb.entries[idx].pkt.Header.Order {
				rb.numOutOfOrderPkts--
			}
			rb.entries[idx].pkt.Release()
			rb.entries[idx] = recvEntry{}
			rb.startSeq = rb.startSeq.Inc()
			rb.size--
			rb.releaseFillerEntries()
			if rb.messageAPI {
				rb.updateFirstReadableOutOfOrder()
			}
			return nil, false
		}
		count++
		pos := rb.entries[si].pkt.Header.PacketPosition
		if pos == packet.PositionLast || pos == packet.PositionSingle {
			break // found the end
		}
		s = s.Inc()
		if count > len(rb.entries) {
			return nil, false // safety: prevent infinite loop
		}
	}

	// All packets available — consume them (advance startSeq)
	pkts := make([]packet.Packet, 0, count)
	for i := 0; i < count; i++ {
		si := int(uint32(rb.startSeq)) & rb.mask
		p := rb.entries[si].pkt
		if rb.numOutOfOrderPkts > 0 && !p.Header.Order {
			rb.numOutOfOrderPkts--
		}
		pkts = append(pkts, p)
		rb.entries[si] = recvEntry{}
		rb.startSeq = rb.startSeq.Inc()
		rb.size--
	}

	rb.releaseFillerEntries()
	// Rescan OOO after in-order read.
	if rb.messageAPI {
		rb.updateFirstReadableOutOfOrder()
	}

	return pkts, true
}

// readMessageOutOfOrder reads a complete out-of-order message starting at
// firstReadableOOO. Packets are marked as EntryRead but startSeq is NOT
// advanced.
func (rb *RecvBuffer) readMessageOutOfOrder() ([]packet.Packet, bool) {
	if rb.firstReadableOOO < 0 {
		return nil, false
	}

	readPos := rb.firstReadableOOO

	// Collect all packets in this message from readPos forward until PP_LAST.
	var pkts []packet.Packet
	for i := readPos; ; i = (i + 1) & rb.mask {
		entry := &rb.entries[i]
		if entry.state != EntryAvailable {
			// Should not happen if firstReadableOOO is correct, but be safe.
			rb.firstReadableOOO = -1
			return nil, false
		}

		p := entry.pkt
		pkts = append(pkts, p)

		if rb.numOutOfOrderPkts > 0 && !p.Header.Order {
			rb.numOutOfOrderPkts--
		}

		// Mark as Read (don't clear — startSeq not advancing).
		entry.state = EntryRead
		entry.pkt = packet.Packet{} // release the packet data reference
		rb.size--

		isLast := p.Header.PacketPosition == packet.PositionLast ||
			p.Header.PacketPosition == packet.PositionSingle
		if isLast {
			break
		}

		// Safety: prevent infinite loop
		if len(pkts) > len(rb.entries) {
			rb.firstReadableOOO = -1
			return nil, false
		}
	}

	// Clear firstReadableOOO since we just read it.
	rb.firstReadableOOO = -1

	// Release filler entries after read.
	rb.releaseFillerEntries()

	// Rescan for the next OOO message.
	rb.updateFirstReadableOutOfOrder()

	return pkts, true
}

// onInsertNotInOrderPacket is called when a packet with Order=false is inserted.
// It checks whether this packet completes a message that can be read out of order.
func (rb *RecvBuffer) onInsertNotInOrderPacket(insertPos int) {
	if rb.numOutOfOrderPkts == 0 {
		return
	}

	// If we already have a readable OOO message, skip.
	// The search should be done when that message is read out from the buffer.
	if rb.firstReadableOOO >= 0 {
		return
	}

	entry := &rb.entries[insertPos]
	pp := entry.pkt.Header.PacketPosition
	msgNo := entry.pkt.Header.MessageNumber

	// Single-packet message: immediately readable out of order.
	if pp == packet.PositionSingle {
		rb.firstReadableOOO = insertPos
		return
	}

	// First check last packet (expected to arrive last).
	hasLast := (pp == packet.PositionLast) ||
		rb.scanNotInOrderMessageRight(insertPos, msgNo) >= 0

	if !hasLast {
		return
	}

	// Find the first packet position.
	firstPktPos := insertPos
	if pp != packet.PositionFirst {
		firstPktPos = rb.scanNotInOrderMessageLeft(insertPos, msgNo)
	}

	if firstPktPos < 0 {
		return
	}

	rb.firstReadableOOO = firstPktPos
}

// scanNotInOrderMessageRight scans forward from startPos looking for PP_LAST
// of the same message. Returns the buffer index of the LAST packet, or -1.
func (rb *RecvBuffer) scanNotInOrderMessageRight(startPos int, msgNo uint32) int {
	// Compute the last valid position in the buffer.
	maxOff := int(rb.startSeq.Distance(rb.maxSeq.Dec()))
	if maxOff <= 0 {
		return -1
	}
	lastPos := (int(uint32(rb.startSeq)) + maxOff) & rb.mask
	if startPos == lastPos {
		return -1
	}

	pos := startPos
	for {
		pos = (pos + 1) & rb.mask

		entry := &rb.entries[pos]
		if entry.state != EntryAvailable {
			break
		}

		if entry.pkt.Header.MessageNumber != msgNo {
			return -1
		}

		if entry.pkt.Header.PacketPosition == packet.PositionLast ||
			entry.pkt.Header.PacketPosition == packet.PositionSingle {
			return pos
		}

		if pos == lastPos {
			break
		}
	}

	return -1
}

// scanNotInOrderMessageLeft scans backward from startPos looking for PP_FIRST
// of the same message. Returns the buffer index of the FIRST packet, or -1.
func (rb *RecvBuffer) scanNotInOrderMessageLeft(startPos int, msgNo uint32) int {
	startIdx := int(uint32(rb.startSeq)) & rb.mask
	if startPos == startIdx {
		return -1
	}

	pos := startPos
	for {
		pos = (pos - 1 + len(rb.entries)) & rb.mask

		entry := &rb.entries[pos]
		if entry.state != EntryAvailable {
			return -1
		}

		if entry.pkt.Header.MessageNumber != msgNo {
			return -1
		}

		if entry.pkt.Header.PacketPosition == packet.PositionFirst ||
			entry.pkt.Header.PacketPosition == packet.PositionSingle {
			return pos
		}

		if pos == startIdx {
			break
		}
	}

	return -1
}

// checkFirstReadableOutOfOrder verifies that firstReadableOOO still points
// to a valid complete out-of-order message. Returns false if invalidated.
func (rb *RecvBuffer) checkFirstReadableOutOfOrder() bool {
	if rb.numOutOfOrderPkts <= 0 || rb.firstReadableOOO < 0 {
		return false
	}

	// Verify the buffer has content.
	if rb.startSeq == rb.maxSeq {
		return false
	}

	maxOff := int(rb.startSeq.Distance(rb.maxSeq))
	endPos := (int(uint32(rb.startSeq)) + maxOff) & rb.mask
	msgNo := int64(-1)

	for pos := rb.firstReadableOOO; pos != endPos; pos = (pos + 1) & rb.mask {
		entry := &rb.entries[pos]
		if entry.state != EntryAvailable {
			return false
		}

		if entry.pkt.Header.Order {
			return false
		}

		if msgNo == -1 {
			msgNo = int64(entry.pkt.Header.MessageNumber)
		} else if int64(entry.pkt.Header.MessageNumber) != msgNo {
			return false
		}

		if entry.pkt.Header.PacketPosition == packet.PositionLast ||
			entry.pkt.Header.PacketPosition == packet.PositionSingle {
			return true
		}
	}

	return false
}

// updateFirstReadableOutOfOrder scans the buffer to find the earliest
// complete out-of-order message when firstReadableOOO is -1.
func (rb *RecvBuffer) updateFirstReadableOutOfOrder() {
	// Skip if in-order data is readable, no OOO packets,
	// or we already have a known OOO position.
	if rb.canReadInOrder() || rb.numOutOfOrderPkts <= 0 || rb.firstReadableOOO >= 0 {
		return
	}

	if rb.startSeq == rb.maxSeq {
		return
	}

	oooRemain := rb.numOutOfOrderPkts

	maxOff := int(rb.startSeq.Distance(rb.maxSeq))
	if maxOff <= 0 {
		return
	}
	lastPos := (int(uint32(rb.startSeq)) + maxOff - 1) & rb.mask

	posFirst := -1
	msgNo := int64(-1)

	startIdx := int(uint32(rb.startSeq)) & rb.mask
	for pos := startIdx; oooRemain > 0; pos = (pos + 1) & rb.mask {
		entry := &rb.entries[pos]

		if entry.state != EntryAvailable {
			// Gap or read/dropped — reset tracking for current message.
			posFirst = -1
			msgNo = -1
			if pos == lastPos {
				break
			}
			continue
		}

		if entry.pkt.Header.Order {
			// In-order packet — can't be part of an OOO message.
			posFirst = -1
			msgNo = -1
			if pos == lastPos {
				break
			}
			continue
		}

		oooRemain--

		pp := entry.pkt.Header.PacketPosition

		if pp == packet.PositionFirst || pp == packet.PositionSingle {
			posFirst = pos
			msgNo = int64(entry.pkt.Header.MessageNumber)
		}

		// Message number mismatch — reset.
		if int64(entry.pkt.Header.MessageNumber) != msgNo {
			posFirst = -1
			msgNo = -1
			if pos == lastPos {
				break
			}
			continue
		}

		if pp == packet.PositionLast || pp == packet.PositionSingle {
			if posFirst >= 0 {
				rb.firstReadableOOO = posFirst
				return
			}
		}

		if pos == lastPos {
			break
		}
	}
}

// HasAvailablePackets returns true if there is any readable message —
// either in-order at the head or a complete out-of-order message.
func (rb *RecvBuffer) HasAvailablePackets() bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.canReadInOrder() {
		return true
	}
	return rb.numOutOfOrderPkts > 0 && rb.firstReadableOOO >= 0
}

// DeliveryTimeFunc calculates the TSBPD delivery time for a packet given its
// 32-bit SRT timestamp. This allows the recv buffer to delegate timestamp
// interpretation (wrap handling, drift correction) to the TSBPD timer.
type DeliveryTimeFunc func(pktTimestamp uint32) clock.Timestamp

// ReadTSBPD returns the next in-order packet if its TSBPD delivery time
// has passed. The delivery time is calculated by the provided function
// using the sender's packet timestamp (not arrival time).
// Returns false if no packet is ready for delivery.
func (rb *RecvBuffer) ReadTSBPD(now clock.Timestamp, deliveryTime DeliveryTimeFunc) (packet.Packet, bool) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	idx := int(uint32(rb.startSeq)) & rb.mask
	entry := &rb.entries[idx]

	if entry.state != EntryAvailable {
		return packet.Packet{}, false
	}

	dt := deliveryTime(entry.pkt.Header.Timestamp)
	if now.Before(dt) {
		return packet.Packet{}, false // not ready yet
	}

	p := entry.pkt
	// Update TSBPD time base on read.
	if rb.onRead != nil {
		rb.onRead(p.Header.Timestamp)
	}
	*entry = recvEntry{} // clear the slot
	rb.startSeq = rb.startSeq.Inc()
	rb.size--

	return p, true
}

// ReadMessageTSBPD returns the next complete message if its TSBPD delivery
// time has passed. In live mode, multi-packet messages are forbidden, so this
// only handles single-packet messages. The delivery time check applies to
// the first packet of the message.
func (rb *RecvBuffer) ReadMessageTSBPD(now clock.Timestamp, deliveryTime DeliveryTimeFunc) ([]packet.Packet, bool) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	idx := int(uint32(rb.startSeq)) & rb.mask
	entry := &rb.entries[idx]
	if entry.state != EntryAvailable {
		return nil, false
	}

	dt := deliveryTime(entry.pkt.Header.Timestamp)
	if now.Before(dt) {
		return nil, false
	}

	// Live mode: only single-packet messages (multi-packet forbidden in TSBPD mode)
	p := entry.pkt
	// Update TSBPD time base on read.
	if rb.onRead != nil {
		rb.onRead(p.Header.Timestamp)
	}
	*entry = recvEntry{}
	rb.startSeq = rb.startSeq.Inc()
	rb.size--
	return []packet.Packet{p}, true
}

// Drop drops packets from startSeq up to (but not including) the given
// sequence number. Used for DROPREQ handling.
// Returns the number of dropped packets (both available and empty).
// Entries are marked as EntryDrop rather than cleared, so
// releaseFillerEntries can skip past them.
func (rb *RecvBuffer) Drop(upTo seq.Number) int {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	count := 0
	for rb.startSeq.LessThan(upTo) {
		idx := int(uint32(rb.startSeq)) & rb.mask
		switch rb.entries[idx].state {
		case EntryAvailable:
			// Release the packet and mark as Drop.
			if rb.onDrop != nil {
				rb.onDrop(rb.entries[idx].pkt.Header.Timestamp)
			}
			// Decrement OOO counter if applicable.
			if rb.messageAPI && !rb.entries[idx].pkt.Header.Order {
				rb.numOutOfOrderPkts--
				if idx == rb.firstReadableOOO {
					rb.firstReadableOOO = -1
				}
			}
			rb.entries[idx].pkt.Release()
			count++
			rb.size--
		case EntryEmpty:
			// Empty entries count as dropped (missing packets).
			count++
		case EntryDrop:
			// Already dropped — don't double-count.
		}
		rb.entries[idx] = recvEntry{state: EntryDrop}
		rb.startSeq = rb.startSeq.Inc()
	}

	// Advance past any Drop/Read entries at head.
	rb.releaseFillerEntries()

	// Rescan OOO after drop.
	if rb.messageAPI {
		if !rb.checkFirstReadableOutOfOrder() {
			rb.firstReadableOOO = -1
		}
		rb.updateFirstReadableOutOfOrder()
	}

	return count
}

// DropTooLate skips empty or already-dropped slots at the head of the buffer
// whose TSBPD delivery time has passed. An empty slot is considered "too late"
// if the nearest subsequent available packet's delivery time has already passed
// (meaning the missing packet would have been delivered even later).
// Returns the number of dropped (skipped) sequence numbers.
func (rb *RecvBuffer) DropTooLate(now clock.Timestamp, deliveryTime DeliveryTimeFunc) int {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	dropped := 0
	for rb.startSeq.LessThan(rb.maxSeq) {
		idx := int(uint32(rb.startSeq)) & rb.mask
		if rb.entries[idx].state == EntryAvailable {
			// Head has a valid packet — stop (let ReadTSBPD handle it)
			break
		}

		// Empty or already-dropped slot at head. Find the nearest available
		// packet to determine if this gap is too late.
		refDelivery := clock.Timestamp(0)
		s := rb.startSeq.Inc()
		for s.LessThan(rb.maxSeq) {
			si := int(uint32(s)) & rb.mask
			if rb.entries[si].state == EntryAvailable {
				refDelivery = deliveryTime(rb.entries[si].pkt.Header.Timestamp)
				break
			}
			s = s.Inc()
		}

		if refDelivery == 0 {
			// No reference packet found — can't determine if too late
			break
		}
		if now.Before(refDelivery) {
			// Reference packet not yet ready — retransmit may still arrive in time
			break
		}

		// The reference packet's delivery time has passed, so this empty
		// slot is definitely too late. Mark as dropped and skip it.
		rb.entries[idx] = recvEntry{state: EntryDrop}
		rb.startSeq = rb.startSeq.Inc()
		dropped++
	}

	// Advance past any contiguous Drop/Read entries at the new head.
	rb.releaseFillerEntries()

	return dropped
}

// GenerateLossList returns the sequence numbers of gaps (empty slots)
// between startSeq and maxSeq. These are packets we haven't received
// yet that should be reported via NAK.
func (rb *RecvBuffer) GenerateLossList() []uint32 {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.startSeq == rb.maxSeq {
		return nil
	}

	// Reuse buffer to avoid per-call allocation
	rb.lossListBuf = rb.lossListBuf[:0]
	s := rb.startSeq
	for s.LessThan(rb.maxSeq) {
		idx := int(uint32(s)) & rb.mask
		if rb.entries[idx].state == EntryEmpty {
			rb.lossListBuf = append(rb.lossListBuf, s.Value())
		}
		s = s.Inc()
	}

	if len(rb.lossListBuf) == 0 {
		return nil
	}
	return rb.lossListBuf
}

// ACKSequence returns the highest contiguous sequence number that has been
// received (the "ACK number" — next expected sequence number).
// This scans from startSeq forward until a gap is found.
func (rb *RecvBuffer) ACKSequence() seq.Number {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	s := rb.startSeq
	for s.LessThan(rb.maxSeq) {
		idx := int(uint32(s)) & rb.mask
		if rb.entries[idx].state == EntryEmpty {
			break
		}
		s = s.Inc()
	}

	return s
}

// Size returns the number of available (received but not read) packets.
func (rb *RecvBuffer) Size() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size
}

// Capacity returns the usable buffer capacity.
// One slot is reserved to distinguish full from empty ring buffer.
func (rb *RecvBuffer) Capacity() int {
	return len(rb.entries) - 1
}

// AvailableSize returns the available buffer size for an ACK.
// The available space is calculated as capacity - seqlen(startSeq, lastAck) + 1,
// where seqlen counts the range from startSeq to lastAck as "used" (including
// gaps). This is more conservative than Capacity()-Size() because it counts
// gap slots as occupied.
func (rb *RecvBuffer) AvailableSize(lastAck seq.Number) int {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	cap := len(rb.entries) - 1 // one slot reserved
	if !rb.startSeq.LessThan(lastAck) {
		return cap
	}
	used := int(rb.startSeq.Distance(lastAck))
	if used > cap {
		return 0
	}
	return cap - used + 1
}

// StartSeq returns the oldest unread sequence number.
func (rb *RecvBuffer) StartSeq() seq.Number {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.startSeq
}

// MaxSeq returns one past the highest received sequence number.
func (rb *RecvBuffer) MaxSeq() seq.Number {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.maxSeq
}

// IsEmpty returns true if the buffer has no available packets.
func (rb *RecvBuffer) IsEmpty() bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size == 0
}

// SetInitialRcvSeq resets the receive buffer to a new initial sequence number,
// dropping all data. Used by group idle link synchronization.
func (rb *RecvBuffer) SetInitialRcvSeq(newISN seq.Number) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Release any held packets.
	for i := range rb.entries {
		if rb.entries[i].state == EntryAvailable {
			rb.entries[i].pkt.Release()
		}
		rb.entries[i] = recvEntry{}
	}

	rb.startSeq = newISN
	rb.maxSeq = newISN
	rb.size = 0
	rb.numOutOfOrderPkts = 0
	rb.firstReadableOOO = -1
}
