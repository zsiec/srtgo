package buffer

import (
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
)

// --- SendBuffer tests ---

func TestSendBufferPushAndACK(t *testing.T) {
	sb := NewSendBuffer(64, seq.Number(0))

	// Push 10 packets
	for i := range uint32(10) {
		p := packet.NewData(nil, i, uint32(i*1000), 0, []byte("test"))
		if !sb.Push(p) {
			t.Fatalf("Push(%d) failed", i)
		}
	}

	if sb.Size() != 10 {
		t.Errorf("Size: got %d, want 10", sb.Size())
	}

	// ACK up to 5
	acked := sb.ACK(seq.Number(5))
	if acked != 5 {
		t.Errorf("ACK returned %d, want 5", acked)
	}
	if sb.Size() != 5 {
		t.Errorf("Size after ACK: got %d, want 5", sb.Size())
	}
	if sb.StartSeq() != seq.Number(5) {
		t.Errorf("StartSeq: got %d, want 5", sb.StartSeq())
	}

	// ACK the rest
	acked = sb.ACK(seq.Number(10))
	if acked != 5 {
		t.Errorf("ACK returned %d, want 5", acked)
	}
	if sb.Size() != 0 {
		t.Errorf("Size: got %d, want 0", sb.Size())
	}
}

func TestSendBufferFull(t *testing.T) {
	sb := NewSendBuffer(4, seq.Number(0)) // capacity rounds up to 4

	for i := range uint32(4) {
		p := packet.NewData(nil, i, 0, 0, []byte("x"))
		if !sb.Push(p) {
			t.Fatalf("Push(%d) failed", i)
		}
	}

	// Buffer should be full
	p := packet.NewData(nil, 4, 0, 0, []byte("x"))
	if sb.Push(p) {
		t.Error("Push should fail when buffer is full")
	}
	p.Release()

	// ACK one, then push should work
	sb.ACK(seq.Number(1))
	p = packet.NewData(nil, 4, 0, 0, []byte("x"))
	if !sb.Push(p) {
		t.Error("Push should succeed after ACK frees a slot")
	}
}

func TestSendBufferNAK(t *testing.T) {
	sb := NewSendBuffer(64, seq.Number(0))

	for i := range uint32(10) {
		p := packet.NewData(nil, i, uint32(i), 0, []byte("data"))
		sb.Push(p)
	}

	// Request retransmission of packets 3, 5, 7
	retransmit := sb.NAK([]uint32{3, 5, 7})
	if len(retransmit) != 3 {
		t.Fatalf("NAK returned %d packets, want 3", len(retransmit))
	}

	for _, p := range retransmit {
		if !p.Header.Retransmitted {
			t.Error("retransmitted packet should have Retransmitted flag set")
		}
		p.Release()
	}

	// NAK for out-of-range sequences should be ignored
	retransmit = sb.NAK([]uint32{100, 200})
	if len(retransmit) != 0 {
		t.Errorf("NAK returned %d for out-of-range, want 0", len(retransmit))
	}
}

func TestSendBufferGet(t *testing.T) {
	sb := NewSendBuffer(64, seq.Number(10))

	p := packet.NewData(nil, 10, 1000, 0, []byte("hello"))
	sb.Push(p)

	got, ok := sb.Get(seq.Number(10))
	if !ok {
		t.Fatal("Get failed")
	}
	defer got.Release()

	if string(got.Data) != "hello" {
		t.Errorf("data: got %q, want %q", got.Data, "hello")
	}

	_, ok = sb.Get(seq.Number(99))
	if ok {
		t.Error("Get should fail for non-existent sequence")
	}
}

func TestSendBufferAvailable(t *testing.T) {
	sb := NewSendBuffer(8, seq.Number(0))
	if sb.Available() != 8 {
		t.Errorf("Available: got %d, want 8", sb.Available())
	}

	p := packet.NewData(nil, 0, 0, 0, []byte("x"))
	sb.Push(p)
	if sb.Available() != 7 {
		t.Errorf("Available: got %d, want 7", sb.Available())
	}
}

// --- RecvBuffer tests ---

func TestRecvBufferInsertAndRead(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))

	// Insert packets 0-4
	for i := range uint32(5) {
		p := packet.NewData(nil, i, uint32(i*1000), 0, []byte("test"))
		if !rb.Insert(p, clock.Timestamp(i*1000)).Inserted {
			t.Fatalf("Insert(%d) failed", i)
		}
	}

	if rb.Size() != 5 {
		t.Errorf("Size: got %d, want 5", rb.Size())
	}

	// Read sequentially
	for i := range uint32(5) {
		p, ok := rb.ReadNext()
		if !ok {
			t.Fatalf("ReadNext(%d) failed", i)
		}
		if p.Header.SequenceNumber != i {
			t.Errorf("seq: got %d, want %d", p.Header.SequenceNumber, i)
		}
	}

	if rb.Size() != 0 {
		t.Errorf("Size: got %d, want 0", rb.Size())
	}
}

func TestRecvBufferOutOfOrder(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))

	// Insert out of order: 2, 0, 3, 1
	for _, s := range []uint32{2, 0, 3, 1} {
		p := packet.NewData(nil, s, 0, 0, []byte("test"))
		rb.Insert(p, clock.Timestamp(0))
	}

	// Should read in order: 0, 1, 2, 3
	for i := range uint32(4) {
		p, ok := rb.ReadNext()
		if !ok {
			t.Fatalf("ReadNext(%d) failed", i)
		}
		if p.Header.SequenceNumber != i {
			t.Errorf("seq: got %d, want %d", p.Header.SequenceNumber, i)
		}
	}
}

func TestRecvBufferDuplicate(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))

	p1 := packet.NewData(nil, 0, 0, 0, []byte("first"))
	if !rb.Insert(p1, clock.Timestamp(0)).Inserted {
		t.Fatal("first Insert should succeed")
	}

	p2 := packet.NewData(nil, 0, 0, 0, []byte("duplicate"))
	if rb.Insert(p2, clock.Timestamp(0)).Inserted {
		t.Error("duplicate Insert should fail")
	}
	p2.Release()
}

func TestRecvBufferTooOld(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(5))

	p := packet.NewData(nil, 3, 0, 0, []byte("old"))
	if rb.Insert(p, clock.Timestamp(0)).Inserted {
		t.Error("Insert of too-old packet should fail")
	}
	p.Release()
}

func TestRecvBufferGapDetection(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))

	// Insert 0, 1, 4, 5 (gap at 2, 3)
	for _, s := range []uint32{0, 1, 4, 5} {
		p := packet.NewData(nil, s, 0, 0, []byte("test"))
		rb.Insert(p, clock.Timestamp(0))
	}

	losses := rb.GenerateLossList()
	if len(losses) != 2 {
		t.Fatalf("LossList length: got %d, want 2", len(losses))
	}
	if losses[0] != 2 || losses[1] != 3 {
		t.Errorf("LossList: got %v, want [2, 3]", losses)
	}
}

func TestRecvBufferInsertGapDetection(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))

	// Insert seq 0 — first packet, no gap
	p0 := packet.NewData(nil, 0, 0, 0, []byte("test"))
	r0 := rb.Insert(p0, clock.Timestamp(0))
	if !r0.Inserted {
		t.Fatal("Insert(0) failed")
	}
	if r0.HasGap() {
		t.Error("first packet should not report a gap")
	}

	// Insert seq 3 — skips 1,2 → gap [1,2]
	p3 := packet.NewData(nil, 3, 0, 0, []byte("test"))
	r3 := rb.Insert(p3, clock.Timestamp(0))
	if !r3.Inserted {
		t.Fatal("Insert(3) failed")
	}
	if !r3.HasGap() {
		t.Fatal("Insert(3) should report a gap")
	}
	if r3.GapStart != 1 || r3.GapEnd != 2 {
		t.Errorf("gap: got [%d,%d], want [1,2]", r3.GapStart, r3.GapEnd)
	}
}

func TestRecvBufferInsertNoGapOnFill(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))

	// Insert 0 then 3 (creates gap)
	p0 := packet.NewData(nil, 0, 0, 0, []byte("test"))
	rb.Insert(p0, clock.Timestamp(0))
	p3 := packet.NewData(nil, 3, 0, 0, []byte("test"))
	rb.Insert(p3, clock.Timestamp(0))

	// Insert 1 — fills a gap, does NOT extend beyond maxSeq → no new gap
	p1 := packet.NewData(nil, 1, 0, 0, []byte("test"))
	r1 := rb.Insert(p1, clock.Timestamp(0))
	if !r1.Inserted {
		t.Fatal("Insert(1) failed")
	}
	if r1.HasGap() {
		t.Error("filling a gap should not report a new gap")
	}
}

func TestRecvBufferInsertConsecutive(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))

	// Insert 0, 1, 2, 3 consecutively — no gaps ever
	for i := range uint32(4) {
		p := packet.NewData(nil, i, 0, 0, []byte("test"))
		r := rb.Insert(p, clock.Timestamp(0))
		if !r.Inserted {
			t.Fatalf("Insert(%d) failed", i)
		}
		if r.HasGap() {
			t.Errorf("consecutive Insert(%d) should not report a gap", i)
		}
	}
}

func TestRecvBufferInsertSingleGap(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))

	// Insert 0 then 2 — single missing packet at 1
	p0 := packet.NewData(nil, 0, 0, 0, []byte("test"))
	rb.Insert(p0, clock.Timestamp(0))

	p2 := packet.NewData(nil, 2, 0, 0, []byte("test"))
	r2 := rb.Insert(p2, clock.Timestamp(0))
	if !r2.HasGap() {
		t.Fatal("expected gap")
	}
	if r2.GapStart != 1 || r2.GapEnd != 1 {
		t.Errorf("gap: got [%d,%d], want [1,1]", r2.GapStart, r2.GapEnd)
	}
}

func TestRecvBufferACKSequence(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))

	// Insert 0, 1, 2, 5 (gap at 3, 4)
	for _, s := range []uint32{0, 1, 2, 5} {
		p := packet.NewData(nil, s, 0, 0, []byte("test"))
		rb.Insert(p, clock.Timestamp(0))
	}

	ack := rb.ACKSequence()
	if ack != seq.Number(3) {
		t.Errorf("ACKSequence: got %d, want 3", ack)
	}

	// Fill the gap
	for _, s := range []uint32{3, 4} {
		p := packet.NewData(nil, s, 0, 0, []byte("test"))
		rb.Insert(p, clock.Timestamp(0))
	}

	ack = rb.ACKSequence()
	if ack != seq.Number(6) {
		t.Errorf("ACKSequence: got %d, want 6", ack)
	}
}

func TestRecvBufferTSBPD(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))
	delay := clock.Microseconds(100_000) // 100ms

	// DeliveryTimeFunc: simulates TSBPD with timeBase=0, no drift
	dtFunc := func(ts uint32) clock.Timestamp {
		return clock.Timestamp(ts) + clock.Timestamp(delay)
	}

	// Packet with sender timestamp = 1.0s
	p := packet.NewData(nil, 0, 1_000_000, 0, []byte("tsbpd"))
	rb.Insert(p, clock.Timestamp(1_000_000))

	// Before delivery time (1.0s + 0.1s = 1.1s)
	_, ok := rb.ReadTSBPD(clock.Timestamp(1_050_000), dtFunc)
	if ok {
		t.Error("should not deliver before delay")
	}

	// At delivery time
	p2, ok := rb.ReadTSBPD(clock.Timestamp(1_100_001), dtFunc)
	if !ok {
		t.Fatal("should deliver after delay")
	}
	if string(p2.Data) != "tsbpd" {
		t.Errorf("data: got %q, want %q", p2.Data, "tsbpd")
	}
}

func TestRecvBufferDrop(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))

	for i := range uint32(5) {
		p := packet.NewData(nil, i, 0, 0, []byte("x"))
		rb.Insert(p, clock.Timestamp(0))
	}

	dropped := rb.Drop(seq.Number(3))
	if dropped != 3 {
		t.Errorf("Drop: got %d, want 3", dropped)
	}
	if rb.Size() != 2 {
		t.Errorf("Size: got %d, want 2", rb.Size())
	}
	if rb.StartSeq() != seq.Number(3) {
		t.Errorf("StartSeq: got %d, want 3", rb.StartSeq())
	}
}

// --- DropTooLate tests ---

func TestRecvBufferDropTooLate(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))
	delay := clock.Microseconds(100_000) // 100ms

	dtFunc := func(ts uint32) clock.Timestamp {
		return clock.Timestamp(ts) + clock.Timestamp(delay)
	}

	// Insert packets 1 and 3 — gaps at 0 and 2
	// Sender timestamps at 1.0s
	for _, s := range []uint32{1, 3} {
		p := packet.NewData(nil, s, 1_000_000, 0, []byte("data"))
		rb.Insert(p, clock.Timestamp(1_000_000))
	}

	// Before delivery time (1.0s + 0.1s = 1.1s) — nothing should be dropped
	dropped := rb.DropTooLate(clock.Timestamp(1_050_000), dtFunc)
	if dropped != 0 {
		t.Errorf("DropTooLate before delivery: got %d, want 0", dropped)
	}
	if rb.StartSeq() != seq.Number(0) {
		t.Errorf("StartSeq: got %d, want 0", rb.StartSeq())
	}

	// After delivery time — empty slot 0 should be skipped
	dropped = rb.DropTooLate(clock.Timestamp(1_200_000), dtFunc)
	if dropped != 1 {
		t.Errorf("DropTooLate after delivery: got %d, want 1", dropped)
	}
	if rb.StartSeq() != seq.Number(1) {
		t.Errorf("StartSeq: got %d, want 1", rb.StartSeq())
	}

	// Now packet 1 is at the head (Available) — DropTooLate should stop
	dropped = rb.DropTooLate(clock.Timestamp(1_200_000), dtFunc)
	if dropped != 0 {
		t.Errorf("DropTooLate at available: got %d, want 0", dropped)
	}

	// Read packet 1
	_, ok := rb.ReadNext()
	if !ok {
		t.Fatal("ReadNext should return packet 1")
	}

	// Now startSeq=2 (empty), packet 3 is the reference. Drop slot 2.
	dropped = rb.DropTooLate(clock.Timestamp(1_200_000), dtFunc)
	if dropped != 1 {
		t.Errorf("DropTooLate for gap at 2: got %d, want 1", dropped)
	}
	if rb.StartSeq() != seq.Number(3) {
		t.Errorf("StartSeq: got %d, want 3", rb.StartSeq())
	}
}

func TestRecvBufferDropTooLateNoFalsePositive(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))
	delay := clock.Microseconds(100_000) // 100ms

	dtFunc := func(ts uint32) clock.Timestamp {
		return clock.Timestamp(ts) + clock.Timestamp(delay)
	}

	// Insert packet 1 (gap at 0), sender timestamp at 1.0s
	p := packet.NewData(nil, 1, 1_000_000, 0, []byte("data"))
	rb.Insert(p, clock.Timestamp(1_000_000))

	// Call DropTooLate before delivery time — slot 0 should NOT be dropped
	dropped := rb.DropTooLate(clock.Timestamp(1_050_000), dtFunc)
	if dropped != 0 {
		t.Errorf("DropTooLate: got %d, want 0 (retransmit may still arrive)", dropped)
	}
	if rb.StartSeq() != seq.Number(0) {
		t.Errorf("StartSeq: got %d, want 0", rb.StartSeq())
	}
}

func TestRecvBufferDropTooLateNoReference(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))

	dtFunc := func(ts uint32) clock.Timestamp {
		return clock.Timestamp(ts) + 100_000
	}

	// maxSeq > startSeq but all slots empty (e.g., after Drop)
	// Insert and then drop to create this state
	p := packet.NewData(nil, 0, 0, 0, []byte("data"))
	rb.Insert(p, clock.Timestamp(1_000_000))
	rb.ReadNext() // now startSeq=1, maxSeq=1

	// Nothing to drop — startSeq == maxSeq
	dropped := rb.DropTooLate(clock.Timestamp(2_000_000), dtFunc)
	if dropped != 0 {
		t.Errorf("DropTooLate with no reference: got %d, want 0", dropped)
	}
}

// --- nextPow2 tests ---

func TestNextPow2(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{0, 1},
		{1, 1},
		{2, 2},
		{3, 4},
		{4, 4},
		{5, 8},
		{7, 8},
		{8, 8},
		{9, 16},
		{100, 128},
		{1000, 1024},
		{8192, 8192},
	}

	for _, tt := range tests {
		got := nextPow2(tt.input)
		if got != tt.expected {
			t.Errorf("nextPow2(%d) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

// --- Benchmarks ---

func BenchmarkSendBufferPush(b *testing.B) {
	sb := NewSendBuffer(8192, seq.Number(0))
	p := packet.NewData(nil, 0, 0, 0, make([]byte, 1316))

	b.ResetTimer()
	for b.Loop() {
		sb.Push(p)
		sb.ACK(sb.NextSeq()) // keep space available
	}
}

func BenchmarkSendBufferACK(b *testing.B) {
	sb := NewSendBuffer(8192, seq.Number(0))

	// Fill buffer
	for i := range uint32(4096) {
		p := packet.NewData(nil, i, 0, 0, make([]byte, 1316))
		sb.Push(p)
	}

	b.ResetTimer()
	// ACK one at a time
	ackSeq := seq.Number(0)
	for b.Loop() {
		ackSeq = ackSeq.Inc()
		sb.ACK(ackSeq)
	}
}

func BenchmarkRecvBufferInsert(b *testing.B) {
	rb := NewRecvBuffer(8192, seq.Number(0))
	s := seq.Number(0)

	b.ResetTimer()
	for b.Loop() {
		p := packet.NewData(nil, s.Value(), 0, 0, make([]byte, 1316))
		rb.Insert(p, clock.Timestamp(0))
		rb.ReadNext() // consume to keep space
		s = s.Inc()
	}
}

func BenchmarkRecvBufferGenerateLossList(b *testing.B) {
	rb := NewRecvBuffer(8192, seq.Number(0))

	// Insert with 10% gap pattern
	for i := range uint32(1000) {
		if i%10 == 5 {
			continue // create gaps
		}
		p := packet.NewData(nil, i, 0, 0, []byte("x"))
		rb.Insert(p, clock.Timestamp(0))
	}

	b.ResetTimer()
	for b.Loop() {
		rb.GenerateLossList()
	}
}

func TestReadMessageTSBPDSinglePacket(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))

	// Insert a single-packet message
	p := packet.NewData(nil, 0, 1000, 0, []byte("hello"))
	p.Header.PacketPosition = packet.PositionSingle
	p.Header.MessageNumber = 1
	rb.Insert(p, clock.Timestamp(1000))

	deliveryTime := func(ts uint32) clock.Timestamp {
		return clock.Timestamp(ts) + 100 // 100us delivery delay
	}

	// Too early
	msgs, ok := rb.ReadMessageTSBPD(clock.Timestamp(1050), deliveryTime)
	if ok {
		t.Error("should not be ready yet")
	}
	if msgs != nil {
		t.Error("should return nil when not ready")
	}

	// Ready
	msgs, ok = rb.ReadMessageTSBPD(clock.Timestamp(1200), deliveryTime)
	if !ok {
		t.Error("message should be ready")
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(msgs))
	}
	if string(msgs[0].Data) != "hello" {
		t.Errorf("data: got %q, want %q", msgs[0].Data, "hello")
	}
	if msgs[0].Header.MessageNumber != 1 {
		t.Errorf("message number: got %d, want 1", msgs[0].Header.MessageNumber)
	}
}

func TestReadMessageTSBPDEmpty(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))

	deliveryTime := func(ts uint32) clock.Timestamp {
		return clock.Timestamp(ts) + 100
	}

	msgs, ok := rb.ReadMessageTSBPD(clock.Timestamp(99999), deliveryTime)
	if ok || msgs != nil {
		t.Error("empty buffer should return false")
	}
}

func TestRecvBufferReadMessageSingle(t *testing.T) {
	rb := NewRecvBuffer(16, seq.Number(1))

	// Insert a single-packet message (PP_SINGLE)
	p := packet.Packet{
		Header: packet.Header{
			SequenceNumber: 1,
			PacketPosition: packet.PositionSingle,
			MessageNumber:  100,
		},
		Data: []byte("hello"),
	}
	rb.Insert(p, 0)

	pkts, ok := rb.ReadMessage()
	if !ok {
		t.Fatal("ReadMessage should return true for single-packet message")
	}
	if len(pkts) != 1 {
		t.Fatalf("ReadMessage: got %d packets, want 1", len(pkts))
	}
	if string(pkts[0].Data) != "hello" {
		t.Errorf("ReadMessage data: got %q, want %q", pkts[0].Data, "hello")
	}
}

func TestRecvBufferReadMessageMultiPacket(t *testing.T) {
	rb := NewRecvBuffer(16, seq.Number(1))

	// Insert a 3-packet message: FIRST, MIDDLE, LAST
	msgNo := uint32(42)
	packets := []struct {
		seq  uint32
		pos  packet.PacketPosition
		data string
	}{
		{1, packet.PositionFirst, "AAA"},
		{2, packet.PositionMiddle, "BBB"},
		{3, packet.PositionLast, "CCC"},
	}

	for _, pp := range packets {
		p := packet.Packet{
			Header: packet.Header{
				SequenceNumber: pp.seq,
				PacketPosition: pp.pos,
				MessageNumber:  msgNo,
			},
			Data: []byte(pp.data),
		}
		rb.Insert(p, 0)
	}

	pkts, ok := rb.ReadMessage()
	if !ok {
		t.Fatal("ReadMessage should return true for complete multi-packet message")
	}
	if len(pkts) != 3 {
		t.Fatalf("ReadMessage: got %d packets, want 3", len(pkts))
	}

	// Verify data concatenation
	var combined []byte
	for _, p := range pkts {
		combined = append(combined, p.Data...)
	}
	if string(combined) != "AAABBBCCC" {
		t.Errorf("combined data: got %q, want %q", combined, "AAABBBCCC")
	}
}

func TestRecvBufferReadMessageIncomplete(t *testing.T) {
	rb := NewRecvBuffer(16, seq.Number(1))

	// Insert only FIRST packet (missing LAST)
	p := packet.Packet{
		Header: packet.Header{
			SequenceNumber: 1,
			PacketPosition: packet.PositionFirst,
			MessageNumber:  42,
		},
		Data: []byte("AAA"),
	}
	rb.Insert(p, 0)

	// Should not be readable yet (incomplete message)
	pkts, ok := rb.ReadMessage()
	if ok || pkts != nil {
		t.Error("ReadMessage should return false for incomplete message")
	}

	// Now insert the LAST packet
	p2 := packet.Packet{
		Header: packet.Header{
			SequenceNumber: 2,
			PacketPosition: packet.PositionLast,
			MessageNumber:  42,
		},
		Data: []byte("BBB"),
	}
	rb.Insert(p2, 0)

	// Now it should be readable
	pkts, ok = rb.ReadMessage()
	if !ok {
		t.Fatal("ReadMessage should return true after LAST packet arrives")
	}
	if len(pkts) != 2 {
		t.Fatalf("ReadMessage: got %d packets, want 2", len(pkts))
	}
}

// ---- DropExpiredTTL tests ----

func TestDropExpiredTTLBasic(t *testing.T) {
	sb := NewSendBuffer(64, seq.Number(0))

	// Push 5 packets at time 1000
	sentAt := clock.Timestamp(1000)
	for i := range uint32(5) {
		p := packet.NewData(nil, i, uint32(i*100), 0, []byte("ttl-data"))
		sb.Push(p, sentAt)
	}

	// Set per-message TTL on packets 1 and 3 (100ms = 100_000_000 ns)
	// We need to manipulate the entries directly since SetMsgTTL only
	// sets the last pushed packet.
	sb.mu.Lock()
	sb.entries[1&sb.mask].msgTTL = 100_000_000 // 100ms in ns
	sb.entries[3&sb.mask].msgTTL = 100_000_000 // 100ms in ns
	sb.mu.Unlock()

	// Before TTL expires (at 1000 + 50ms = 51_000us): nothing should be dropped
	now := clock.Timestamp(51_000) // 50ms after sentAt
	dropped := sb.DropExpiredTTL(now)
	if dropped != 0 {
		t.Errorf("DropExpiredTTL before expiry: got %d, want 0", dropped)
	}

	// After TTL expires (at 1000 + 101ms = 101_001us): packets 1 and 3 should drop
	// msgTTL is 100_000_000ns = 100_000us; sentAt=1000; elapsed must > msgTTL/1000 = 100_000
	now = clock.Timestamp(101_001) // 100_001us after sentAt (elapsed > 100_000)
	dropped = sb.DropExpiredTTL(now)
	if dropped != 2 {
		t.Errorf("DropExpiredTTL after expiry: got %d, want 2", dropped)
	}

	// Buffer should have 3 remaining packets (0, 2, 4)
	if sb.Size() != 3 {
		t.Errorf("Size after TTL drop: got %d, want 3", sb.Size())
	}
}

func TestDropExpiredTTLNoTTL(t *testing.T) {
	sb := NewSendBuffer(64, seq.Number(0))

	sentAt := clock.Timestamp(1000)
	for i := range uint32(5) {
		p := packet.NewData(nil, i, uint32(i*100), 0, []byte("no-ttl"))
		sb.Push(p, sentAt)
	}

	// No packets have TTL set — nothing should be dropped even after a long time
	now := clock.Timestamp(10_000_000) // 10 seconds later
	dropped := sb.DropExpiredTTL(now)
	if dropped != 0 {
		t.Errorf("DropExpiredTTL with no TTL: got %d, want 0", dropped)
	}
	if sb.Size() != 5 {
		t.Errorf("Size: got %d, want 5", sb.Size())
	}
}

func TestDropExpiredTTLAdvancesStartSeq(t *testing.T) {
	sb := NewSendBuffer(64, seq.Number(0))

	sentAt := clock.Timestamp(1000)
	for i := range uint32(4) {
		p := packet.NewData(nil, i, uint32(i*100), 0, []byte("data"))
		sb.Push(p, sentAt)
	}

	// Set TTL on the first two packets only
	sb.mu.Lock()
	sb.entries[0&sb.mask].msgTTL = 50_000_000 // 50ms
	sb.entries[1&sb.mask].msgTTL = 50_000_000 // 50ms
	sb.mu.Unlock()

	// Expire them
	now := clock.Timestamp(51_001) // > 50_000us after sentAt
	dropped := sb.DropExpiredTTL(now)
	if dropped != 2 {
		t.Errorf("DropExpiredTTL: got %d, want 2", dropped)
	}

	// StartSeq should advance past the dropped packets at the front
	if sb.StartSeq() != seq.Number(2) {
		t.Errorf("StartSeq: got %d, want 2", sb.StartSeq())
	}
}

func TestSetMsgTTL(t *testing.T) {
	sb := NewSendBuffer(64, seq.Number(0))

	p := packet.NewData(nil, 0, 100, 0, []byte("msg"))
	sb.Push(p, clock.Timestamp(1000))

	// SetMsgTTL should set TTL on the last pushed entry
	ttl := int64(200_000_000) // 200ms
	sb.SetMsgTTL(ttl)

	sb.mu.Lock()
	gotTTL := sb.entries[0&sb.mask].msgTTL
	sb.mu.Unlock()

	if gotTTL != ttl {
		t.Errorf("msgTTL: got %d, want %d", gotTTL, ttl)
	}
}

func TestSetMsgTTLEmpty(t *testing.T) {
	sb := NewSendBuffer(64, seq.Number(0))

	// SetMsgTTL on empty buffer should not panic
	sb.SetMsgTTL(100_000)
}

// ---- Out-of-Order Message Reading tests ----
// readMessage with out-of-order support.

// helper: creates a data packet with the given sequence, position, message number,
// and Order flag. Order=false means the packet can be read out of order.
func makeOOOPacket(seqno uint32, pos packet.PacketPosition, msgNo uint32, order bool, data string) packet.Packet {
	return packet.Packet{
		Header: packet.Header{
			SequenceNumber: seqno,
			PacketPosition: pos,
			MessageNumber:  msgNo,
			Order:          order,
		},
		Data: []byte(data),
	}
}

func TestReadMessageOOOSinglePacket(t *testing.T) {
	// A single-packet OOO message behind a gap should be readable.
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// Insert packet 0 (in-order, will be read first)
	p0 := makeOOOPacket(0, packet.PositionSingle, 1, true, "msg1")
	rb.Insert(p0, 0)

	// Skip seq 1 (gap), insert OOO single-packet message at seq 2
	p2 := makeOOOPacket(2, packet.PositionSingle, 2, false, "ooo-msg")
	rb.Insert(p2, 0)

	// Read the in-order message first
	pkts, ok := rb.ReadMessage()
	if !ok {
		t.Fatal("should read in-order message at seq 0")
	}
	if string(pkts[0].Data) != "msg1" {
		t.Errorf("data: got %q, want %q", pkts[0].Data, "msg1")
	}

	// Now startSeq=1 (gap). The OOO message at seq 2 should be readable.
	pkts, ok = rb.ReadMessage()
	if !ok {
		t.Fatal("should read OOO single-packet message at seq 2")
	}
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(pkts))
	}
	if string(pkts[0].Data) != "ooo-msg" {
		t.Errorf("data: got %q, want %q", pkts[0].Data, "ooo-msg")
	}

	// startSeq should NOT have advanced (OOO read doesn't advance it)
	if rb.StartSeq() != seq.Number(1) {
		t.Errorf("StartSeq: got %d, want 1 (OOO read should not advance)", rb.StartSeq())
	}
}

func TestReadMessageOOOMultiPacket(t *testing.T) {
	// A multi-packet OOO message (FIRST, MIDDLE, LAST) behind a gap.
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// Gap at seq 0. Insert 3-packet OOO message at seq 1-3.
	p1 := makeOOOPacket(1, packet.PositionFirst, 10, false, "AAA")
	p2 := makeOOOPacket(2, packet.PositionMiddle, 10, false, "BBB")
	p3 := makeOOOPacket(3, packet.PositionLast, 10, false, "CCC")

	// Insert packets (last packet triggers OOO detection)
	rb.Insert(p1, 0)
	rb.Insert(p2, 0)
	rb.Insert(p3, 0)

	// No in-order data (gap at 0), but OOO message is complete.
	pkts, ok := rb.ReadMessage()
	if !ok {
		t.Fatal("should read OOO multi-packet message")
	}
	if len(pkts) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(pkts))
	}

	var combined []byte
	for _, p := range pkts {
		combined = append(combined, p.Data...)
	}
	if string(combined) != "AAABBBCCC" {
		t.Errorf("combined data: got %q, want %q", combined, "AAABBBCCC")
	}

	// startSeq should still be 0 (gap not filled)
	if rb.StartSeq() != seq.Number(0) {
		t.Errorf("StartSeq: got %d, want 0", rb.StartSeq())
	}

	// Size should have decreased by 3
	if rb.Size() != 0 {
		t.Errorf("Size: got %d, want 0", rb.Size())
	}
}

func TestReadMessageOOOPreferInOrder(t *testing.T) {
	// When both in-order and OOO messages are available, prefer in-order.
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// In-order message at seq 0
	p0 := makeOOOPacket(0, packet.PositionSingle, 1, true, "inorder")
	rb.Insert(p0, 0)

	// Gap at seq 1, OOO message at seq 2
	p2 := makeOOOPacket(2, packet.PositionSingle, 2, false, "ooo")
	rb.Insert(p2, 0)

	// Should read in-order first
	pkts, ok := rb.ReadMessage()
	if !ok {
		t.Fatal("should read in-order message")
	}
	if string(pkts[0].Data) != "inorder" {
		t.Errorf("data: got %q, want %q", pkts[0].Data, "inorder")
	}

	// Now should read OOO
	pkts, ok = rb.ReadMessage()
	if !ok {
		t.Fatal("should read OOO message")
	}
	if string(pkts[0].Data) != "ooo" {
		t.Errorf("data: got %q, want %q", pkts[0].Data, "ooo")
	}
}

func TestReadMessageOOONoMessageAPIDisabled(t *testing.T) {
	// Without messageAPI enabled, OOO reading should not happen.
	rb := NewRecvBuffer(64, seq.Number(0))
	// messageAPI defaults to false

	// Gap at seq 0, OOO packet at seq 1
	p1 := makeOOOPacket(1, packet.PositionSingle, 1, false, "ooo")
	rb.Insert(p1, 0)

	// Should NOT be readable (no in-order data, messageAPI disabled)
	pkts, ok := rb.ReadMessage()
	if ok || pkts != nil {
		t.Error("should not read OOO when messageAPI is disabled")
	}
}

func TestReadMessageOOODoesNotAdvanceStartSeq(t *testing.T) {
	// Verify that OOO reads mark entries as Read but don't advance startSeq.
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// Gap at seq 0, two OOO messages at seq 1 and seq 2
	p1 := makeOOOPacket(1, packet.PositionSingle, 10, false, "ooo1")
	p2 := makeOOOPacket(2, packet.PositionSingle, 11, false, "ooo2")
	rb.Insert(p1, 0)
	rb.Insert(p2, 0)

	// Read first OOO message
	pkts, ok := rb.ReadMessage()
	if !ok {
		t.Fatal("should read first OOO message")
	}
	if string(pkts[0].Data) != "ooo1" {
		t.Errorf("data: got %q, want %q", pkts[0].Data, "ooo1")
	}
	if rb.StartSeq() != seq.Number(0) {
		t.Errorf("StartSeq: got %d, want 0 after first OOO read", rb.StartSeq())
	}

	// Read second OOO message
	pkts, ok = rb.ReadMessage()
	if !ok {
		t.Fatal("should read second OOO message")
	}
	if string(pkts[0].Data) != "ooo2" {
		t.Errorf("data: got %q, want %q", pkts[0].Data, "ooo2")
	}
	if rb.StartSeq() != seq.Number(0) {
		t.Errorf("StartSeq: got %d, want 0 after second OOO read", rb.StartSeq())
	}

	// No more readable messages
	pkts, ok = rb.ReadMessage()
	if ok || pkts != nil {
		t.Error("should have no more messages")
	}
}

func TestReadMessageOOOGapFilledAfterOOORead(t *testing.T) {
	// After reading OOO messages, filling the gap should advance startSeq
	// past the Read entries.
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// Gap at seq 0, OOO message at seq 1
	p1 := makeOOOPacket(1, packet.PositionSingle, 10, false, "ooo")
	rb.Insert(p1, 0)

	// Read OOO message
	pkts, ok := rb.ReadMessage()
	if !ok {
		t.Fatal("should read OOO message")
	}
	if string(pkts[0].Data) != "ooo" {
		t.Errorf("data: got %q, want %q", pkts[0].Data, "ooo")
	}
	if rb.StartSeq() != seq.Number(0) {
		t.Errorf("StartSeq: got %d, want 0", rb.StartSeq())
	}

	// Now fill the gap at seq 0
	p0 := makeOOOPacket(0, packet.PositionSingle, 9, true, "gap-fill")
	rb.Insert(p0, 0)

	// Read the gap-fill message (in-order)
	pkts, ok = rb.ReadMessage()
	if !ok {
		t.Fatal("should read gap-fill message")
	}
	if string(pkts[0].Data) != "gap-fill" {
		t.Errorf("data: got %q, want %q", pkts[0].Data, "gap-fill")
	}

	// startSeq should advance past both seq 0 (just read) and seq 1 (EntryRead from OOO)
	if rb.StartSeq() != seq.Number(2) {
		t.Errorf("StartSeq: got %d, want 2 (should skip past Read entries)", rb.StartSeq())
	}
}

func TestReadMessageOOOIncompleteNotReadable(t *testing.T) {
	// An incomplete OOO multi-packet message should not be readable.
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// Gap at seq 0. Insert only FIRST of a multi-packet OOO message at seq 1.
	p1 := makeOOOPacket(1, packet.PositionFirst, 10, false, "AAA")
	rb.Insert(p1, 0)

	// Should not be readable (message incomplete — no LAST)
	pkts, ok := rb.ReadMessage()
	if ok || pkts != nil {
		t.Error("incomplete OOO message should not be readable")
	}

	// Now add the LAST packet
	p2 := makeOOOPacket(2, packet.PositionLast, 10, false, "BBB")
	rb.Insert(p2, 0)

	// Now it should be readable
	pkts, ok = rb.ReadMessage()
	if !ok {
		t.Fatal("complete OOO message should be readable after LAST arrives")
	}
	if len(pkts) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(pkts))
	}
}

func TestReadMessageOOOWithOrderFlagTrue(t *testing.T) {
	// Packets with Order=true should NOT be readable out of order,
	// even if they form a complete message behind a gap.
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// Gap at seq 0. Message at seq 1 with Order=true.
	p1 := makeOOOPacket(1, packet.PositionSingle, 10, true, "ordered")
	rb.Insert(p1, 0)

	// Should not be readable (Order=true packets require in-order delivery)
	pkts, ok := rb.ReadMessage()
	if ok || pkts != nil {
		t.Error("Order=true packets should not be readable out of order")
	}
}

func TestHasAvailablePackets(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// Empty buffer
	if rb.HasAvailablePackets() {
		t.Error("empty buffer should have no available packets")
	}

	// Gap at seq 0, OOO message at seq 1
	p1 := makeOOOPacket(1, packet.PositionSingle, 10, false, "ooo")
	rb.Insert(p1, 0)

	if !rb.HasAvailablePackets() {
		t.Error("should have available packets (OOO message)")
	}

	// Read the OOO message
	rb.ReadMessage()

	if rb.HasAvailablePackets() {
		t.Error("should have no available packets after reading OOO")
	}
}

func TestReadMessageOOODropResetsOOOState(t *testing.T) {
	// After Drop, rescan OOO state.
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// Insert OOO messages at seq 1 and seq 3 (gaps at 0 and 2)
	p1 := makeOOOPacket(1, packet.PositionSingle, 10, false, "ooo1")
	p3 := makeOOOPacket(3, packet.PositionSingle, 11, false, "ooo2")
	rb.Insert(p1, 0)
	rb.Insert(p3, 0)

	// Drop up to seq 2 (drops the gap at 0 and the OOO packet at 1)
	rb.Drop(seq.Number(2))

	// StartSeq should now be 2 (gap at 2)
	if rb.StartSeq() != seq.Number(2) {
		t.Errorf("StartSeq after drop: got %d, want 2", rb.StartSeq())
	}

	// The OOO message at seq 3 should still be readable
	pkts, ok := rb.ReadMessage()
	if !ok {
		t.Fatal("OOO message at seq 3 should be readable after drop")
	}
	if string(pkts[0].Data) != "ooo2" {
		t.Errorf("data: got %q, want %q", pkts[0].Data, "ooo2")
	}
}

func TestReadMessageOOOMultipleOOOMessages(t *testing.T) {
	// Multiple OOO messages: should read the earliest one first.
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// Gap at seq 0.
	// OOO message 1 at seq 1-2 (FIRST, LAST)
	// OOO message 2 at seq 3-4 (FIRST, LAST)
	rb.Insert(makeOOOPacket(1, packet.PositionFirst, 10, false, "A1"), 0)
	rb.Insert(makeOOOPacket(2, packet.PositionLast, 10, false, "A2"), 0)
	rb.Insert(makeOOOPacket(3, packet.PositionFirst, 11, false, "B1"), 0)
	rb.Insert(makeOOOPacket(4, packet.PositionLast, 11, false, "B2"), 0)

	// First read should get message 10 (earliest OOO)
	pkts, ok := rb.ReadMessage()
	if !ok {
		t.Fatal("should read first OOO message")
	}
	if len(pkts) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(pkts))
	}
	if string(pkts[0].Data) != "A1" || string(pkts[1].Data) != "A2" {
		t.Errorf("unexpected data in first OOO read")
	}

	// Second read should get message 11
	pkts, ok = rb.ReadMessage()
	if !ok {
		t.Fatal("should read second OOO message")
	}
	if len(pkts) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(pkts))
	}
	if string(pkts[0].Data) != "B1" || string(pkts[1].Data) != "B2" {
		t.Errorf("unexpected data in second OOO read")
	}

	// No more
	pkts, ok = rb.ReadMessage()
	if ok || pkts != nil {
		t.Error("should have no more messages")
	}
}

func TestReadMessageOOOLastPacketArrivesTriggersScan(t *testing.T) {
	// Insert FIRST packet first, then LAST. The LAST arrival should trigger
	// onInsertNotInOrderPacket to scan left and find the complete message.
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// Gap at seq 0.
	rb.Insert(makeOOOPacket(1, packet.PositionFirst, 10, false, "F"), 0)
	// At this point, no complete OOO message yet.
	if rb.HasAvailablePackets() {
		t.Error("incomplete message should not be available")
	}

	rb.Insert(makeOOOPacket(2, packet.PositionLast, 10, false, "L"), 0)
	// Now the message is complete.
	if !rb.HasAvailablePackets() {
		t.Error("complete OOO message should be available")
	}

	pkts, ok := rb.ReadMessage()
	if !ok {
		t.Fatal("should read the complete OOO message")
	}
	if len(pkts) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(pkts))
	}
}

func TestReadMessageOOOFirstPacketArrivesTriggersScan(t *testing.T) {
	// Insert LAST packet first, then FIRST. The FIRST arrival should trigger
	// onInsertNotInOrderPacket to scan right and find the complete message.
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// Gap at seq 0.
	rb.Insert(makeOOOPacket(2, packet.PositionLast, 10, false, "L"), 0)
	// At this point, no complete OOO message yet.
	if rb.HasAvailablePackets() {
		t.Error("incomplete message should not be available")
	}

	rb.Insert(makeOOOPacket(1, packet.PositionFirst, 10, false, "F"), 0)
	// Now the message is complete.
	if !rb.HasAvailablePackets() {
		t.Error("complete OOO message should be available")
	}

	pkts, ok := rb.ReadMessage()
	if !ok {
		t.Fatal("should read the complete OOO message")
	}
	if len(pkts) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(pkts))
	}
	if string(pkts[0].Data) != "F" || string(pkts[1].Data) != "L" {
		t.Errorf("unexpected data order: %q, %q", pkts[0].Data, pkts[1].Data)
	}
}

func TestReadMessageOOOAfterInOrderExhausted(t *testing.T) {
	// After reading all in-order packets,
	// updateFirstReadableOutOfOrder should find OOO messages.
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// In-order messages at seq 0 and seq 1
	rb.Insert(makeOOOPacket(0, packet.PositionSingle, 1, true, "io1"), 0)
	rb.Insert(makeOOOPacket(1, packet.PositionSingle, 2, true, "io2"), 0)

	// Gap at seq 2, OOO message at seq 3
	rb.Insert(makeOOOPacket(3, packet.PositionSingle, 3, false, "ooo"), 0)

	// Read in-order messages
	pkts, ok := rb.ReadMessage()
	if !ok || string(pkts[0].Data) != "io1" {
		t.Fatal("should read io1")
	}
	pkts, ok = rb.ReadMessage()
	if !ok || string(pkts[0].Data) != "io2" {
		t.Fatal("should read io2")
	}

	// Now in-order is exhausted (gap at seq 2). OOO should be available.
	pkts, ok = rb.ReadMessage()
	if !ok {
		t.Fatal("should read OOO message after in-order exhausted")
	}
	if string(pkts[0].Data) != "ooo" {
		t.Errorf("data: got %q, want %q", pkts[0].Data, "ooo")
	}
}

func TestReadMessageOOONumOutOfOrderPktsCounter(t *testing.T) {
	// Verify the numOutOfOrderPkts counter is properly maintained.
	rb := NewRecvBuffer(64, seq.Number(0))
	rb.SetMessageAPI(true)

	// Insert 3 OOO packets
	rb.Insert(makeOOOPacket(1, packet.PositionSingle, 10, false, "a"), 0)
	rb.Insert(makeOOOPacket(2, packet.PositionSingle, 11, false, "b"), 0)
	rb.Insert(makeOOOPacket(3, packet.PositionSingle, 12, false, "c"), 0)

	rb.mu.Lock()
	if rb.numOutOfOrderPkts != 3 {
		t.Errorf("numOutOfOrderPkts after insert: got %d, want 3", rb.numOutOfOrderPkts)
	}
	rb.mu.Unlock()

	// Read one OOO message
	rb.ReadMessage()

	rb.mu.Lock()
	if rb.numOutOfOrderPkts != 2 {
		t.Errorf("numOutOfOrderPkts after 1 read: got %d, want 2", rb.numOutOfOrderPkts)
	}
	rb.mu.Unlock()

	// Drop up to seq 3 (drops seq 0 gap + OOO at seq 2)
	rb.Drop(seq.Number(3))

	rb.mu.Lock()
	if rb.numOutOfOrderPkts != 1 {
		t.Errorf("numOutOfOrderPkts after drop: got %d, want 1", rb.numOutOfOrderPkts)
	}
	rb.mu.Unlock()
}

// --- RecvBuffer IsEmpty and SetInitialRcvSeq tests ---

func TestRecvBufferIsEmpty(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(100))

	if !rb.IsEmpty() {
		t.Error("new buffer should be empty")
	}

	// Insert a packet.
	p := packet.NewData(nil, 100, 1000, 0, []byte("data"))
	rb.Insert(p, clock.Timestamp(1000))

	if rb.IsEmpty() {
		t.Error("buffer should not be empty after insert")
	}

	// Read it out.
	_, ok := rb.ReadNext()
	if !ok {
		t.Fatal("ReadNext should succeed")
	}

	if !rb.IsEmpty() {
		t.Error("buffer should be empty after reading")
	}
}

func TestRecvBufferSetInitialRcvSeq(t *testing.T) {
	rb := NewRecvBuffer(64, seq.Number(100))

	// Insert some packets.
	for i := uint32(0); i < 5; i++ {
		p := packet.NewData(nil, 100+i, (100+i)*1000, 0, []byte("data"))
		rb.Insert(p, clock.Timestamp(1000+clock.Timestamp(i)))
	}

	if rb.Size() != 5 {
		t.Fatalf("Size before reset: got %d, want 5", rb.Size())
	}

	// Reset to a new ISN.
	rb.SetInitialRcvSeq(seq.Number(200))

	if rb.Size() != 0 {
		t.Errorf("Size after reset: got %d, want 0", rb.Size())
	}
	if rb.StartSeq() != seq.Number(200) {
		t.Errorf("StartSeq after reset: got %d, want 200", rb.StartSeq())
	}
	if rb.MaxSeq() != seq.Number(200) {
		t.Errorf("MaxSeq after reset: got %d, want 200", rb.MaxSeq())
	}
	if !rb.IsEmpty() {
		t.Error("buffer should be empty after reset")
	}

	// Should be able to insert at the new position.
	p := packet.NewData(nil, 200, 2000, 0, []byte("new"))
	rb.Insert(p, clock.Timestamp(5000))

	if rb.Size() != 1 {
		t.Errorf("Size after insert at new pos: got %d, want 1", rb.Size())
	}
}
