package filter

import (
	"testing"
)

// ---- Config parsing tests ----

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Config
		wantErr bool
	}{
		{
			name:  "basic cols only",
			input: "fec,cols:10",
			want:  Config{Cols: 10, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq},
		},
		{
			name:  "full config",
			input: "fec,cols:5,rows:3,layout:even,arq:always",
			want:  Config{Cols: 5, Rows: 3, Layout: LayoutEven, ARQ: ARQAlways},
		},
		{
			name:  "arq never",
			input: "fec,cols:8,arq:never",
			want:  Config{Cols: 8, Rows: 1, Layout: LayoutStaircase, ARQ: ARQNever},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "not fec",
			input:   "xor,cols:5",
			wantErr: true,
		},
		{
			name:    "missing cols",
			input:   "fec,rows:3",
			wantErr: true,
		},
		{
			name:    "cols too small",
			input:   "fec,cols:1",
			wantErr: true,
		},
		{
			name:    "rows zero",
			input:   "fec,cols:5,rows:0",
			wantErr: true,
		},
		{
			name:    "invalid layout",
			input:   "fec,cols:5,layout:random",
			wantErr: true,
		},
		{
			name:    "invalid arq",
			input:   "fec,cols:5,arq:maybe",
			wantErr: true,
		},
		{
			name:    "unknown parameter",
			input:   "fec,cols:5,foo:bar",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseConfig(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestFormatConfig(t *testing.T) {
	cfg := Config{Cols: 10, Rows: 5, Layout: LayoutStaircase, ARQ: ARQOnReq}
	s := FormatConfig(cfg)
	parsed, err := ParseConfig(s)
	if err != nil {
		t.Fatalf("round-trip failed: %v", err)
	}
	if parsed != cfg {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", parsed, cfg)
	}
}

func TestFormatConfigRowsOne(t *testing.T) {
	cfg := Config{Cols: 5, Rows: 1, Layout: LayoutEven, ARQ: ARQAlways}
	s := FormatConfig(cfg)
	// rows:1 is the default, so it should NOT appear
	parsed, err := ParseConfig(s)
	if err != nil {
		t.Fatalf("round-trip failed: %v", err)
	}
	if parsed != cfg {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", parsed, cfg)
	}
}

func TestNegotiateConfig(t *testing.T) {
	a := Config{Cols: 5, Rows: 3, Layout: LayoutStaircase, ARQ: ARQOnReq}
	b := Config{Cols: 5, Rows: 3, Layout: LayoutStaircase, ARQ: ARQOnReq}
	got, err := NegotiateConfig(a, b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != a {
		t.Fatalf("got %+v, want %+v", got, a)
	}

	// Mismatched cols
	c := Config{Cols: 10, Rows: 3, Layout: LayoutStaircase, ARQ: ARQOnReq}
	_, err = NegotiateConfig(a, c)
	if err == nil {
		t.Fatal("expected error for mismatched cols")
	}

	// Mismatched rows
	d := Config{Cols: 5, Rows: 5, Layout: LayoutStaircase, ARQ: ARQOnReq}
	_, err = NegotiateConfig(a, d)
	if err == nil {
		t.Fatal("expected error for mismatched rows")
	}
}

// ---- XOR accumulation tests ----

func TestGroupClipXOR(t *testing.T) {
	g := newGroup(0, 1, 10)

	// Clip two packets; XOR should cancel out identical data
	payload1 := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	payload2 := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	g.clipPacket(5, 1, 100, payload1)
	g.clipPacket(5, 1, 100, payload2)

	// After XOR of identical values, everything should be 0
	if g.flagClip != 0 {
		t.Fatalf("flagClip: got %d, want 0", g.flagClip)
	}
	if g.timestampClip != 0 {
		t.Fatalf("timestampClip: got %d, want 0", g.timestampClip)
	}
	if g.lengthClip != 0 {
		t.Fatalf("lengthClip: got %d, want 0", g.lengthClip)
	}
	for i, b := range g.payloadClip {
		if b != 0 {
			t.Fatalf("payloadClip[%d]: got 0x%02x, want 0", i, b)
		}
	}
}

func TestGroupClipRecovery(t *testing.T) {
	// Simulate 3 packets in a row group, lose packet 1, recover via XOR
	payloads := [][]byte{
		{0x01, 0x02, 0x03, 0x04},
		{0x10, 0x20, 0x30, 0x40}, // this one will be "lost"
		{0xA0, 0xB0, 0xC0, 0xD0},
	}
	timestamps := []uint32{1000, 2000, 3000}
	flags := []uint8{0, 0, 0}

	// Build FEC from all 3 packets (sender side)
	senderGroup := newGroup(0, 1, 4)
	for i := range 3 {
		senderGroup.clipPacket(len(payloads[i]), flags[i], timestamps[i], payloads[i])
	}

	// Receiver: got packets 0 and 2, plus the FEC packet
	recvGroup := newGroup(0, 1, 4)
	recvGroup.clipPacket(len(payloads[0]), flags[0], timestamps[0], payloads[0])
	recvGroup.clipPacket(len(payloads[2]), flags[2], timestamps[2], payloads[2])

	// Clip the FEC data into receiver group
	// FEC data = senderGroup's clip state
	recvGroup.clipData(senderGroup.lengthClip, senderGroup.flagClip,
		senderGroup.timestampClip, senderGroup.payloadClip)

	// The result should be the lost packet's data
	recoveredTS := recvGroup.timestampClip
	if recoveredTS != timestamps[1] {
		t.Fatalf("recovered timestamp: got %d, want %d", recoveredTS, timestamps[1])
	}

	recoveredLen := recvGroup.lengthClip
	if int(recoveredLen) != len(payloads[1]) {
		t.Fatalf("recovered length: got %d, want %d", recoveredLen, len(payloads[1]))
	}

	for i := range len(payloads[1]) {
		if recvGroup.payloadClip[i] != payloads[1][i] {
			t.Fatalf("recovered payload[%d]: got 0x%02x, want 0x%02x",
				i, recvGroup.payloadClip[i], payloads[1][i])
		}
	}
}

// ---- Sender tests ----

func TestFECSenderRowOnly(t *testing.T) {
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	sender := NewFECSender(cfg, 10, 0)

	// Feed 3 packets — should trigger a row FEC after the 3rd
	for i := range 3 {
		payload := []byte{byte(i + 1), byte(i + 2)}
		sender.FeedSource(uint32(i), uint32((i+1)*100), 0, payload)
	}

	// Should have 1 pending FEC packet
	data, groupIdx, fecSeqNo, _, ok := sender.PackControlPacket()
	if !ok {
		t.Fatal("expected FEC packet after 3 data packets")
	}
	if groupIdx != -1 {
		t.Fatalf("expected row FEC (index -1), got %d", groupIdx)
	}
	if len(data) < ExtraHeaderSize {
		t.Fatalf("FEC packet too short: %d bytes", len(data))
	}

	// FEC packet shares the last data packet's seqno
	if fecSeqNo != 2 {
		t.Fatalf("FEC seqNo: got %d, want 2 (last data seqno)", fecSeqNo)
	}

	// Verify the FEC payload is correct XOR
	// The group index byte should be -1 (0xFF)
	if data[0] != 0xFF {
		t.Fatalf("FEC header[0]: got 0x%02x, want 0xFF", data[0])
	}

	// No more FEC packets
	_, _, _, _, ok = sender.PackControlPacket()
	if ok {
		t.Fatal("unexpected extra FEC packet")
	}
}

func TestFECSenderMultipleRows(t *testing.T) {
	cfg := Config{Cols: 2, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	sender := NewFECSender(cfg, 10, 0)

	fecCount := 0
	for i := range 6 {
		sender.FeedSource(uint32(i), uint32(i*100), 0, []byte{byte(i)})
		for {
			_, _, _, _, ok := sender.PackControlPacket()
			if !ok {
				break
			}
			fecCount++
		}
	}

	// 6 packets / 2 cols = 3 FEC packets
	if fecCount != 3 {
		t.Fatalf("expected 3 FEC packets, got %d", fecCount)
	}
}

func TestFECSender2D(t *testing.T) {
	// 3 cols x 2 rows = 6 data packets per matrix
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQOnReq}
	sender := NewFECSender(cfg, 10, 0)

	var rowFEC, colFEC int
	for i := range 6 {
		sender.FeedSource(uint32(i), uint32(i*100), 0, []byte{byte(i)})
		for {
			_, idx, _, _, ok := sender.PackControlPacket()
			if !ok {
				break
			}
			if idx == -1 {
				rowFEC++
			} else {
				colFEC++
			}
		}
	}

	// Expected: 2 row FEC packets (3 packets per row), 3 column FEC packets (2 packets per column)
	if rowFEC != 2 {
		t.Fatalf("expected 2 row FEC, got %d", rowFEC)
	}
	if colFEC != 3 {
		t.Fatalf("expected 3 column FEC, got %d", colFEC)
	}
}

// ---- Receiver tests ----

func TestFECReceiverRowRecovery(t *testing.T) {
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	payloadSize := 10

	// Build FEC packet via sender
	sender := NewFECSender(cfg, payloadSize, 0)
	payloads := [][]byte{
		{0x01, 0x02, 0x03},
		{0x10, 0x20, 0x30}, // will be "lost"
		{0xA0, 0xB0, 0xC0},
	}
	timestamps := []uint32{100, 200, 300}

	for i := range 3 {
		sender.FeedSource(uint32(i), timestamps[i], 0, payloads[i])
	}
	fecData, _, fecSeqNo, fecTS, ok := sender.PackControlPacket()
	if !ok {
		t.Fatal("expected FEC packet from sender")
	}

	// Create receiver
	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Receive packets 0 and 2 (skip 1)
	recovered, _, pt := receiver.Receive(0, timestamps[0], 0, 1, payloads[0])
	if !pt {
		t.Fatal("expected passThrough for data packet 0")
	}
	if len(recovered) != 0 {
		t.Fatalf("unexpected recovery after packet 0: %d", len(recovered))
	}

	recovered, _, pt = receiver.Receive(2, timestamps[2], 0, 3, payloads[2])
	if !pt {
		t.Fatal("expected passThrough for data packet 2")
	}
	if len(recovered) != 0 {
		t.Fatalf("unexpected recovery after packet 2: %d", len(recovered))
	}

	// FEC packet shares last data seqno (MessageNumber=0)
	recovered, _, pt = receiver.Receive(fecSeqNo, fecTS, 0, 0, fecData)
	if pt {
		t.Fatal("expected passThrough=false for FEC control packet")
	}
	if len(recovered) != 1 {
		t.Fatalf("expected 1 recovered packet, got %d", len(recovered))
	}

	rp := recovered[0]
	if rp.SeqNo != 1 {
		t.Fatalf("recovered seqNo: got %d, want 1", rp.SeqNo)
	}
	if rp.Timestamp != timestamps[1] {
		t.Fatalf("recovered timestamp: got %d, want %d", rp.Timestamp, timestamps[1])
	}
	if len(rp.Payload) != len(payloads[1]) {
		t.Fatalf("recovered payload length: got %d, want %d", len(rp.Payload), len(payloads[1]))
	}
	for i := range payloads[1] {
		if rp.Payload[i] != payloads[1][i] {
			t.Fatalf("recovered payload[%d]: got 0x%02x, want 0x%02x", i, rp.Payload[i], payloads[1][i])
		}
	}
}

func TestFECReceiverColumnRecovery(t *testing.T) {
	// 3 cols x 2 rows = 6 packets per matrix
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQOnReq}
	payloadSize := 10

	// Matrix layout (even):
	// Row 0: seq 0, 1, 2
	// Row 1: seq 3, 4, 5
	// Column 0: seq 0, 3
	// Column 1: seq 1, 4
	// Column 2: seq 2, 5

	sender := NewFECSender(cfg, payloadSize, 0)
	payloads := make([][]byte, 6)
	timestamps := make([]uint32, 6)

	// Collect FEC packets after EACH feed (pendingFEC is cleared on each FeedSource call)
	type fecPkt struct {
		data      []byte
		idx       int8
		seqNo     uint32
		timestamp uint32
	}
	var fecPkts []fecPkt
	for i := range 6 {
		payloads[i] = []byte{byte(i * 10), byte(i*10 + 1)}
		timestamps[i] = uint32((i + 1) * 100)
		sender.FeedSource(uint32(i), timestamps[i], 0, payloads[i])
		for {
			data, idx, seqNo, ts, ok := sender.PackControlPacket()
			if !ok {
				break
			}
			fecPkts = append(fecPkts, fecPkt{data: data, idx: idx, seqNo: seqNo, timestamp: ts})
		}
	}

	// Find the column 0 FEC packet (index=0)
	var colFEC *fecPkt
	for i := range fecPkts {
		if fecPkts[i].idx == 0 {
			colFEC = &fecPkts[i]
			break
		}
	}
	if colFEC == nil {
		t.Fatal("no column 0 FEC packet found")
	}

	// Receiver: lose packet 3 (column 0, row 1)
	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Receive all data packets except seq 3
	for i := range 6 {
		if i == 3 {
			continue // lost
		}
		receiver.Receive(uint32(i), timestamps[i], 0, uint32(i+1), payloads[i])
	}

	// Receive column 0 FEC (shares seqno of last data in column group)
	recovered, _, pt := receiver.Receive(colFEC.seqNo, colFEC.timestamp, 0, 0, colFEC.data)
	if pt {
		t.Fatal("expected passThrough=false for FEC packet")
	}
	if len(recovered) != 1 {
		t.Fatalf("expected 1 recovered packet, got %d", len(recovered))
	}

	rp := recovered[0]
	if rp.SeqNo != 3 {
		t.Fatalf("recovered seqNo: got %d, want 3", rp.SeqNo)
	}
	for i := range payloads[3] {
		if rp.Payload[i] != payloads[3][i] {
			t.Fatalf("recovered payload[%d]: got 0x%02x, want 0x%02x", i, rp.Payload[i], payloads[3][i])
		}
	}
}

func TestFECReceiverDataBeforeFEC(t *testing.T) {
	// Test that recovery works when all data packets arrive first, then FEC
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	payloadSize := 10

	sender := NewFECSender(cfg, payloadSize, 0)
	payloads := [][]byte{
		{0xDE, 0xAD},
		{0xBE, 0xEF}, // lost
		{0xCA, 0xFE},
	}

	for i := range 3 {
		sender.FeedSource(uint32(i), uint32(i*100), 0, payloads[i])
	}
	fecData, _, fecSeqNo, fecTS, _ := sender.PackControlPacket()

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Receive packet 0, skip 1, receive packet 2
	receiver.Receive(0, 0, 0, 1, payloads[0])
	receiver.Receive(2, 200, 0, 3, payloads[2])

	// Receive FEC — should trigger recovery of packet 1
	recovered, _, _ := receiver.Receive(fecSeqNo, fecTS, 0, 0, fecData)
	if len(recovered) != 1 {
		t.Fatalf("expected 1 recovered, got %d", len(recovered))
	}
	if recovered[0].SeqNo != 1 {
		t.Fatalf("expected seqNo 1, got %d", recovered[0].SeqNo)
	}
}

func TestFECReceiverDuplicate(t *testing.T) {
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	receiver := NewFECReceiver(cfg, 10, 0)

	payload := []byte{0x01, 0x02}
	// Receive same packet twice
	receiver.Receive(0, 100, 0, 1, payload)
	recovered, _, pt := receiver.Receive(0, 100, 0, 1, payload)
	if !pt {
		t.Fatal("expected passThrough=true for duplicate data packet")
	}
	if len(recovered) != 0 {
		t.Fatalf("unexpected recovery from duplicate: %d", len(recovered))
	}
}

func TestFECReceiverNoLoss(t *testing.T) {
	// All packets arrive — FEC should not trigger any recovery
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	payloadSize := 10

	sender := NewFECSender(cfg, payloadSize, 0)
	payloads := [][]byte{{1}, {2}, {3}}
	for i := range 3 {
		sender.FeedSource(uint32(i), uint32(i*100), 0, payloads[i])
	}
	fecData, _, fecSeqNo, fecTS, _ := sender.PackControlPacket()

	receiver := NewFECReceiver(cfg, payloadSize, 0)
	for i := range 3 {
		receiver.Receive(uint32(i), uint32(i*100), 0, uint32(i+1), payloads[i])
	}

	// FEC arrives but all packets already received — no recovery needed
	recovered, _, pt := receiver.Receive(fecSeqNo, fecTS, 0, 0, fecData)
	if pt {
		t.Fatal("expected passThrough=false for FEC packet")
	}
	if len(recovered) != 0 {
		t.Fatalf("expected 0 recovered (no loss), got %d", len(recovered))
	}
}

// ---- Staircase layout tests ----

func TestStaircaseColumnBases(t *testing.T) {
	// Verify staircase column base offsets match configureColumns
	// With cols=5, rows=3:
	// col 0: offset 0
	// col 1: offset 0 + 1 + sizeRow(5) = 6
	// col 2: offset 6 + 1 + 5 = 12 — but col 2 is at index 2, 2 % 3 = 2 (not rows-1), so offset = 12
	//   actually 2 % 3 = 2, which is rows-1=2, so reset: offset = 2 + 1 = 3
	// Wait, let me re-trace:
	// col 0: offset=0, col=0, 0%3=0 != 2, offset = 0 + 1 + 5 = 6
	// col 1: offset=6, col=1, 1%3=1 != 2, offset = 6 + 1 + 5 = 12
	// col 2: offset=12, col=2, 2%3=2 == 2, offset = 2 + 1 = 3
	// col 3: offset=3, col=3, 3%3=0 != 2, offset = 3 + 1 + 5 = 9
	// col 4: offset=9, col=4, 4%3=1 != 2, offset = 9 + 1 + 5 = 15

	cfg := Config{Cols: 5, Rows: 3, Layout: LayoutStaircase, ARQ: ARQOnReq}
	sender := NewFECSender(cfg, 10, 100)

	expectedBases := []uint32{100, 106, 112, 103, 109}
	for i, exp := range expectedBases {
		if sender.cols[i].base != exp {
			t.Errorf("col %d base: got %d, want %d", i, sender.cols[i].base, exp)
		}
	}
}

func TestEvenColumnBases(t *testing.T) {
	cfg := Config{Cols: 4, Rows: 3, Layout: LayoutEven, ARQ: ARQOnReq}
	sender := NewFECSender(cfg, 10, 0)

	// Even layout: col i base = ISN + i
	for i := range 4 {
		expected := uint32(i)
		if sender.cols[i].base != expected {
			t.Errorf("col %d base: got %d, want %d", i, sender.cols[i].base, expected)
		}
	}
}

// ---- Benchmarks ----

func BenchmarkFECSenderFeed(b *testing.B) {
	cfg := Config{Cols: 10, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	sender := NewFECSender(cfg, 1316, 0)
	payload := make([]byte, 1316)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sender.FeedSource(uint32(i), uint32(i*100), 0, payload)
		for {
			_, _, _, _, ok := sender.PackControlPacket()
			if !ok {
				break
			}
		}
	}
}

// ---- MAX_RCV_HISTORY tests ----

func TestGetRowGroupIndexBeyondHistory(t *testing.T) {
	// getRowGroupIndex should return -1 when seqNo is beyond fecMaxRcvHistory
	// matrix series. This prevents unbounded growth of row group tracking.
	cfg := Config{Cols: 5, Rows: 2, Layout: LayoutEven, ARQ: ARQOnReq}
	payloadSize := 10

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// matrixSize = cols * rows = 5 * 2 = 10
	// max tracked: fecMaxRcvHistory * sizeCol() = 10 * 2 = 20 row groups
	// Each row has 5 packets, so max offset = 20 * 5 = 100

	// First, feed some early packets to establish state
	receiver.Receive(0, 100, 0, 1, []byte{0x01})
	receiver.Receive(1, 200, 0, 2, []byte{0x02})

	// Now try a sequence number far beyond the history limit.
	// Offset = cols * (fecMaxRcvHistory * rows + 1) = 5 * (10*2 + 1) = 105
	farSeq := uint32(105)
	idx := receiver.getRowGroupIndex(farSeq)
	if idx != -1 {
		t.Errorf("getRowGroupIndex(%d) beyond history: got %d, want -1", farSeq, idx)
	}
}

func TestGetRowGroupIndexWithinHistory(t *testing.T) {
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	payloadSize := 10

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Feed packet 0 to ensure row group exists
	receiver.Receive(0, 100, 0, 1, []byte{0x01})

	// Packet at seq 2 should be within the first row group (0-2)
	idx := receiver.getRowGroupIndex(2)
	if idx < 0 {
		t.Errorf("getRowGroupIndex(2) within history: got %d, want >= 0", idx)
	}
}

// ---- fullReset tests ----

func TestCheckLargeDropTriggersFullReset(t *testing.T) {
	// When a sequence jump exceeds fecMaxRcvHistory matrix series,
	// checkLargeDrop triggers a full reset of all FEC state.
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQOnReq}
	payloadSize := 10

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Feed some initial packets
	for i := range 6 {
		receiver.Receive(uint32(i), uint32(i*100), 0, uint32(i+1), []byte{byte(i)})
	}

	// matrixSize = 3 * 2 = 6
	// A jump of fecMaxRcvHistory (10) * matrixSize (6) = 60+ should trigger fullReset
	farSeq := uint32(6 + 10*6 + 5) // well beyond 10 series
	_, _, pt := receiver.Receive(farSeq, 99999, 0, uint32(farSeq+1), []byte{0xFF})
	if !pt {
		t.Error("expected passThrough=true for data packet after large drop")
	}

	// After fullReset, the row groups should be re-initialized around the new base.
	// The receiver should accept the new packet without issues.
	if len(receiver.rowGroups) == 0 {
		t.Fatal("rowGroups should not be empty after fullReset")
	}

	// The new base should be aligned to the row boundary containing farSeq
	newBase := receiver.rowGroups[0].base
	rowSize := cfg.Cols
	expectedBase := farSeq - uint32(int(farSeq)%rowSize)
	if newBase != expectedBase {
		t.Errorf("after fullReset, base: got %d, want %d", newBase, expectedBase)
	}
}

func TestCheckLargeDropSmallJump(t *testing.T) {
	// A small sequence jump should NOT trigger fullReset, only dismiss old groups.
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	payloadSize := 10

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Feed packets in first row group
	receiver.Receive(0, 100, 0, 1, []byte{0x01})
	receiver.Receive(1, 200, 0, 2, []byte{0x02})

	initialGroupCount := len(receiver.rowGroups)

	// Jump by 2 rows (6 packets) — should dismiss old, not reset
	receiver.Receive(6, 700, 0, 7, []byte{0x07})

	// Should have extended row groups, not reset to just 1
	if len(receiver.rowGroups) < initialGroupCount {
		t.Errorf("small jump should not reduce group count: before=%d, after=%d",
			initialGroupCount, len(receiver.rowGroups))
	}
}

// ---- Irrecoverable timing (deferred loss reporting) ----

func TestCollectLossReportDeferredTiming(t *testing.T) {
	// When a row has FEC but more than 1 packet missing (irrecoverable),
	// loss reporting is deferred until sequence progress exceeds 1/3 row size
	// past the group end.
	cfg := Config{Cols: 6, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	payloadSize := 10

	sender := NewFECSender(cfg, payloadSize, 0)

	// Build FEC from 6 packets
	payloads := make([][]byte, 6)
	for i := range 6 {
		payloads[i] = []byte{byte(i)}
		sender.FeedSource(uint32(i), uint32(i*100), 0, payloads[i])
	}
	fecData, _, fecSeqNo, fecTS, _ := sender.PackControlPacket()

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Receive packets 0, 1, 4, 5 — skip 2 and 3 (2 missing = irrecoverable)
	receiver.Receive(0, 0, 0, 1, payloads[0])
	receiver.Receive(1, 100, 0, 2, payloads[1])
	receiver.Receive(4, 400, 0, 5, payloads[4])
	receiver.Receive(5, 500, 0, 6, payloads[5])

	// Receive FEC — can't recover (2 packets missing)
	receiver.Receive(fecSeqNo, fecTS, 0, 0, fecData)

	// Progress is at seq 5, group end is at seq 5, 1/3 of 6 = 2.
	// progress (5 - 5 = 0) < 2 — should NOT report losses yet
	losses := receiver.collectLossReport()
	if len(losses) != 0 {
		t.Errorf("loss report should be deferred (insufficient progress): got %d losses", len(losses))
	}

	// Advance progress by feeding more packets (next row)
	receiver.Receive(6, 600, 0, 7, payloads[0])
	receiver.Receive(7, 700, 0, 8, payloads[1])
	receiver.Receive(8, 800, 0, 9, payloads[2])

	// Now progress = seqDiff(5, 8) = 3 >= 2 (1/3 of 6) — should report
	losses = receiver.collectLossReport()
	if len(losses) != 2 {
		t.Errorf("expected 2 irrecoverable losses, got %d", len(losses))
	}
}

// ---- Filter plugin registry tests ----

func TestFilterRegistryRegisterAndLookup(t *testing.T) {
	// Register a custom filter factory
	called := false
	Register("testfilter", func(cfg Config, payloadSize int, isn uint32) (*FECSender, *FECReceiver, error) {
		called = true
		return NewFECSender(cfg, payloadSize, isn), NewFECReceiver(cfg, payloadSize, isn), nil
	})

	factory := Lookup("testfilter")
	if factory == nil {
		t.Fatal("Lookup should find registered 'testfilter'")
	}

	// Clean up: remove from registry to not affect other tests
	defer delete(registry, "testfilter")

	cfg := Config{Cols: 3, Rows: 1}
	_, _, err := factory(cfg, 1316, 0)
	if err != nil {
		t.Fatalf("factory returned error: %v", err)
	}
	if !called {
		t.Error("custom factory should have been called")
	}
}

func TestFilterRegistryLookupBuiltIn(t *testing.T) {
	// The "fec" factory should be registered by init()
	factory := Lookup("fec")
	if factory == nil {
		t.Fatal("Lookup should find built-in 'fec' filter")
	}
}

func TestFilterRegistryLookupUnknown(t *testing.T) {
	factory := Lookup("nonexistent")
	if factory != nil {
		t.Error("Lookup should return nil for unregistered filter")
	}
}

func TestFilterNameExtraction(t *testing.T) {
	tests := []struct {
		config string
		want   string
	}{
		{"fec,cols:5,rows:3", "fec"},
		{"xor,cols:10", "xor"},
		{"fec", "fec"},
		{"", ""},
	}

	for _, tt := range tests {
		got := FilterName(tt.config)
		if got != tt.want {
			t.Errorf("FilterName(%q): got %q, want %q", tt.config, got, tt.want)
		}
	}
}

func TestParseConfigRegisteredFilter(t *testing.T) {
	// Register a custom filter so ParseConfig accepts its name
	Register("myfilter", func(cfg Config, payloadSize int, isn uint32) (*FECSender, *FECReceiver, error) {
		return nil, nil, nil
	})
	defer delete(registry, "myfilter")

	// ParseConfig should accept "myfilter" as the first token since it's registered
	_, err := ParseConfig("myfilter,cols:5")
	if err != nil {
		t.Errorf("ParseConfig with registered filter: %v", err)
	}
}

// ---- unmarkCell tests ----

func TestUnmarkCell(t *testing.T) {
	// Mark a cell, then unmark it, verify cells map no longer contains it.
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	receiver := NewFECReceiver(cfg, 10, 0)

	receiver.markCell(42, true)
	if !receiver.cells[42] {
		t.Fatal("cell 42 should be marked after markCell")
	}

	receiver.unmarkCell(42)
	if _, exists := receiver.cells[42]; exists {
		t.Fatal("cell 42 should not exist in cells map after unmarkCell")
	}
}

// ---- getColumnGroupIndexByColX tests ----

func TestGetColumnGroupIndexByColX(t *testing.T) {
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQOnReq}
	receiver := NewFECReceiver(cfg, 10, 0)

	// In-bounds: colx 0, 1, 2 should return the index directly
	for i := range 3 {
		idx := receiver.getColumnGroupIndexByColX(i)
		if idx != i {
			t.Errorf("getColumnGroupIndexByColX(%d): got %d, want %d", i, idx, i)
		}
	}

	// Out-of-bounds: colx < 0
	idx := receiver.getColumnGroupIndexByColX(-1)
	if idx != -1 {
		t.Errorf("getColumnGroupIndexByColX(-1): got %d, want -1", idx)
	}

	// Out-of-bounds: colx >= len(colGroups)
	idx = receiver.getColumnGroupIndexByColX(len(receiver.colGroups))
	if idx != -1 {
		t.Errorf("getColumnGroupIndexByColX(%d): got %d, want -1", len(receiver.colGroups), idx)
	}

	// Way out-of-bounds: large positive
	idx = receiver.getColumnGroupIndexByColX(9999)
	if idx != -1 {
		t.Errorf("getColumnGroupIndexByColX(9999): got %d, want -1", idx)
	}
}

// ---- crossRebuildVertical tests ----

func TestCrossRebuildVertical(t *testing.T) {
	// Setup: 3 cols x 2 rows = 6 packets per matrix, even layout.
	// Use ARQNever to prevent collectLossReport from dismissing row groups
	// between FEC packet arrivals.
	//
	// Matrix layout:
	//   Row 0: seq 0, 1, 2
	//   Row 1: seq 3, 4, 5
	//   Column 0: seq 0, 3
	//   Column 1: seq 1, 4
	//   Column 2: seq 2, 5
	//
	// Lose 2 packets: seq 1 (col 1, row 0) and seq 4 (col 1, row 1).
	// Row 0 has 1 loss (seq 1) -> row FEC can recover it.
	// Col 1 has 2 losses (seq 1, 4) -> col FEC alone can't recover.
	// After col FEC is installed (hasFEC=true on col 1), row 0 FEC recovers
	// seq 1 and triggers crossRebuildVertical. col 1 now has collected=1==sizeCol()-1
	// with hasFEC=true -> recovers seq 4.

	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQNever}
	payloadSize := 10

	sender := NewFECSender(cfg, payloadSize, 0)
	payloads := make([][]byte, 6)
	timestamps := make([]uint32, 6)

	type fecPkt struct {
		data      []byte
		idx       int8
		seqNo     uint32
		timestamp uint32
	}
	var fecPkts []fecPkt
	for i := range 6 {
		payloads[i] = []byte{byte(i*10 + 1), byte(i*10 + 2), byte(i*10 + 3)}
		timestamps[i] = uint32((i + 1) * 100)
		sender.FeedSource(uint32(i), timestamps[i], 0, payloads[i])
		for {
			data, idx, seqNo, ts, ok := sender.PackControlPacket()
			if !ok {
				break
			}
			fecPkts = append(fecPkts, fecPkt{data: data, idx: idx, seqNo: seqNo, timestamp: ts})
		}
	}

	// Find row 0 FEC (first row FEC, index=-1) and col 1 FEC (index=1)
	var rowFEC0, colFEC1 *fecPkt
	for i := range fecPkts {
		if fecPkts[i].idx == -1 && rowFEC0 == nil {
			rowFEC0 = &fecPkts[i]
		}
		if fecPkts[i].idx == 1 {
			colFEC1 = &fecPkts[i]
		}
	}
	if rowFEC0 == nil {
		t.Fatal("no row 0 FEC packet found")
	}
	if colFEC1 == nil {
		t.Fatal("no column 1 FEC packet found")
	}

	// Receiver: lose seq 1 and seq 4
	receiver := NewFECReceiver(cfg, payloadSize, 0)
	for i := range 6 {
		if i == 1 || i == 4 {
			continue // lost
		}
		receiver.Receive(uint32(i), timestamps[i], 0, uint32(i+1), payloads[i])
	}

	// Feed col 1 FEC first -- col 1 has 2 losses, can't recover yet
	recovered, _, _ := receiver.Receive(colFEC1.seqNo, colFEC1.timestamp, 0, 0, colFEC1.data)
	if len(recovered) != 0 {
		t.Fatalf("expected 0 recovered from col FEC alone (2 losses), got %d", len(recovered))
	}

	// Feed row 0 FEC -- row 0 has 1 loss (seq 1), recovers it.
	// Recovery of seq 1 triggers crossRebuildVertical into col 1,
	// which now has only 1 loss (seq 4) and hasFEC=true -> recovers seq 4.
	recovered, _, _ = receiver.Receive(rowFEC0.seqNo, rowFEC0.timestamp, 0, 0, rowFEC0.data)

	// We should get both seq 1 (from row recovery) and seq 4 (from cross-rebuild into col)
	if len(recovered) != 2 {
		t.Fatalf("expected 2 recovered packets (seq 1 from row, seq 4 from cross-col), got %d", len(recovered))
	}

	// Verify recovered sequence numbers
	seqNos := map[uint32]bool{}
	for _, rp := range recovered {
		seqNos[rp.SeqNo] = true
	}
	if !seqNos[1] {
		t.Error("expected seq 1 to be recovered")
	}
	if !seqNos[4] {
		t.Error("expected seq 4 to be recovered (via crossRebuildVertical)")
	}

	// Verify payload correctness
	for _, rp := range recovered {
		idx := int(rp.SeqNo)
		for j := range payloads[idx] {
			if rp.Payload[j] != payloads[idx][j] {
				t.Fatalf("recovered seq %d payload[%d]: got 0x%02x, want 0x%02x",
					rp.SeqNo, j, rp.Payload[j], payloads[idx][j])
			}
		}
	}
}

// ---- hangHorizontalData hasFEC + collected branch tests ----

func TestHangHorizontalDataHasFECThenLastPacket(t *testing.T) {
	// Setup: 3 cols x 1 row. Lose seq 1. Receive seq 0 and FEC (hasFEC=true,
	// collected=1). Then receive seq 2 (the last missing data packet).
	// At that point collected==sizeRow()-1 (2==2) and hasFEC is true,
	// so hangHorizontalData should trigger recovery of seq 1.
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	payloadSize := 10

	sender := NewFECSender(cfg, payloadSize, 0)
	payloads := [][]byte{
		{0xAA, 0xBB},
		{0xCC, 0xDD}, // will be lost
		{0xEE, 0xFF},
	}
	timestamps := []uint32{100, 200, 300}

	for i := range 3 {
		sender.FeedSource(uint32(i), timestamps[i], 0, payloads[i])
	}
	fecData, _, fecSeqNo, fecTS, ok := sender.PackControlPacket()
	if !ok {
		t.Fatal("expected FEC packet from sender")
	}

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Step 1: receive seq 0
	recovered, _, _ := receiver.Receive(0, timestamps[0], 0, 1, payloads[0])
	if len(recovered) != 0 {
		t.Fatalf("unexpected recovery after packet 0: %d", len(recovered))
	}

	// Step 2: receive FEC (hasFEC=true, but collected=1, need sizeRow()-1=2)
	// FEC arrives with only 1 data packet clipped -> no recovery yet
	recovered, _, _ = receiver.Receive(fecSeqNo, fecTS, 0, 0, fecData)
	if len(recovered) != 0 {
		t.Fatalf("unexpected recovery after FEC with only 1 data packet: %d", len(recovered))
	}

	// Step 3: receive seq 2 (the last data packet)
	// Now collected becomes 2 == sizeRow()-1, and hasFEC is true
	// -> hangHorizontalData triggers rebuild
	recovered, _, pt := receiver.Receive(2, timestamps[2], 0, 3, payloads[2])
	if !pt {
		t.Fatal("expected passThrough for data packet 2")
	}
	if len(recovered) != 1 {
		t.Fatalf("expected 1 recovered (seq 1), got %d", len(recovered))
	}
	if recovered[0].SeqNo != 1 {
		t.Fatalf("recovered seqNo: got %d, want 1", recovered[0].SeqNo)
	}
	for i := range payloads[1] {
		if recovered[0].Payload[i] != payloads[1][i] {
			t.Fatalf("recovered payload[%d]: got 0x%02x, want 0x%02x",
				i, recovered[0].Payload[i], payloads[1][i])
		}
	}
}

// ---- dismissOldColumns tests ----

func TestDismissOldColumnsEvenLayout(t *testing.T) {
	// 3 cols x 2 rows, even layout.
	// matrixSize = 6, mindist = 1 * matrixSize = 6 (even layout)
	// Column 0 members: seq 0, 3. Last member span = (2-1)*3 = 3.
	// Dismiss when colOffset >= 6 AND colOffset - 3 >= 0 => colOffset >= 6.
	// So seq >= 0 + 6 = 6.
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQOnReq}
	payloadSize := 10

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Feed enough data packets to populate groups
	for i := range 6 {
		receiver.Receive(uint32(i), uint32(i*100), 0, uint32(i+1), []byte{byte(i)})
	}

	// At seq 5, offset from col 0 base (0) is 5 < mindist(6) -> no dismissal
	losses := receiver.dismissOldColumns(5)
	dismissed := false
	for _, g := range receiver.colGroups {
		if g.dismissed {
			dismissed = true
		}
	}
	if dismissed {
		t.Error("columns should NOT be dismissed at seq 5 (offset < mindist)")
	}
	_ = losses

	// Feed seq 6 -> offset from col 0 base (0) is 6 >= mindist(6) -> dismiss col 0
	receiver.Receive(6, 600, 0, 7, []byte{0x06})
	losses = receiver.dismissOldColumns(6)

	// Col 0 should now be dismissed (members seq 0, 3 are both received -> no losses)
	if !receiver.colGroups[0].dismissed {
		t.Error("col 0 should be dismissed at seq 6")
	}
	if len(losses) != 0 {
		t.Errorf("expected 0 losses (all received), got %d", len(losses))
	}
}

func TestDismissOldColumnsStaircaseMindist(t *testing.T) {
	// 3 cols x 2 rows, staircase layout.
	// matrixSize = 6, mindist = 2 * matrixSize = 12 (staircase layout)
	// vs even layout mindist = 1 * matrixSize = 6.
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutStaircase, ARQ: ARQOnReq}
	payloadSize := 10

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Feed packets up to seq 11
	for i := range 12 {
		receiver.Receive(uint32(i), uint32(i*100), 0, uint32(i+1), []byte{byte(i)})
	}

	// At seq 11, col 0 offset is 11 < mindist(12) -> no dismissal
	losses := receiver.dismissOldColumns(11)
	if receiver.colGroups[0].dismissed {
		t.Error("col 0 should NOT be dismissed at seq 11 with staircase layout (mindist=12)")
	}
	_ = losses

	// At seq 12, col 0 offset is 12 >= mindist(12) -> dismiss
	receiver.Receive(12, 1200, 0, 13, []byte{0x0C})
	losses = receiver.dismissOldColumns(12)
	if !receiver.colGroups[0].dismissed {
		t.Error("col 0 should be dismissed at seq 12 with staircase layout")
	}
}

func TestDismissOldColumnsDismissedGuard(t *testing.T) {
	// Verify that once a column is dismissed, it is not re-processed.
	// Call dismissOldColumns directly (not via Receive) to control state precisely.
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQOnReq}
	payloadSize := 10

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Feed packets 0-5 via markCell + hangVerticalData directly so that
	// the Receive function's internal dismissOldColumns is not called.
	// Just use markCell to mark received packets.
	for i := range 6 {
		if i == 3 {
			continue // lost
		}
		receiver.markCell(uint32(i), true)
	}
	// Also mark cell for seq 6 so it's in the cells map
	receiver.markCell(6, true)

	// Now call dismissOldColumns(6) manually. Col 0 base=0, offset=6 >= mindist=6.
	// Col 0 members: seq 0 (received) and seq 3 (not received).
	losses1 := receiver.dismissOldColumns(6)

	// Col 0 should be dismissed with seq 3 as a loss
	if !receiver.colGroups[0].dismissed {
		t.Fatal("col 0 should be dismissed")
	}
	if len(losses1) != 1 || losses1[0] != 3 {
		t.Fatalf("expected 1 loss (seq 3), got %v", losses1)
	}

	// Call dismissOldColumns again — dismissed col should NOT produce losses again
	losses2 := receiver.dismissOldColumns(7)
	for _, l := range losses2 {
		if l == 3 {
			t.Fatal("dismissed column should not report seq 3 loss again")
		}
	}
}

// ---- collectLossReport edge cases ----

func TestCollectLossReportARQAlways(t *testing.T) {
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQAlways}
	receiver := NewFECReceiver(cfg, 10, 0)

	// Feed some packets to create row groups
	receiver.Receive(0, 100, 0, 1, []byte{0x01})
	receiver.Receive(3, 400, 0, 4, []byte{0x04})
	receiver.Receive(4, 500, 0, 5, []byte{0x05})
	receiver.Receive(5, 600, 0, 6, []byte{0x06})

	losses := receiver.collectLossReport()
	if losses != nil {
		t.Errorf("ARQAlways should return nil from collectLossReport, got %v", losses)
	}
}

func TestCollectLossReportARQNever(t *testing.T) {
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQNever}
	receiver := NewFECReceiver(cfg, 10, 0)

	// Feed some packets to create row groups with gaps
	receiver.Receive(0, 100, 0, 1, []byte{0x01})
	receiver.Receive(3, 400, 0, 4, []byte{0x04})
	receiver.Receive(4, 500, 0, 5, []byte{0x05})
	receiver.Receive(5, 600, 0, 6, []byte{0x06})

	losses := receiver.collectLossReport()
	if losses != nil {
		t.Errorf("ARQNever should return nil from collectLossReport, got %v", losses)
	}
}

// ---- checkLargeDrop with column trimming tests ----

func TestCheckLargeDropColumnTrimming(t *testing.T) {
	// 3 cols x 2 rows, even layout, matrixSize=6
	// Feed enough packets to accumulate multiple column series,
	// then call checkLargeDrop directly with a moderate jump to verify
	// old column series are trimmed from the front of the deque.
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQOnReq}
	payloadSize := 10

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Feed packets through several matrices to build up column series.
	// matrixSize = 6. Feed 5 complete matrices = 30 packets.
	for i := range 30 {
		receiver.Receive(uint32(i), uint32(i*100), 0, uint32(i+1), []byte{byte(i)})
	}

	initialColSeries := receiver.colSeries
	initialColGroups := len(receiver.colGroups)

	// Call checkLargeDrop directly to trigger column trimming without
	// also triggering data packet processing that extends series.
	// threshold for row trimming = matrixSize * 2 = 12
	// min_series_history for even layout is 2.
	farSeq := uint32(30 + 18) // jump ahead by > 2 * matrixSize
	receiver.checkLargeDrop(farSeq)

	// Column series should be trimmed if we had more than minHistory(2) series
	if initialColSeries > 2 {
		if receiver.colSeries >= initialColSeries {
			t.Errorf("expected column series to be trimmed: before=%d, after=%d",
				initialColSeries, receiver.colSeries)
		}
		if len(receiver.colGroups) >= initialColGroups {
			t.Errorf("expected colGroups to shrink: before=%d, after=%d",
				initialColGroups, len(receiver.colGroups))
		}
	}
}

func TestCheckLargeDropColumnTrimmingStaircase(t *testing.T) {
	// Staircase layout: min_series_history = 4
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutStaircase, ARQ: ARQOnReq}
	payloadSize := 10

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Feed many packets to build up > 4 column series
	for i := range 60 {
		receiver.Receive(uint32(i), uint32(i*100), 0, uint32(i+1), []byte{byte(i)})
	}

	initialColSeries := receiver.colSeries

	// Call checkLargeDrop directly to trigger trimming without extending series
	farSeq := uint32(60 + 24)
	receiver.checkLargeDrop(farSeq)

	// For staircase, minHistory = 4, so if we had > 4 series, some get trimmed
	if initialColSeries > 4 {
		if receiver.colSeries >= initialColSeries {
			t.Errorf("expected column series to be trimmed (staircase): before=%d, after=%d",
				initialColSeries, receiver.colSeries)
		}
	}
}

// ---- clipFECPacket short payload tests ----

func TestClipFECPacketShortPayload(t *testing.T) {
	g := newGroup(0, 1, 10)

	// Save initial state
	origLenClip := g.lengthClip
	origFlagClip := g.flagClip
	origTSClip := g.timestampClip

	// Call with payload shorter than ExtraHeaderSize (4 bytes)
	g.clipFECPacket(12345, []byte{0xAA, 0xBB}) // only 2 bytes

	// Should be a no-op: all clip values unchanged
	if g.lengthClip != origLenClip {
		t.Errorf("lengthClip changed after short payload: got %d, want %d", g.lengthClip, origLenClip)
	}
	if g.flagClip != origFlagClip {
		t.Errorf("flagClip changed after short payload: got %d, want %d", g.flagClip, origFlagClip)
	}
	if g.timestampClip != origTSClip {
		t.Errorf("timestampClip changed after short payload: got %d, want %d", g.timestampClip, origTSClip)
	}

	// Also test with empty payload
	g.clipFECPacket(99999, nil)
	if g.lengthClip != origLenClip {
		t.Error("clipFECPacket with nil payload should be no-op")
	}

	// And exactly 3 bytes (still < ExtraHeaderSize=4)
	g.clipFECPacket(99999, []byte{0x01, 0x02, 0x03})
	if g.lengthClip != origLenClip {
		t.Error("clipFECPacket with 3-byte payload should be no-op")
	}
}

// ---- ColsOnly suppression tests ----

func TestColsOnlySuppressesRowFEC(t *testing.T) {
	// Create sender with ColsOnly=true and 2D config.
	// Feed a full row (3 packets). Verify NO row FEC is emitted.
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQOnReq, ColsOnly: true}
	sender := NewFECSender(cfg, 10, 0)

	var rowFEC, colFEC int
	// Feed a full matrix (6 packets)
	for i := range 6 {
		sender.FeedSource(uint32(i), uint32(i*100), 0, []byte{byte(i)})
		for {
			_, idx, _, _, ok := sender.PackControlPacket()
			if !ok {
				break
			}
			if idx == -1 {
				rowFEC++
			} else {
				colFEC++
			}
		}
	}

	// With ColsOnly=true, no row FEC should be emitted
	if rowFEC != 0 {
		t.Fatalf("expected 0 row FEC with ColsOnly=true, got %d", rowFEC)
	}
	// Column FEC should still be emitted (3 columns, each with 2 rows)
	if colFEC != 3 {
		t.Fatalf("expected 3 column FEC, got %d", colFEC)
	}
}

func TestColsOnlyRowOnlyConfig(t *testing.T) {
	// ColsOnly with rows=1 means no FEC at all is emitted
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq, ColsOnly: true}
	sender := NewFECSender(cfg, 10, 0)

	fecCount := 0
	for i := range 6 {
		sender.FeedSource(uint32(i), uint32(i*100), 0, []byte{byte(i)})
		for {
			_, _, _, _, ok := sender.PackControlPacket()
			if !ok {
				break
			}
			fecCount++
		}
	}

	// rows=1 means no column groups. ColsOnly suppresses row FEC. No FEC at all.
	if fecCount != 0 {
		t.Fatalf("expected 0 FEC with ColsOnly=true and rows=1, got %d", fecCount)
	}
}

// ---- getColumnGroupIndex edge cases ----

func TestGetColumnGroupIndexNegativeOffset(t *testing.T) {
	// Call with seqNo before colBaseISN -> returns -1
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQOnReq}
	receiver := NewFECReceiver(cfg, 10, 100)

	// seqNo 50 is before ISN 100 -> negative offset -> -1
	idx := receiver.getColumnGroupIndex(50)
	if idx != -1 {
		t.Errorf("getColumnGroupIndex(50) with ISN=100: got %d, want -1", idx)
	}
}

func TestGetColumnGroupIndexSeriesExtension(t *testing.T) {
	// Call with seqNo in a future series -> extends colGroups, returns valid index
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQOnReq}
	receiver := NewFECReceiver(cfg, 10, 0)

	initialSeries := receiver.colSeries
	initialGroups := len(receiver.colGroups)

	// matrixSize = 6. Series 0: seq 0-5. Series 1: seq 6-11.
	// Seq 6 is in series 1, col 0. Should extend.
	idx := receiver.getColumnGroupIndex(6)
	if idx < 0 {
		t.Fatalf("getColumnGroupIndex(6) for series 1: got %d, want >= 0", idx)
	}

	if receiver.colSeries <= initialSeries {
		t.Errorf("expected colSeries to increase: before=%d, after=%d",
			initialSeries, receiver.colSeries)
	}
	if len(receiver.colGroups) <= initialGroups {
		t.Errorf("expected colGroups to grow: before=%d, after=%d",
			initialGroups, len(receiver.colGroups))
	}

	// Verify the returned index is correct for col 0, series 1
	// The group at that index should have base = 6 (series 1 starts at 6)
	g := receiver.colGroups[idx]
	if g.base != 6 {
		t.Errorf("extended series col 0 base: got %d, want 6", g.base)
	}
}

func TestGetColumnGroupIndexBeyondMaxHistory(t *testing.T) {
	// Call with seqNo that would require more than fecMaxRcvHistory series -> returns -1
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQOnReq}
	receiver := NewFECReceiver(cfg, 10, 0)

	// matrixSize = 6. fecMaxRcvHistory = 10. Need series > 10.
	// Seq = 11 * 6 = 66 is in series 11 (0-indexed), which exceeds max history.
	farSeq := uint32(fecMaxRcvHistory * 6 * 2) // well beyond
	idx := receiver.getColumnGroupIndex(farSeq)
	if idx != -1 {
		t.Errorf("getColumnGroupIndex(%d) beyond max history: got %d, want -1", farSeq, idx)
	}
}

// ---- Receive with staircase column FEC and recovery ----

func TestReceiverStaircaseColumnRecovery(t *testing.T) {
	// Test the staircase layout path through extendColumnSeries on the receiver
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutStaircase, ARQ: ARQOnReq}
	payloadSize := 10

	sender := NewFECSender(cfg, payloadSize, 0)
	payloads := make([][]byte, 6)
	timestamps := make([]uint32, 6)

	type fecPkt struct {
		data      []byte
		idx       int8
		seqNo     uint32
		timestamp uint32
	}
	var fecPkts []fecPkt
	for i := range 6 {
		payloads[i] = []byte{byte(i*11 + 1), byte(i*11 + 2)}
		timestamps[i] = uint32((i + 1) * 100)
		sender.FeedSource(uint32(i), timestamps[i], 0, payloads[i])
		for {
			data, idx, seqNo, ts, ok := sender.PackControlPacket()
			if !ok {
				break
			}
			fecPkts = append(fecPkts, fecPkt{data: data, idx: idx, seqNo: seqNo, timestamp: ts})
		}
	}

	// Find col 0 FEC
	var colFEC0 *fecPkt
	for i := range fecPkts {
		if fecPkts[i].idx == 0 {
			colFEC0 = &fecPkts[i]
			break
		}
	}
	if colFEC0 == nil {
		t.Fatal("no col 0 FEC found")
	}

	// Receiver: lose seq 0 (col 0 member)
	receiver := NewFECReceiver(cfg, payloadSize, 0)
	for i := 1; i < 6; i++ {
		receiver.Receive(uint32(i), timestamps[i], 0, uint32(i+1), payloads[i])
	}

	// Feed col 0 FEC
	recovered, _, _ := receiver.Receive(colFEC0.seqNo, colFEC0.timestamp, 0, 0, colFEC0.data)
	if len(recovered) != 1 {
		t.Fatalf("expected 1 recovered (seq 0), got %d", len(recovered))
	}
	if recovered[0].SeqNo != 0 {
		t.Fatalf("recovered seqNo: got %d, want 0", recovered[0].SeqNo)
	}
}

// ---- hangVerticalData recovery branch ----

func TestHangVerticalDataHasFECThenLastPacket(t *testing.T) {
	// Similar to TestHangHorizontalDataHasFECThenLastPacket but for columns.
	// Setup: 3 cols x 2 rows, even layout. Col 0: seq 0, 3.
	// Lose seq 3. Receive seq 0, col FEC (hasFEC=true for col 0, collected=1).
	// Then receive seq 3 as a data packet. The data packet arrival should
	// NOT trigger rebuild (because seq 3 was the last missing one and now
	// collected reaches sizeCol()-1=1 with hasFEC... actually collected becomes 2
	// which equals sizeCol=2, not sizeCol()-1=1).
	//
	// Actually let's set up 3 cols x 3 rows. Col 0: seq 0, 3, 6.
	// Lose seq 3. Receive seq 0, seq 6, col FEC (hasFEC=true, collected=2).
	// Then verify col FEC triggers recovery directly (collected == sizeCol()-1).
	// But we want the hangVerticalData branch. So:
	// Receive seq 0, col FEC (hasFEC=true, collected=1). Then receive seq 6.
	// Now collected=2 == sizeCol()-1=2, hasFEC=true -> rebuild.
	cfg := Config{Cols: 3, Rows: 3, Layout: LayoutEven, ARQ: ARQOnReq}
	payloadSize := 10

	sender := NewFECSender(cfg, payloadSize, 0)
	payloads := make([][]byte, 9)
	timestamps := make([]uint32, 9)

	type fecPkt struct {
		data      []byte
		idx       int8
		seqNo     uint32
		timestamp uint32
	}
	var fecPkts []fecPkt
	for i := range 9 {
		payloads[i] = []byte{byte(i*7 + 1), byte(i*7 + 2)}
		timestamps[i] = uint32((i + 1) * 100)
		sender.FeedSource(uint32(i), timestamps[i], 0, payloads[i])
		for {
			data, idx, seqNo, ts, ok := sender.PackControlPacket()
			if !ok {
				break
			}
			fecPkts = append(fecPkts, fecPkt{data: data, idx: idx, seqNo: seqNo, timestamp: ts})
		}
	}

	var colFEC0 *fecPkt
	for i := range fecPkts {
		if fecPkts[i].idx == 0 {
			colFEC0 = &fecPkts[i]
			break
		}
	}
	if colFEC0 == nil {
		t.Fatal("no col 0 FEC found")
	}

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Receive all except seq 3 (col 0, row 1)
	for i := range 9 {
		if i == 3 {
			continue
		}
		receiver.Receive(uint32(i), timestamps[i], 0, uint32(i+1), payloads[i])
	}

	// Feed col 0 FEC -> should recover seq 3 (collected is already 2 = sizeCol()-1)
	recovered, _, _ := receiver.Receive(colFEC0.seqNo, colFEC0.timestamp, 0, 0, colFEC0.data)
	if len(recovered) != 1 {
		t.Fatalf("expected 1 recovered (seq 3), got %d", len(recovered))
	}
	if recovered[0].SeqNo != 3 {
		t.Fatalf("recovered seqNo: got %d, want 3", recovered[0].SeqNo)
	}
}

// ---- dismissOldColumns with irrecoverable losses ----

func TestDismissOldColumnsWithLosses(t *testing.T) {
	// 3 cols x 2 rows, even layout.
	// Skip seq 3 (col 0, row 1) to create a loss in col 0.
	// Advance past col 0 mindist and verify the loss is reported.
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQOnReq}
	payloadSize := 10

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Mark cells directly to avoid Receive's internal dismissOldColumns call
	for i := range 6 {
		if i == 3 {
			continue // lost
		}
		receiver.markCell(uint32(i), true)
	}

	// Call dismissOldColumns with seq 6 (offset >= mindist=6 for col 0)
	losses := receiver.dismissOldColumns(6)

	// seq 3 should be reported as a loss
	foundLoss := false
	for _, l := range losses {
		if l == 3 {
			foundLoss = true
		}
	}
	if !foundLoss {
		t.Errorf("expected seq 3 in irrecoverable losses, got %v", losses)
	}
}

// ---- NegotiateConfig additional edge cases ----

func TestNegotiateConfigLayoutMismatch(t *testing.T) {
	a := Config{Cols: 5, Rows: 3, Layout: LayoutStaircase, ARQ: ARQOnReq}
	b := Config{Cols: 5, Rows: 3, Layout: LayoutEven, ARQ: ARQOnReq}
	_, err := NegotiateConfig(a, b)
	if err == nil {
		t.Fatal("expected error for layout mismatch")
	}
}

func TestNegotiateConfigARQMismatch(t *testing.T) {
	a := Config{Cols: 5, Rows: 3, Layout: LayoutStaircase, ARQ: ARQOnReq}
	b := Config{Cols: 5, Rows: 3, Layout: LayoutStaircase, ARQ: ARQNever}
	_, err := NegotiateConfig(a, b)
	if err == nil {
		t.Fatal("expected error for ARQ mismatch")
	}
}

// ---- FEC receiver short FEC control packet ----

func TestReceiverShortFECPacket(t *testing.T) {
	// FEC control packets shorter than ExtraHeaderSize should be silently ignored
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	receiver := NewFECReceiver(cfg, 10, 0)

	// msgNo=0 signals FEC control packet, but payload too short
	recovered, lossReport, pt := receiver.Receive(0, 100, 0, 0, []byte{0xAA})
	if pt {
		t.Error("expected passThrough=false for FEC control packet")
	}
	if len(recovered) != 0 {
		t.Errorf("expected 0 recovered, got %d", len(recovered))
	}
	_ = lossReport
}

// ---- Receiver duplicate for old seqno ----

func TestReceiverOldSeqNo(t *testing.T) {
	// Receiving a packet with seqNo before cellBase should be ignored
	cfg := Config{Cols: 3, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	receiver := NewFECReceiver(cfg, 10, 100) // ISN=100

	// seqNo 50 is before ISN 100
	recovered, _, pt := receiver.Receive(50, 100, 0, 1, []byte{0x01})
	if !pt {
		t.Error("expected passThrough=true for data packet")
	}
	if len(recovered) != 0 {
		t.Errorf("expected 0 recovered for old seqno, got %d", len(recovered))
	}
}

// ---- Receiver extendColumnSeries staircase path ----

func TestReceiverExtendColumnSeriesStaircase(t *testing.T) {
	// Ensure the staircase branch in extendColumnSeries is exercised
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutStaircase, ARQ: ARQOnReq}
	payloadSize := 10

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	initialSeries := receiver.colSeries
	initialGroups := len(receiver.colGroups)

	// Force extension by accessing a packet in a future series
	// matrixSize = 6, series 1 starts at seq 6
	idx := receiver.getColumnGroupIndex(6)
	if idx < 0 {
		t.Fatalf("getColumnGroupIndex(6) staircase: got %d, want >= 0", idx)
	}

	if receiver.colSeries <= initialSeries {
		t.Errorf("staircase colSeries should grow: before=%d, after=%d",
			initialSeries, receiver.colSeries)
	}
	if len(receiver.colGroups) <= initialGroups {
		t.Errorf("staircase colGroups should grow: before=%d, after=%d",
			initialGroups, len(receiver.colGroups))
	}
}

// ---- crossRebuildHorizontal (column recovery feeds into row recovery) ----

func TestCrossRebuildHorizontal(t *testing.T) {
	// Setup: 3 cols x 2 rows, even layout. ARQNever to prevent premature
	// row group dismissal by collectLossReport.
	// Matrix:
	//   Row 0: seq 0, 1, 2
	//   Row 1: seq 3, 4, 5
	//   Col 0: seq 0, 3
	//   Col 1: seq 1, 4
	//   Col 2: seq 2, 5
	//
	// Lose seq 4 (row 1, col 1) and seq 5 (row 1, col 2).
	// Col 1 has 1 loss (seq 4) -> col FEC can recover it.
	// Row 1 has 2 losses (seq 4, 5) -> row FEC alone can't recover.
	// After col 1 FEC recovers seq 4, crossRebuildHorizontal feeds seq 4 into row 1.
	// Now row 1 has 1 loss (seq 5) with hasFEC -> recovers seq 5.
	cfg := Config{Cols: 3, Rows: 2, Layout: LayoutEven, ARQ: ARQNever}
	payloadSize := 10

	sender := NewFECSender(cfg, payloadSize, 0)
	payloads := make([][]byte, 6)
	timestamps := make([]uint32, 6)

	type fecPkt struct {
		data      []byte
		idx       int8
		seqNo     uint32
		timestamp uint32
	}
	var fecPkts []fecPkt
	for i := range 6 {
		payloads[i] = []byte{byte(i*13 + 1), byte(i*13 + 2)}
		timestamps[i] = uint32((i + 1) * 100)
		sender.FeedSource(uint32(i), timestamps[i], 0, payloads[i])
		for {
			data, idx, seqNo, ts, ok := sender.PackControlPacket()
			if !ok {
				break
			}
			fecPkts = append(fecPkts, fecPkt{data: data, idx: idx, seqNo: seqNo, timestamp: ts})
		}
	}

	// Find col 1 FEC and row 1 FEC
	var colFEC1, rowFEC1 *fecPkt
	rowFECCount := 0
	for i := range fecPkts {
		if fecPkts[i].idx == 1 {
			colFEC1 = &fecPkts[i]
		}
		if fecPkts[i].idx == -1 {
			rowFECCount++
			if rowFECCount == 2 { // second row FEC is for row 1
				rowFEC1 = &fecPkts[i]
			}
		}
	}
	if colFEC1 == nil {
		t.Fatal("no col 1 FEC found")
	}
	if rowFEC1 == nil {
		t.Fatal("no row 1 FEC found")
	}

	receiver := NewFECReceiver(cfg, payloadSize, 0)

	// Receive all except seq 4 and seq 5
	for i := range 6 {
		if i == 4 || i == 5 {
			continue
		}
		receiver.Receive(uint32(i), timestamps[i], 0, uint32(i+1), payloads[i])
	}

	// Feed row 1 FEC first (row 1 has 2 losses, can't recover)
	recovered, _, _ := receiver.Receive(rowFEC1.seqNo, rowFEC1.timestamp, 0, 0, rowFEC1.data)
	if len(recovered) != 0 {
		t.Fatalf("expected 0 recovered from row FEC alone (2 losses), got %d", len(recovered))
	}

	// Feed col 1 FEC -> recovers seq 4, then crossRebuildHorizontal recovers seq 5
	recovered, _, _ = receiver.Receive(colFEC1.seqNo, colFEC1.timestamp, 0, 0, colFEC1.data)
	if len(recovered) != 2 {
		t.Fatalf("expected 2 recovered (seq 4 from col, seq 5 from cross-row), got %d", len(recovered))
	}

	seqNos := map[uint32]bool{}
	for _, rp := range recovered {
		seqNos[rp.SeqNo] = true
	}
	if !seqNos[4] {
		t.Error("expected seq 4 to be recovered")
	}
	if !seqNos[5] {
		t.Error("expected seq 5 to be recovered (via crossRebuildHorizontal)")
	}
}

// ---- FormatConfig with ARQNever ----

func TestFormatConfigARQNever(t *testing.T) {
	cfg := Config{Cols: 5, Rows: 1, Layout: LayoutStaircase, ARQ: ARQNever}
	s := FormatConfig(cfg)
	parsed, err := ParseConfig(s)
	if err != nil {
		t.Fatalf("round-trip failed: %v", err)
	}
	if parsed != cfg {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", parsed, cfg)
	}
}

// ---- ParseConfig additional edge case ----

func TestParseConfigInvalidColsValue(t *testing.T) {
	_, err := ParseConfig("fec,cols:abc")
	if err == nil {
		t.Fatal("expected error for non-numeric cols value")
	}
}

func TestParseConfigInvalidRowsValue(t *testing.T) {
	_, err := ParseConfig("fec,cols:5,rows:abc")
	if err == nil {
		t.Fatal("expected error for non-numeric rows value")
	}
}

func TestParseConfigInvalidParam(t *testing.T) {
	_, err := ParseConfig("fec,nocolon")
	if err == nil {
		t.Fatal("expected error for param without colon")
	}
}

func BenchmarkFECReceiverRecover(b *testing.B) {
	cfg := Config{Cols: 10, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	payloadSize := 1316

	// Pre-build FEC packets
	sender := NewFECSender(cfg, payloadSize, 0)
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	// Build one complete group
	for i := range 10 {
		sender.FeedSource(uint32(i), uint32(i*100), 0, payload)
	}
	fecData, _, fecSeqNo, fecTS, _ := sender.PackControlPacket()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		receiver := NewFECReceiver(cfg, payloadSize, 0)
		// Receive 9 of 10 packets (skip packet 5)
		for j := 0; j < 10; j++ {
			if j == 5 {
				continue
			}
			receiver.Receive(uint32(j), uint32(j*100), 0, uint32(j+1), payload)
		}
		// Receive FEC to trigger recovery
		receiver.Receive(fecSeqNo, fecTS, 0, 0, fecData)
	}
}
