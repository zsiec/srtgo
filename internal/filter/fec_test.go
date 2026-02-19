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
	for i := 0; i < 3; i++ {
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

	for i := 0; i < len(payloads[1]); i++ {
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
	for i := 0; i < 3; i++ {
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
	for i := 0; i < 6; i++ {
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
	for i := 0; i < 6; i++ {
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

	for i := 0; i < 3; i++ {
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
	for i := 0; i < 6; i++ {
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
	for i := 0; i < 6; i++ {
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

	for i := 0; i < 3; i++ {
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
	for i := 0; i < 3; i++ {
		sender.FeedSource(uint32(i), uint32(i*100), 0, payloads[i])
	}
	fecData, _, fecSeqNo, fecTS, _ := sender.PackControlPacket()

	receiver := NewFECReceiver(cfg, payloadSize, 0)
	for i := 0; i < 3; i++ {
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
	for i := 0; i < 4; i++ {
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
	for i := 0; i < 6; i++ {
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
	for i := 0; i < 6; i++ {
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
	for i := 0; i < 10; i++ {
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
