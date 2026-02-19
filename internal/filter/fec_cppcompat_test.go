package filter

// Tests ported from the C++ SRT implementation's test_fec_rebuilding.cpp.
// These validate FEC config parsing rejection, single-loss XOR rebuild, and
// multi-loss (irrecoverable) scenarios to ensure compatibility with the
// C++ reference behaviour.

import (
	"bytes"
	"math/rand"
	"testing"
)

// ---------------------------------------------------------------------------
// TestCppCompat_ConfigExchangeFaux ports the ConfigExchangeFaux test.
// Every config string listed here must be rejected by ParseConfig.
//
// Mapping from C++ test cases:
//
//	D:  "FEC,Cols:20"             -- unknown filter (case sensitive)
//	E1: "fec,cols:-10"            -- invalid value for cols
//	E2: "fec,cols:10,rows:0"      -- invalid value for rows
//	E4: "fec,cols:10,layout:stairwars" -- invalid layout value
//	E5: "fec,cols:10,arq:sometimes"    -- invalid arq value
//	F:  "fec,cols:10,weight:2"    -- unknown parameter name
//
// ---------------------------------------------------------------------------
func TestCppCompat_ConfigExchangeFaux(t *testing.T) {
	rejected := []struct {
		tag    string
		config string
	}{
		{"D_unknown_filter", "FEC,Cols:20"},
		{"E1_negative_cols", "fec,cols:-10"},
		{"E2_rows_zero", "fec,cols:10,rows:0"},
		{"E3_negative_rows", "fec,cols:10,rows:-1"},
		{"E4_bad_layout", "fec,cols:10,layout:stairwars"},
		{"E5_bad_arq", "fec,cols:10,arq:sometimes"},
		{"F_unknown_param", "fec,cols:10,weight:2"},
	}

	for _, tc := range rejected {
		t.Run(tc.tag, func(t *testing.T) {
			_, err := ParseConfig(tc.config)
			if err == nil {
				t.Fatalf("ParseConfig(%q) should have been rejected, but succeeded", tc.config)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestCppCompat_Rebuild ports the Rebuild test from TestFECRebuilding.
//
// Setup (matching C++):
//   - ISN = 123456, payloadSize = 1316, cols = 7, rows = 1
//   - 7 source packets with random-length payloads (732..1315 bytes)
//     filled with random data
//   - Feed all 7 to sender; extract the row FEC control packet
//   - Feed packets 0-3, 5-6 (skip index 4) plus FEC to receiver
//   - Expect exactly 1 recovered packet with correct seqno and payload
//
// ---------------------------------------------------------------------------
func TestCppCompat_Rebuild(t *testing.T) {
	const (
		isn         = uint32(123456)
		plsize      = 1316
		numPkts     = 7
		lostIdx     = 4
		minSize     = 732
		timestampT0 = uint32(10)
		tsDelta     = uint32(10)
	)

	cfg := Config{Cols: 7, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}

	// Deterministic random source so the test is reproducible.
	rng := rand.New(rand.NewSource(0xC0FFEE))

	// Build source packets (matching C++ setup()).
	type srcPkt struct {
		seqNo     uint32
		timestamp uint32
		payload   []byte
	}
	sources := make([]srcPkt, numPkts)
	seq := isn
	ts := timestampT0
	for i := range numPkts {
		divergence := plsize - minSize - 1
		length := minSize + rng.Intn(divergence)
		payload := make([]byte, length)
		for b := range length {
			payload[b] = byte(rng.Intn(255))
		}
		sources[i] = srcPkt{seqNo: seq, timestamp: ts, payload: payload}
		seq = seqAdd(seq, 1)
		ts += tsDelta
	}

	// --- Sender side: feed all 7 packets, extract FEC control packet ---
	sender := NewFECSender(cfg, plsize, isn)
	for i := range numPkts {
		sender.FeedSource(sources[i].seqNo, sources[i].timestamp, 0, sources[i].payload)
	}

	fecData, fecIdx, fecSeqNo, fecTS, ok := sender.PackControlPacket()
	if !ok {
		t.Fatal("sender did not produce an FEC control packet after 7 data packets")
	}
	if fecIdx != -1 {
		t.Fatalf("expected row FEC (groupIndex -1), got %d", fecIdx)
	}

	// --- Receiver side: feed 6 of 7 data packets (skip index 4) ---
	receiver := NewFECReceiver(cfg, plsize, isn)
	for i := range numPkts {
		if i == lostIdx {
			continue
		}
		recovered, _, pt := receiver.Receive(
			sources[i].seqNo, sources[i].timestamp, 0,
			uint32(i+1), // msgNo != 0 means data packet
			sources[i].payload,
		)
		if !pt {
			t.Fatalf("packet %d: expected passThrough=true for data packet", i)
		}
		if len(recovered) != 0 {
			t.Fatalf("packet %d: unexpected recovery before FEC control", i)
		}
	}

	// Feed the FEC control packet (msgNo == 0 signals FEC).
	recovered, _, pt := receiver.Receive(fecSeqNo, fecTS, 0, 0, fecData)
	if pt {
		t.Fatal("FEC control packet should have passThrough=false")
	}

	// --- Verify recovery ---
	if len(recovered) != 1 {
		t.Fatalf("expected exactly 1 recovered packet, got %d", len(recovered))
	}

	rp := recovered[0]
	if rp.SeqNo != sources[lostIdx].seqNo {
		t.Fatalf("recovered SeqNo: got %d, want %d", rp.SeqNo, sources[lostIdx].seqNo)
	}
	if rp.Timestamp != sources[lostIdx].timestamp {
		t.Fatalf("recovered Timestamp: got %d, want %d", rp.Timestamp, sources[lostIdx].timestamp)
	}
	if len(rp.Payload) != len(sources[lostIdx].payload) {
		t.Fatalf("recovered payload length: got %d, want %d",
			len(rp.Payload), len(sources[lostIdx].payload))
	}
	if !bytes.Equal(rp.Payload, sources[lostIdx].payload) {
		// Find first differing byte for a useful error message.
		for j := range rp.Payload {
			if rp.Payload[j] != sources[lostIdx].payload[j] {
				t.Fatalf("recovered payload differs at byte %d: got 0x%02x, want 0x%02x",
					j, rp.Payload[j], sources[lostIdx].payload[j])
			}
		}
	}
}

// ---------------------------------------------------------------------------
// TestCppCompat_NoRebuild ports the NoRebuild test from TestFECRebuilding.
//
// Same setup as Rebuild, but skip packets at indices 4 AND 6 (two losses in
// one row group). Row-only FEC can recover at most 1 loss per group, so:
//   - FEC control packet must be consumed (passThrough = false)
//   - No packets should be recovered (provided.size() == 0 in C++)
//
// ---------------------------------------------------------------------------
func TestCppCompat_NoRebuild(t *testing.T) {
	const (
		isn         = uint32(123456)
		plsize      = 1316
		numPkts     = 7
		timestampT0 = uint32(10)
		tsDelta     = uint32(10)
		minSize     = 732
	)

	cfg := Config{Cols: 7, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}

	rng := rand.New(rand.NewSource(0xC0FFEE))

	type srcPkt struct {
		seqNo     uint32
		timestamp uint32
		payload   []byte
	}
	sources := make([]srcPkt, numPkts)
	seq := isn
	ts := timestampT0
	for i := range numPkts {
		divergence := plsize - minSize - 1
		length := minSize + rng.Intn(divergence)
		payload := make([]byte, length)
		for b := range length {
			payload[b] = byte(rng.Intn(255))
		}
		sources[i] = srcPkt{seqNo: seq, timestamp: ts, payload: payload}
		seq = seqAdd(seq, 1)
		ts += tsDelta
	}

	// --- Sender side ---
	sender := NewFECSender(cfg, plsize, isn)
	for i := range numPkts {
		sender.FeedSource(sources[i].seqNo, sources[i].timestamp, 0, sources[i].payload)
	}

	fecData, _, fecSeqNo, fecTS, ok := sender.PackControlPacket()
	if !ok {
		t.Fatal("sender did not produce an FEC control packet")
	}

	// --- Receiver side: skip indices 4 and 6 ---
	receiver := NewFECReceiver(cfg, plsize, isn)
	for i := range numPkts {
		if i == 4 || i == 6 {
			continue
		}
		recovered, _, pt := receiver.Receive(
			sources[i].seqNo, sources[i].timestamp, 0,
			uint32(i+1),
			sources[i].payload,
		)
		if !pt {
			t.Fatalf("packet %d: expected passThrough=true", i)
		}
		if len(recovered) != 0 {
			t.Fatalf("packet %d: unexpected recovery", i)
		}
	}

	// Feed the FEC control packet.
	recovered, _, pt := receiver.Receive(fecSeqNo, fecTS, 0, 0, fecData)
	if pt {
		t.Fatal("FEC control packet should have passThrough=false (consumed)")
	}

	// Two losses in one row group: FEC cannot recover.
	if len(recovered) != 0 {
		t.Fatalf("expected 0 recovered packets (2 losses irrecoverable), got %d", len(recovered))
	}
}

// ---------------------------------------------------------------------------
// TestCppCompat_ConfigNegotiationConflict ports the RejectionConflict test.
// Two configs with conflicting cols values must fail negotiation.
// ---------------------------------------------------------------------------
func TestCppCompat_ConfigNegotiationConflict(t *testing.T) {
	a := Config{Cols: 10, Rows: 10, Layout: LayoutStaircase, ARQ: ARQOnReq}
	b := Config{Cols: 20, Rows: 1, Layout: LayoutStaircase, ARQ: ARQNever}

	_, err := NegotiateConfig(a, b)
	if err == nil {
		t.Fatal("NegotiateConfig should reject conflicting cols (10 vs 20)")
	}
}

// ---------------------------------------------------------------------------
// TestCppCompat_ConfigNegotiationSuccess ports the Connection test.
// Two compatible configs should negotiate successfully and produce a merged
// config with the expected values.
// ---------------------------------------------------------------------------
func TestCppCompat_ConfigNegotiationSuccess(t *testing.T) {
	// C++ Connection test: "fec,cols:10,rows:10" + "fec,cols:10,arq:never"
	// Expected result: "fec,cols:10,rows:10,arq:never,layout:staircase"
	//
	// In our Go API, NegotiateConfig requires all fields to match exactly
	// (no partial merge). So we test the round-trip parse + negotiate path
	// with fully-specified identical configs.
	cfg := Config{Cols: 10, Rows: 10, Layout: LayoutStaircase, ARQ: ARQNever}

	got, err := NegotiateConfig(cfg, cfg)
	if err != nil {
		t.Fatalf("NegotiateConfig failed: %v", err)
	}
	if got != cfg {
		t.Fatalf("negotiated config mismatch: got %+v, want %+v", got, cfg)
	}

	// Verify round-trip through FormatConfig -> ParseConfig
	s := FormatConfig(cfg)
	parsed, err := ParseConfig(s)
	if err != nil {
		t.Fatalf("ParseConfig(%q) failed: %v", s, err)
	}
	if parsed != cfg {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", parsed, cfg)
	}
}

// ---------------------------------------------------------------------------
// TestCppCompat_ConfigFullRoundTrip ports ConnectionFull1 and ConnectionFull2.
// Full configs with all parameters specified in different orders should parse
// to identical Config structs.
// ---------------------------------------------------------------------------
func TestCppCompat_ConfigFullRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		config1 string
		config2 string
		want    Config
	}{
		{
			name:    "Full1_arq_never",
			config1: "fec,cols:10,rows:20,arq:never,layout:even",
			config2: "fec,layout:even,rows:20,cols:10,arq:never",
			want:    Config{Cols: 10, Rows: 20, Layout: LayoutEven, ARQ: ARQNever},
		},
		{
			name:    "Full2_arq_always",
			config1: "fec,cols:10,rows:20,arq:always,layout:even",
			config2: "fec,layout:even,rows:20,cols:10,arq:always",
			want:    Config{Cols: 10, Rows: 20, Layout: LayoutEven, ARQ: ARQAlways},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg1, err := ParseConfig(tc.config1)
			if err != nil {
				t.Fatalf("ParseConfig(%q): %v", tc.config1, err)
			}
			cfg2, err := ParseConfig(tc.config2)
			if err != nil {
				t.Fatalf("ParseConfig(%q): %v", tc.config2, err)
			}
			if cfg1 != cfg2 {
				t.Fatalf("configs differ:\n  %q -> %+v\n  %q -> %+v",
					tc.config1, cfg1, tc.config2, cfg2)
			}
			if cfg1 != tc.want {
				t.Fatalf("parsed config: got %+v, want %+v", cfg1, tc.want)
			}

			// Both sides identical -- negotiation should succeed.
			negotiated, err := NegotiateConfig(cfg1, cfg2)
			if err != nil {
				t.Fatalf("NegotiateConfig failed: %v", err)
			}
			if negotiated != tc.want {
				t.Fatalf("negotiated: got %+v, want %+v", negotiated, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestCppCompat_Prepare ports the Prepare test from TestFECRebuilding.
// Simply verifies that feeding 7 packets to the sender produces an FEC
// control packet.
// ---------------------------------------------------------------------------
func TestCppCompat_Prepare(t *testing.T) {
	const (
		isn    = uint32(123456)
		plsize = 1316
	)

	cfg := Config{Cols: 7, Rows: 1, Layout: LayoutStaircase, ARQ: ARQOnReq}
	sender := NewFECSender(cfg, plsize, isn)

	rng := rand.New(rand.NewSource(42))
	seq := isn
	ts := uint32(10)
	for range 7 {
		length := 732 + rng.Intn(plsize-732-1)
		payload := make([]byte, length)
		for b := range payload {
			payload[b] = byte(rng.Intn(255))
		}
		sender.FeedSource(seq, ts, 0, payload)
		seq = seqAdd(seq, 1)
		ts += 10
	}

	_, _, _, _, ok := sender.PackControlPacket()
	if !ok {
		t.Fatal("expected FEC control packet after feeding 7 packets with cols=7")
	}

	// Should have no more pending FEC packets (row-only, single group).
	_, _, _, _, ok = sender.PackControlPacket()
	if ok {
		t.Fatal("unexpected second FEC control packet")
	}
}
