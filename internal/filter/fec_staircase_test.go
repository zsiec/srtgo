package filter

import (
	"encoding/binary"
	"testing"
)

// These tests guard the staircase column (2D) FEC fix. Staircase columns are
// staggered and span the matrix boundary, so the receiver must measure a
// column's series from its own base offset (not the raw matrix offset).
// Before the fix, a no-loss 2D stream produced many corrupt/spurious recoveries.

// drive2D feeds n in-order data packets (dropping those in drop) plus the
// sender's FEC packets into a fresh receiver and returns, for every recovered
// packet, whether its payload was correct and the set of recovered offsets.
func drive2D(t *testing.T, cfgStr string, n int, drop map[int]bool) (corrupt int, recovered map[int]bool) {
	t.Helper()
	cfg, err := ParseConfig(cfgStr)
	if err != nil {
		t.Fatal(err)
	}
	const isn = 100
	snd := NewFECSender(cfg, 1316, isn)
	rcv := NewFECReceiver(cfg, 1316, isn)
	recovered = map[int]bool{}
	consume := func(rps []RecoveredPacket) {
		for _, rp := range rps {
			off := int(rp.SeqNo - isn)
			recovered[off] = true
			if binary.BigEndian.Uint32(rp.Payload) != uint32(off) {
				corrupt++
			}
		}
	}
	for i := 0; i < n; i++ {
		s := uint32(isn + i)
		ts := uint32(i * 1000)
		pl := make([]byte, 1316)
		binary.BigEndian.PutUint32(pl, uint32(i))
		snd.FeedSource(s, ts, 0, pl)
		if !drop[i] {
			rec, _, _ := rcv.Receive(s, ts, 0, uint32((i%0x03FFFFFF)+1), pl)
			consume(rec)
		}
		for {
			d, _, fs, ft, ok := snd.PackControlPacket()
			if !ok {
				break
			}
			r2, _, _ := rcv.Receive(fs, ft, 0, 0, d)
			consume(r2)
		}
	}
	return corrupt, recovered
}

func TestStaircase2DNoCorruption(t *testing.T) {
	for _, cfg := range []string{
		"fec,cols:8,rows:4,arq:onreq,layout:staircase",
		"fec,cols:10,rows:5,arq:onreq,layout:staircase",
		"fec,cols:6,rows:6,arq:onreq,layout:staircase",
		"fec,cols:8,rows:4,arq:onreq,layout:even",
	} {
		corrupt, recovered := drive2D(t, cfg, 1000, nil)
		if corrupt != 0 {
			t.Errorf("%s no-loss: %d corrupt recoveries (want 0)", cfg, corrupt)
		}
		// Any recoveries in a no-loss stream must be rare, correct-payload
		// duplicates (deduped downstream), never a flood.
		if len(recovered) > cfg2cols(t, cfg) {
			t.Errorf("%s no-loss: %d recoveries (want a small number)", cfg, len(recovered))
		}
	}
}

func TestStaircase2DRecovery(t *testing.T) {
	const cfg = "fec,cols:8,rows:4,arq:onreq,layout:staircase"
	// Drop one packet per row of 8 (the row dimension recovers each).
	for start := 300; start < 360; start++ {
		drop := map[int]bool{start: true}
		corrupt, recovered := drive2D(t, cfg, 1000, drop)
		if corrupt != 0 {
			t.Fatalf("drop %d: %d corrupt recoveries", start, corrupt)
		}
		if !recovered[start] {
			t.Fatalf("drop %d: not recovered", start)
		}
	}
}

func cfg2cols(t *testing.T, s string) int {
	c, err := ParseConfig(s)
	if err != nil {
		t.Fatal(err)
	}
	return c.Cols
}
