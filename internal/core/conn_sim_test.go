package core_test

import (
	"encoding/binary"
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/packet"
)

// This file drives two pure cores over an in-memory, deterministic, lossy link
// using virtual time. It proves the Sans-I/O data path moves data end-to-end
// and recovers dropped packets via ACK/NAK/retransmit — with no sockets, no
// goroutines, and no real clock.

const (
	linkDelay  = 20 * clock.Millisecond // one-way propagation
	simPayload = 1316
)

// outDatagram is one marshaled packet leaving a host, tagged so the link's loss
// model can target data packets by sequence number. msgNo 0 marks an FEC repair
// packet (never dropped by the loss model).
type outDatagram struct {
	data   []byte
	isData bool
	seqNo  uint32
	msgNo  uint32
}

// inflight is a datagram in transit on the link.
type inflight struct {
	arrival clock.Timestamp
	data    []byte
}

// simHost wraps a core.Conn with the host responsibilities the driver owns: a
// timer wheel, a delivered-payload log, and output marshaling.
type simHost struct {
	c         *core.Conn
	timers    map[core.TimerID]clock.Timestamp
	delivered [][]byte
	recvMeta  []core.DataReceived // full delivery events (payload + message metadata)
	connected bool
	closed    bool
}

func newSimHost(c *core.Conn) *simHost {
	return &simHost{c: c, timers: make(map[core.TimerID]clock.Timestamp)}
}

// drain executes every pending output/event, returning datagrams to put on the
// wire. This mirrors what the real internal/session driver will do.
func (h *simHost) drain() []outDatagram {
	var out []outDatagram
	for {
		o, ok := h.c.PollOutput()
		if !ok {
			break
		}
		switch v := o.(type) {
		case core.SendPacket:
			buf := make([]byte, packet.HeaderSize+len(v.Packet.Data))
			n, err := v.Packet.Marshal(buf)
			if err == nil {
				out = append(out, outDatagram{
					data:   buf[:n],
					isData: !v.Packet.Header.IsControl,
					seqNo:  v.Packet.Header.SequenceNumber,
					msgNo:  v.Packet.Header.MessageNumber,
				})
			}
			if v.Owned {
				v.Packet.Release()
			}
		case core.SetTimer:
			h.timers[v.ID] = v.Deadline
		case core.ClearTimer:
			delete(h.timers, v.ID)
		}
	}
	for {
		e, ok := h.c.PollEvent()
		if !ok {
			break
		}
		switch ev := e.(type) {
		case core.DataReceived:
			h.delivered = append(h.delivered, ev.Data)
			h.recvMeta = append(h.recvMeta, ev)
		case core.Connected:
			h.connected = true
		case core.Closed:
			h.closed = true
		}
	}
	return out
}

func makePayload(i int) []byte {
	b := make([]byte, simPayload)
	binary.BigEndian.PutUint32(b, uint32(i))
	return b
}

func TestSimLossRecovery(t *testing.T) {
	const (
		sndSocketID = 1
		rcvSocketID = 2
		sndISN      = 100
		rcvISN      = 5000
		numPayloads = 400
	)
	base := clock.Timestamp(1_000_000)

	sender := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: rcvSocketID,
		PayloadSize:  simPayload,
		SendISN:      sndISN,
		RecvISN:      rcvISN,
		MaxBW:        1 << 34, // effectively unthrottled pacing
	}, base))
	receiver := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: sndSocketID,
		PayloadSize:  simPayload,
		SendISN:      rcvISN,
		RecvISN:      sndISN,
		MaxBW:        1 << 34,
	}, base))

	// Forward-link loss: drop these data sequence numbers exactly once (their
	// retransmissions get through), exercising immediate-NAK recovery.
	dropOnce := map[uint32]bool{150: true, 151: true, 152: true, 207: true, 333: true}

	runStream(t, sender, receiver, base, numPayloads, dropOnce)
}

// dropOnce returns a forward-loss predicate that drops each listed data sequence
// number exactly once (so a retransmission recovers it).
func dropOnce(seqs map[uint32]bool) func(uint32) bool {
	return func(seqNo uint32) bool {
		if seqs != nil && seqs[seqNo] {
			delete(seqs, seqNo)
			return true
		}
		return false
	}
}

// drive runs the two cores over the lossy in-memory link, advancing virtual
// time event by event until done() returns true (or both sides go idle).
// dropFwd, when non-nil, decides which forward data packets to drop by sequence
// number (FEC repair packets, msgNo 0, are never dropped); returning true for a
// sequence every time models permanent loss, once models a recoverable drop.
func drive(t *testing.T, sender, receiver *simHost, base clock.Timestamp, dropFwd func(uint32) bool, done func() bool) {
	t.Helper()

	var fwd, bwd []inflight
	now := base

	schedule := func(out []outDatagram, q *[]inflight, drop func(uint32) bool) {
		for _, dg := range out {
			if dg.isData && dg.msgNo != 0 && drop != nil && drop(dg.seqNo) {
				continue
			}
			*q = append(*q, inflight{arrival: now.Add(linkDelay), data: dg.data})
		}
	}

	schedule(sender.drain(), &fwd, dropFwd)
	schedule(receiver.drain(), &bwd, nil)

	deliverDue := func(q *[]inflight, dst *simHost) bool {
		progressed := false
		for len(*q) > 0 && (*q)[0].arrival <= now {
			dg := (*q)[0]
			*q = (*q)[1:]
			if p, err := packet.Parse(dg.data, nil); err == nil {
				dst.c.HandlePacket(now, p)
			}
			progressed = true
		}
		return progressed
	}
	fireTimers := func(h *simHost) bool {
		progressed := false
		for id, dl := range h.timers {
			if dl <= now {
				delete(h.timers, id)
				h.c.HandleTimer(now, id)
				progressed = true
			}
		}
		return progressed
	}

	const maxIter = 5_000_000
	for iter := 0; iter < maxIter; iter++ {
		if done() {
			break
		}
		for {
			p := false
			p = deliverDue(&fwd, receiver) || p
			p = deliverDue(&bwd, sender) || p
			p = fireTimers(sender) || p
			p = fireTimers(receiver) || p
			schedule(sender.drain(), &fwd, dropFwd)
			schedule(receiver.drain(), &bwd, nil)
			if !p {
				break
			}
		}
		next, ok := earliest(sender, receiver, fwd, bwd)
		if !ok {
			break
		}
		now = next
	}
}

// runStream drives the two cores over the lossy in-memory link until the
// receiver has delivered numPayloads payloads, then asserts they arrived intact
// and in order. dropFwd drops the listed forward data sequence numbers once.
func runStream(t *testing.T, sender, receiver *simHost, base clock.Timestamp, numPayloads int, dropFwd map[uint32]bool) {
	t.Helper()

	// Hand the whole stream to the sender up front; pacing spreads it out.
	for i := 0; i < numPayloads; i++ {
		sender.c.Write(base, makePayload(i))
	}

	drive(t, sender, receiver, base, dropOnce(dropFwd), func() bool {
		return len(receiver.delivered) >= numPayloads
	})

	if got := len(receiver.delivered); got != numPayloads {
		t.Fatalf("delivered %d/%d payloads (loss not recovered)", got, numPayloads)
	}
	for i, p := range receiver.delivered {
		if len(p) != simPayload {
			t.Fatalf("payload %d: len=%d want %d", i, len(p), simPayload)
		}
		if got := binary.BigEndian.Uint32(p); got != uint32(i) {
			t.Fatalf("payload %d out of order: got index %d", i, got)
		}
	}
}

// TestSimFECRecovery drops one data packet per FEC row with ARQ=never (so no
// NAK/retransmission is possible) and confirms the receiver reconstructs every
// dropped packet from the FEC repair packets alone.
func TestSimFECRecovery(t *testing.T) {
	const (
		sndSocketID = 1
		rcvSocketID = 2
		sndISN      = 100
		rcvISN      = 5000
		numPayloads = 200
		fecCfg      = "fec,cols:10,rows:1,arq:never" // row-only FEC, no ARQ
	)
	base := clock.Timestamp(1_000_000)

	sender := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: rcvSocketID, PayloadSize: simPayload,
		SendISN: sndISN, RecvISN: rcvISN, MaxBW: 1 << 34, FilterConfig: fecCfg,
	}, base))
	receiver := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: sndSocketID, PayloadSize: simPayload,
		SendISN: rcvISN, RecvISN: sndISN, MaxBW: 1 << 34, FilterConfig: fecCfg,
	}, base))

	// One drop per row of 10 (recoverable by row FEC): seq 105, 115, 125, ...
	drop := map[uint32]bool{}
	wantRecovered := 0
	for s := uint32(sndISN + 5); s < sndISN+numPayloads; s += 10 {
		drop[s] = true
		wantRecovered++
	}

	runStream(t, sender, receiver, base, numPayloads, drop)

	st := receiver.c.Stats()
	if st.RecvFECRecov < uint64(wantRecovered) {
		t.Fatalf("FEC recovered %d packets, want >= %d", st.RecvFECRecov, wantRecovered)
	}
	if st.SentNAKs != 0 {
		t.Fatalf("receiver sent %d NAKs with arq:never (FEC should suppress all NAK)", st.SentNAKs)
	}
}

// TestSimEncryptedFECRecovery exercises encryption AND FEC together: the FEC
// engine must combine source and repair packets as the on-wire ciphertext (not
// the decrypted plaintext), and recovered packets must then decrypt cleanly.
// With ARQ=never the dropped packets can only return via FEC, so an end-to-end
// in-order delivery of every payload proves encrypted FEC works.
func TestSimEncryptedFECRecovery(t *testing.T) {
	const (
		sndISN      = 100
		rcvISN      = 5000
		numPayloads = 200
		fecCfg      = "fec,cols:10,rows:1,arq:never" // row-only FEC, no ARQ
	)
	base := clock.Timestamp(1_000_000)

	ctx, err := crypto.New(16) // shared AES-CTR context (same salt + SEKs)
	if err != nil {
		t.Fatal(err)
	}

	sender := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: 2, PayloadSize: simPayload, SendISN: sndISN, RecvISN: rcvISN,
		MaxBW: 1 << 34, FilterConfig: fecCfg, CryptoCtx: ctx, ActiveKey: packet.EncryptionEven,
	}, base))
	receiver := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: 1, PayloadSize: simPayload, SendISN: rcvISN, RecvISN: sndISN,
		MaxBW: 1 << 34, FilterConfig: fecCfg, CryptoCtx: ctx, ActiveKey: packet.EncryptionEven,
	}, base))

	// One drop per row of 10 (recoverable by row FEC): seq 105, 115, 125, ...
	drop := map[uint32]bool{}
	wantRecovered := 0
	for s := uint32(sndISN + 5); s < sndISN+numPayloads; s += 10 {
		drop[s] = true
		wantRecovered++
	}

	runStream(t, sender, receiver, base, numPayloads, drop)

	st := receiver.c.Stats()
	if st.RecvFECRecov < uint64(wantRecovered) {
		t.Fatalf("FEC recovered %d packets, want >= %d", st.RecvFECRecov, wantRecovered)
	}
	if st.RecvUndecrypt != 0 {
		t.Fatalf("RecvUndecrypt = %d, want 0 (recovered ciphertext must decrypt)", st.RecvUndecrypt)
	}
	if st.SentNAKs != 0 {
		t.Fatalf("receiver sent %d NAKs with arq:never (FEC should suppress all NAK)", st.SentNAKs)
	}
}

// TestSimFEC2DNoLoss exercises 2D (row+column, staircase) FEC with no loss. It
// regression-guards the staircase column FEC fix: before it, the receiver
// spuriously recovered packets and corrupted delivery.
func TestSimFEC2DNoLoss(t *testing.T) {
	const (
		sndISN      = 100
		rcvISN      = 5000
		numPayloads = 300
		fecCfg      = "fec,cols:8,rows:4,arq:onreq" // 2D, default staircase layout
	)
	base := clock.Timestamp(1_000_000)
	sender := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: 2, PayloadSize: simPayload, SendISN: sndISN, RecvISN: rcvISN,
		MaxBW: 1 << 34, FilterConfig: fecCfg,
	}, base))
	receiver := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: 1, PayloadSize: simPayload, SendISN: rcvISN, RecvISN: sndISN,
		MaxBW: 1 << 34, FilterConfig: fecCfg,
	}, base))
	runStream(t, sender, receiver, base, numPayloads, nil)
}

// TestSimFEC2DRecovery drops one packet per row (recoverable by the row
// dimension) with ARQ=never and confirms 2D staircase FEC reconstructs them all.
func TestSimFEC2DRecovery(t *testing.T) {
	const (
		sndISN      = 100
		rcvISN      = 5000
		numPayloads = 240
		fecCfg      = "fec,cols:8,rows:4,arq:never"
	)
	base := clock.Timestamp(1_000_000)
	sender := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: 2, PayloadSize: simPayload, SendISN: sndISN, RecvISN: rcvISN,
		MaxBW: 1 << 34, FilterConfig: fecCfg,
	}, base))
	receiver := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: 1, PayloadSize: simPayload, SendISN: rcvISN, RecvISN: sndISN,
		MaxBW: 1 << 34, FilterConfig: fecCfg,
	}, base))
	// One drop per row of 8 (row FEC recovers each): seq 103, 111, 119, ...
	drop := map[uint32]bool{}
	for s := uint32(sndISN + 3); s < sndISN+numPayloads; s += 8 {
		drop[s] = true
	}
	runStream(t, sender, receiver, base, numPayloads, drop)
	if st := receiver.c.Stats(); st.SentNAKs != 0 {
		t.Fatalf("receiver sent %d NAKs with arq:never (FEC should suppress NAK)", st.SentNAKs)
	}
}

// TestSimEncryptedLossRecovery runs the same lossy stream with AES-CTR
// encryption: the two cores share one crypto context, so the sender encrypts
// each data packet and the receiver decrypts it — exercising the core's encrypt
// AND decrypt paths (the interop test only covers encrypt). Recovered
// retransmissions must decrypt identically.
func TestSimEncryptedLossRecovery(t *testing.T) {
	const (
		sndSocketID = 1
		rcvSocketID = 2
		sndISN      = 100
		rcvISN      = 5000
		numPayloads = 400
	)
	base := clock.Timestamp(1_000_000)

	ctx, err := crypto.New(16) // shared AES-CTR context (same salt + SEKs)
	if err != nil {
		t.Fatal(err)
	}

	sender := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: rcvSocketID, PayloadSize: simPayload,
		SendISN: sndISN, RecvISN: rcvISN, MaxBW: 1 << 34,
		CryptoCtx: ctx, ActiveKey: packet.EncryptionEven,
	}, base))
	receiver := newSimHost(core.NewEstablished(core.Config{
		PeerSocketID: sndSocketID, PayloadSize: simPayload,
		SendISN: rcvISN, RecvISN: sndISN, MaxBW: 1 << 34,
		CryptoCtx: ctx, ActiveKey: packet.EncryptionEven,
	}, base))

	dropOnce := map[uint32]bool{150: true, 151: true, 152: true, 280: true, 333: true}
	runStream(t, sender, receiver, base, numPayloads, dropOnce)
}

// --- TSBPD playout ---

type tsbpdDelivery struct {
	at  clock.Timestamp
	idx uint32
}

type tsbpdArrival struct {
	at  clock.Timestamp
	pkt packet.Packet
}

// runTSBPD feeds a single live receiver core a stream of packets spaced by
// intervalUs (packet i carries wire timestamp i*intervalUs and arrives at
// base+i*intervalUs), optionally skipping dropIdx entirely (never delivered),
// and returns when each surviving packet was delivered.
func runTSBPD(t *testing.T, n int, intervalUs, delay clock.Microseconds, dropIdx int) []tsbpdDelivery {
	t.Helper()
	const rcvISN = 100
	base := clock.Timestamp(1_000_000)

	rcv := core.NewEstablished(core.Config{
		PeerSocketID: 1, PayloadSize: simPayload, SendISN: 9000, RecvISN: rcvISN,
		MaxBW: 1 << 34, Live: true, TsbpdDelay: delay,
	}, base)

	timers := make(map[core.TimerID]clock.Timestamp)
	var got []tsbpdDelivery
	drain := func(now clock.Timestamp) {
		for {
			o, ok := rcv.PollOutput()
			if !ok {
				break
			}
			switch v := o.(type) {
			case core.SetTimer:
				timers[v.ID] = v.Deadline
			case core.ClearTimer:
				delete(timers, v.ID)
			case core.SendPacket:
				if v.Owned {
					v.Packet.Release()
				}
			}
		}
		for {
			e, ok := rcv.PollEvent()
			if !ok {
				break
			}
			if d, ok := e.(core.DataReceived); ok {
				got = append(got, tsbpdDelivery{at: now, idx: binary.BigEndian.Uint32(d.Data)})
			}
		}
	}
	drain(base)

	var pending []tsbpdArrival
	for i := 0; i < n; i++ {
		if i == dropIdx {
			continue
		}
		ts := uint32(int64(intervalUs) * int64(i))
		payload := make([]byte, simPayload)
		binary.BigEndian.PutUint32(payload, uint32(i))
		p := packet.NewData(nil, uint32(rcvISN+i), ts, 1, payload)
		pending = append(pending, tsbpdArrival{
			at:  base.Add(intervalUs * clock.Microseconds(i)),
			pkt: p,
		})
	}

	expected := n
	if dropIdx >= 0 && dropIdx < n {
		expected = n - 1
	}

	now := base
	pi := 0
	const maxIter = 1_000_000
	for iter := 0; iter < maxIter; iter++ {
		if len(got) >= expected {
			break
		}
		for {
			progressed := false
			for pi < len(pending) && !pending[pi].at.After(now) {
				rcv.HandlePacket(now, pending[pi].pkt)
				pi++
				progressed = true
			}
			for id, dl := range timers {
				if !dl.After(now) {
					delete(timers, id)
					rcv.HandleTimer(now, id)
					progressed = true
				}
			}
			drain(now)
			if !progressed {
				break
			}
		}
		// Advance to the next event (earliest timer or next arrival).
		var next clock.Timestamp
		have := false
		for _, dl := range timers {
			if !have || dl.Before(next) {
				next, have = dl, true
			}
		}
		if pi < len(pending) && (!have || pending[pi].at.Before(next)) {
			next, have = pending[pi].at, true
		}
		if !have {
			break
		}
		now = next
	}
	return got
}

func TestTSBPDPlayout(t *testing.T) {
	const (
		n          = 30
		intervalUs = 10 * clock.Millisecond
		delay      = 100 * clock.Millisecond
	)
	base := clock.Timestamp(1_000_000)
	got := runTSBPD(t, n, intervalUs, delay, -1)

	if len(got) != n {
		t.Fatalf("delivered %d/%d", len(got), n)
	}
	for i, r := range got {
		if r.idx != uint32(i) {
			t.Fatalf("delivery %d out of order: got idx %d", i, r.idx)
		}
		// Each packet must be held until exactly arrival+delay.
		want := base.Add(intervalUs * clock.Microseconds(i)).Add(delay)
		if r.at != want {
			t.Fatalf("packet %d delivered at %d, want %d (TSBPD delay not honored)", i, r.at, want)
		}
	}
}

func TestTSBPDTooLateDrop(t *testing.T) {
	const (
		n          = 30
		intervalUs = 10 * clock.Millisecond
		delay      = 100 * clock.Millisecond
		dropIdx    = 12
	)
	base := clock.Timestamp(1_000_000)
	got := runTSBPD(t, n, intervalUs, delay, dropIdx)

	if len(got) != n-1 {
		t.Fatalf("delivered %d, want %d (dropped pkt should be skipped)", len(got), n-1)
	}
	for _, r := range got {
		if r.idx == dropIdx {
			t.Fatalf("dropped packet %d was delivered", dropIdx)
		}
		// Surviving packets still play out at their own arrival+delay.
		want := base.Add(intervalUs * clock.Microseconds(int(r.idx))).Add(delay)
		if r.at != want {
			t.Fatalf("packet %d delivered at %d, want %d", r.idx, r.at, want)
		}
	}
}

// earliest returns the soonest pending event time across both timer wheels and
// both in-flight queues.
func earliest(a, b *simHost, fwd, bwd []inflight) (clock.Timestamp, bool) {
	var best clock.Timestamp
	have := false
	consider := func(t clock.Timestamp) {
		if !have || t.Before(best) {
			best, have = t, true
		}
	}
	for _, dl := range a.timers {
		consider(dl)
	}
	for _, dl := range b.timers {
		consider(dl)
	}
	if len(fwd) > 0 {
		consider(fwd[0].arrival)
	}
	if len(bwd) > 0 {
		consider(bwd[0].arrival)
	}
	return best, have
}
