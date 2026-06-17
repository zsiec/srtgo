package core_test

import (
	"encoding/binary"
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
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
// model can target data packets by sequence number.
type outDatagram struct {
	data   []byte
	isData bool
	seqNo  uint32
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

	// Hand the whole stream to the sender up front; pacing spreads it out.
	for i := 0; i < numPayloads; i++ {
		sender.c.Write(base, makePayload(i))
	}

	var fwd, bwd []inflight
	now := base

	schedule := func(out []outDatagram, q *[]inflight, drop map[uint32]bool) {
		for _, dg := range out {
			if dg.isData && drop != nil && drop[dg.seqNo] {
				delete(drop, dg.seqNo) // drop once, let the retransmit through
				continue
			}
			*q = append(*q, inflight{arrival: now.Add(linkDelay), data: dg.data})
		}
	}

	// Initial drain (the up-front Writes produced data + the constructors armed timers).
	schedule(sender.drain(), &fwd, dropOnce)
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
		if len(receiver.delivered) >= numPayloads {
			break
		}
		// Settle everything due at the current instant.
		for {
			p := false
			p = deliverDue(&fwd, receiver) || p
			p = deliverDue(&bwd, sender) || p
			p = fireTimers(sender) || p
			p = fireTimers(receiver) || p
			schedule(sender.drain(), &fwd, dropOnce)
			schedule(receiver.drain(), &bwd, nil)
			if !p {
				break
			}
		}
		// Advance virtual time to the next scheduled event.
		next, ok := earliest(sender, receiver, fwd, bwd)
		if !ok {
			break
		}
		now = next
	}

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
