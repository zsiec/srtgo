package core_test

import (
	"encoding/binary"
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/packet"
)

// This file proves broadcast connection bonding: a sender group fans each
// payload out on two independent links with a shared sequence number and
// source timestamp; a receiver group merges the two links, delivering each
// payload exactly once (deduplicating redundant copies). With two links each
// permanently dropping a *different* set of packets, every payload still
// arrives via the other link — seamless redundancy with no shared loss.

// bondCore wraps a core.Conn with a timer wheel for the bonding simulation.
type bondCore struct {
	c      *core.Conn
	timers map[core.TimerID]clock.Timestamp
}

func newBondCore(c *core.Conn) *bondCore {
	return &bondCore{c: c, timers: make(map[core.TimerID]clock.Timestamp)}
}

// drainOut drains the core's outputs into datagrams (timers updated in place).
// Events are routed separately so the group can deduplicate deliveries.
func (b *bondCore) drainOut() []outDatagram {
	var out []outDatagram
	for {
		o, ok := b.c.PollOutput()
		if !ok {
			return out
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
			b.timers[v.ID] = v.Deadline
		case core.ClearTimer:
			delete(b.timers, v.ID)
		}
	}
}

func TestSimBroadcastBonding(t *testing.T) {
	const (
		sharedISN   = 100
		rcvSendISN  = 9000
		numPayloads = 300
		tsbpd       = 100 * clock.Millisecond
	)
	base := clock.Timestamp(1_000_000)

	mkSnd := func(peerID uint32) *core.Conn {
		return core.NewEstablished(core.Config{
			PeerSocketID: peerID, PayloadSize: simPayload,
			SendISN: sharedISN, RecvISN: rcvSendISN, MaxBW: 1 << 34,
		}, base)
	}
	mkRcv := func(peerID uint32) *core.Conn {
		return core.NewEstablished(core.Config{
			PeerSocketID: peerID, PayloadSize: simPayload,
			SendISN: rcvSendISN, RecvISN: sharedISN, MaxBW: 1 << 34,
			Live: true, TsbpdDelay: tsbpd,
		}, base)
	}
	// Link A: sndA <-> rcvA. Link B: sndB <-> rcvB.
	sndA, rcvA := newBondCore(mkSnd(2)), newBondCore(mkRcv(1))
	sndB, rcvB := newBondCore(mkSnd(4)), newBondCore(mkRcv(3))

	sndGroup := core.NewGroup(core.GroupBroadcast)
	sndGroup.AddMember(sndA.c, 0)
	sndGroup.AddMember(sndB.c, 0)

	rcvGroup := core.NewGroup(core.GroupBroadcast)
	rcvGroup.AddMember(rcvA.c, 0)
	rcvGroup.AddMember(rcvB.c, 0)

	// Permanent, disjoint per-link loss: every sequence survives on at least one
	// link, so redundancy must deliver all of them.
	dropA := map[uint32]bool{105: true, 106: true, 150: true, 222: true}
	dropB := map[uint32]bool{120: true, 175: true, 176: true, 250: true}

	// Send the whole stream up front; each member emits immediately.
	for i := 0; i < numPayloads; i++ {
		p := make([]byte, simPayload)
		binary.BigEndian.PutUint32(p, uint32(i))
		sndGroup.Write(base, p)
	}

	// In-flight queues per direction per link.
	var fwdA, bwdA, fwdB, bwdB []inflight
	now := base

	schedule := func(out []outDatagram, q *[]inflight, drop map[uint32]bool) {
		for _, dg := range out {
			if dg.isData && drop != nil && drop[dg.seqNo] {
				continue // permanent drop on this link
			}
			*q = append(*q, inflight{arrival: now.Add(linkDelay), data: dg.data})
		}
	}

	// Initial drain of all four cores (the up-front writes + constructor timers).
	schedule(sndA.drainOut(), &fwdA, dropA)
	schedule(rcvA.drainOut(), &bwdA, nil)
	schedule(sndB.drainOut(), &fwdB, dropB)
	schedule(rcvB.drainOut(), &bwdB, nil)

	var delivered [][]byte
	collect := func() {
		for {
			d, ok := rcvGroup.PollDelivery()
			if !ok {
				return
			}
			delivered = append(delivered, d)
		}
	}

	deliverDue := func(q *[]inflight, dst *bondCore) bool {
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
	fireTimers := func(b *bondCore) bool {
		progressed := false
		for id, dl := range b.timers {
			if dl <= now {
				delete(b.timers, id)
				b.c.HandleTimer(now, id)
				progressed = true
			}
		}
		return progressed
	}

	const maxIter = 10_000_000
	for iter := 0; iter < maxIter; iter++ {
		if len(delivered) >= numPayloads {
			break
		}
		for {
			p := false
			p = deliverDue(&fwdA, rcvA) || p
			p = deliverDue(&bwdA, sndA) || p
			p = deliverDue(&fwdB, rcvB) || p
			p = deliverDue(&bwdB, sndB) || p
			p = fireTimers(sndA) || p
			p = fireTimers(rcvA) || p
			p = fireTimers(sndB) || p
			p = fireTimers(rcvB) || p

			schedule(sndA.drainOut(), &fwdA, dropA)
			schedule(sndB.drainOut(), &fwdB, dropB)
			schedule(rcvA.drainOut(), &bwdA, nil)
			schedule(rcvB.drainOut(), &bwdB, nil)
			// Route receiver deliveries through the group's dedup.
			rcvGroup.RouteMember(rcvA.c)
			rcvGroup.RouteMember(rcvB.c)
			collect()
			if !p {
				break
			}
		}
		next, ok := earliestN(now, []*bondCore{sndA, rcvA, sndB, rcvB}, [][]inflight{fwdA, bwdA, fwdB, bwdB})
		if !ok {
			break
		}
		now = next
	}

	if len(delivered) != numPayloads {
		t.Fatalf("group delivered %d/%d payloads (redundancy failed)", len(delivered), numPayloads)
	}
	for i, d := range delivered {
		if got := binary.BigEndian.Uint32(d); got != uint32(i) {
			t.Fatalf("delivery %d out of order: got index %d", i, got)
		}
	}
}

// TestSimBackupFailover streams over a weighted backup group, kills the active
// link mid-stream, and confirms the group fails over to the standby (replaying
// its sender buffer) so every payload is still delivered in order. The high
// TSBPD latency gives the failover window time to complete before playout.
func TestSimBackupFailover(t *testing.T) {
	const (
		sharedISN    = 100
		rcvSendISN   = 9000
		numPayloads  = 200
		writeEvery   = 5 * clock.Millisecond
		tsbpd        = 2 * clock.Second        // generous buffer to cover failover
		stab         = 150 * clock.Millisecond // quick instability detection
		killAt       = 500 * clock.Millisecond // kill the active link partway in
		monitorEvery = 50 * clock.Millisecond
	)
	base := clock.Timestamp(1_000_000)

	mkSnd := func(peerID uint32) *core.Conn {
		return core.NewEstablished(core.Config{
			PeerSocketID: peerID, PayloadSize: simPayload,
			SendISN: sharedISN, RecvISN: rcvSendISN, MaxBW: 1 << 34,
		}, base)
	}
	mkRcv := func(peerID uint32) *core.Conn {
		return core.NewEstablished(core.Config{
			PeerSocketID: peerID, PayloadSize: simPayload,
			SendISN: rcvSendISN, RecvISN: sharedISN, MaxBW: 1 << 34,
			Live: true, TsbpdDelay: tsbpd,
		}, base)
	}
	sndA, rcvA := newBondCore(mkSnd(2)), newBondCore(mkRcv(1)) // weight 10 (preferred)
	sndB, rcvB := newBondCore(mkSnd(4)), newBondCore(mkRcv(3)) // weight 5 (standby)

	sndGroup := core.NewGroup(core.GroupBackup)
	sndGroup.SetStabilityTimeout(stab)
	sndGroup.AddMember(sndA.c, 10)
	sndGroup.AddMember(sndB.c, 5)

	rcvGroup := core.NewGroup(core.GroupBackup)
	rcvGroup.AddMember(rcvA.c, 10)
	rcvGroup.AddMember(rcvB.c, 5)

	var fwdA, bwdA, fwdB, bwdB []inflight
	now := base
	killTime := base.Add(killAt)

	schedule := func(out []outDatagram, q *[]inflight, dead bool) {
		for _, dg := range out {
			if dead {
				continue // link is down — drop everything
			}
			*q = append(*q, inflight{arrival: now.Add(linkDelay), data: dg.data})
		}
	}
	drainAll := func() {
		// Link A is killed (both directions) once now >= killTime.
		deadA := !now.Before(killTime)
		schedule(sndA.drainOut(), &fwdA, deadA)
		schedule(rcvA.drainOut(), &bwdA, deadA)
		schedule(sndB.drainOut(), &fwdB, false)
		schedule(rcvB.drainOut(), &bwdB, false)
	}

	var delivered [][]byte
	collect := func() {
		rcvGroup.RouteMember(rcvA.c)
		rcvGroup.RouteMember(rcvB.c)
		for {
			d, ok := rcvGroup.PollDelivery()
			if !ok {
				break
			}
			delivered = append(delivered, d)
		}
	}

	deliverDue := func(q *[]inflight, dst *bondCore) bool {
		pr := false
		for len(*q) > 0 && (*q)[0].arrival <= now {
			dg := (*q)[0]
			*q = (*q)[1:]
			if p, err := packet.Parse(dg.data, nil); err == nil {
				dst.c.HandlePacket(now, p)
			}
			pr = true
		}
		return pr
	}
	fireTimers := func(b *bondCore) bool {
		pr := false
		for id, dl := range b.timers {
			if dl <= now {
				delete(b.timers, id)
				b.c.HandleTimer(now, id)
				pr = true
			}
		}
		return pr
	}

	nextWrite := 0
	nextMonitor := base.Add(monitorEvery)

	const maxIter = 20_000_000
	for iter := 0; iter < maxIter; iter++ {
		if len(delivered) >= numPayloads {
			break
		}
		// Due application writes.
		for nextWrite < numPayloads && !base.Add(writeEvery*clock.Microseconds(nextWrite)).After(now) {
			p := make([]byte, simPayload)
			binary.BigEndian.PutUint32(p, uint32(nextWrite))
			sndGroup.Write(now, p)
			nextWrite++
		}
		// Due monitor tick.
		if !nextMonitor.After(now) {
			sndGroup.Monitor(now)
			nextMonitor = nextMonitor.Add(monitorEvery)
		}
		// Settle everything due at this instant.
		for {
			pr := false
			pr = deliverDue(&fwdA, rcvA) || pr
			pr = deliverDue(&bwdA, sndA) || pr
			pr = deliverDue(&fwdB, rcvB) || pr
			pr = deliverDue(&bwdB, sndB) || pr
			pr = fireTimers(sndA) || pr
			pr = fireTimers(rcvA) || pr
			pr = fireTimers(sndB) || pr
			pr = fireTimers(rcvB) || pr
			drainAll()
			collect()
			if !pr {
				break
			}
		}
		// Advance to the next event.
		next, ok := earliestN(now, []*bondCore{sndA, rcvA, sndB, rcvB}, [][]inflight{fwdA, bwdA, fwdB, bwdB})
		if nextWrite < numPayloads {
			wt := base.Add(writeEvery * clock.Microseconds(nextWrite))
			if !ok || wt.Before(next) {
				next, ok = wt, true
			}
		}
		if !ok || nextMonitor.Before(next) {
			next, ok = nextMonitor, true
		}
		if !ok {
			break
		}
		now = next
	}

	if len(delivered) != numPayloads {
		t.Fatalf("group delivered %d/%d payloads (failover lost data)", len(delivered), numPayloads)
	}
	for i, d := range delivered {
		if got := binary.BigEndian.Uint32(d); got != uint32(i) {
			t.Fatalf("delivery %d out of order: got index %d", i, got)
		}
	}
}

// earliestN returns the soonest pending event across the given timer wheels and
// in-flight queues.
func earliestN(now clock.Timestamp, cores []*bondCore, queues [][]inflight) (clock.Timestamp, bool) {
	var best clock.Timestamp
	have := false
	consider := func(t clock.Timestamp) {
		if !have || t.Before(best) {
			best, have = t, true
		}
	}
	for _, c := range cores {
		for _, dl := range c.timers {
			consider(dl)
		}
	}
	for _, q := range queues {
		if len(q) > 0 {
			consider(q[0].arrival)
		}
	}
	return best, have
}
