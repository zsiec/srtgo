package core

import (
	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/seq"
)

// Group is the pure coordination state machine for SRT connection bonding. A
// group is several full, independent connections (each its own handshake, ARQ,
// ACK/NAK, TSBPD, crypto) coordinated to share a sequence space and source
// timestamps so the receiver can merge them. The group performs no I/O and
// reads no clock; the host owns each member's socket and loop and drives the
// group (Write, RouteMember/PollDelivery) from one goroutine.
//
// Scope: broadcast mode (send every payload on every link; the receiver
// delivers the first arrival of each sequence and dedups the rest). Backup
// (active/standby failover) and balancing are later phases.
type Group struct {
	mode GroupMode

	members []*Conn

	// Send-side shared sequence + source-time epoch.
	nextSeq   seq.Number
	seqInit   bool
	sndTSBase uint32
	tsInit    bool

	// Receive-side dedup waterline: the highest sequence number delivered to the
	// application so far. A member delivery is forwarded only if its sequence is
	// strictly ahead of this (wrap-aware), so each packet is delivered once from
	// whichever link supplies it first.
	rcvWater seq.Number
	rcvInit  bool

	delivered fifo[[]byte]
	dedups    uint64
}

// GroupMode selects bonding behavior.
type GroupMode uint8

const (
	// GroupBroadcast sends every packet on all members; the receiver dedups.
	GroupBroadcast GroupMode = iota + 1
	// GroupBackup uses one active link with standby failover (later phase).
	GroupBackup
)

// NewGroup creates a bonding group in the given mode.
func NewGroup(mode GroupMode) *Group { return &Group{mode: mode} }

// AddMember registers an established member connection. The first member seeds
// the group's send sequence; later members are aligned to it.
func (g *Group) AddMember(c *Conn) {
	if !g.seqInit {
		g.nextSeq = c.sendBuf.NextSeq()
		g.seqInit = true
	} else if c.sendBuf.NextSeq() != g.nextSeq {
		c.sendBuf.OverrideNextSeq(g.nextSeq)
	}
	g.members = append(g.members, c)
}

// Members returns the member connections (for the host to drive their I/O).
func (g *Group) Members() []*Conn { return g.members }

// Write sends payload on every member with a shared sequence number and source
// timestamp. The members' outgoing packets land in their own output queues for
// the host to drain to each socket.
func (g *Group) Write(now clock.Timestamp, payload []byte) {
	if len(g.members) == 0 {
		return
	}
	if !g.tsInit {
		g.sndTSBase = now.SRTTimestamp()
		g.tsInit = true
	}
	srcTime := now.SRTTimestamp() - g.sndTSBase
	seqNo := g.nextSeq
	g.nextSeq = g.nextSeq.Inc()
	for _, m := range g.members {
		m.WriteCoordinated(now, payload, seqNo, srcTime)
	}
}

// RouteMember drains one member connection's events, forwarding deduplicated
// payloads to the group's delivery queue and discarding cross-link duplicates.
// The host calls this after feeding the member packets/timers. (Member outputs —
// SendPacket/SetTimer — are drained by the host directly to that member's socket.)
func (g *Group) RouteMember(m *Conn) {
	for {
		ev, ok := m.PollEvent()
		if !ok {
			return
		}
		if d, ok := ev.(DataReceived); ok {
			g.filterDelivery(seq.Number(d.Seq), d.Data)
		}
		// Connected/Closed/Failed per-member events are handled by the host's
		// membership management (failover is a later phase).
	}
}

// PollDelivery drains the next deduplicated payload for the application.
func (g *Group) PollDelivery() ([]byte, bool) { return g.delivered.pop() }

func (g *Group) filterDelivery(s seq.Number, payload []byte) {
	if g.rcvInit && !s.GreaterThan(g.rcvWater) {
		g.dedups++ // already delivered from another link (or stale)
		return
	}
	g.rcvWater = s
	g.rcvInit = true
	data := make([]byte, len(payload))
	copy(data, payload)
	g.delivered.push(data)
}
