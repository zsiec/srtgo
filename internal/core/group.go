package core

import (
	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/seq"
	"github.com/zsiec/srtgo/internal/tsbpd"
)

// GroupMode selects bonding behavior.
type GroupMode uint8

const (
	// GroupBroadcast sends every packet on all members; the receiver dedups.
	GroupBroadcast GroupMode = iota + 1
	// GroupBackup uses one active link with weighted standby failover: the
	// active link carries the stream, and if it stalls or breaks the highest-
	// weight standby is activated and recent packets are replayed from a buffer
	// so delivery continues seamlessly.
	GroupBackup
)

// backupState is a member's role/health in a backup group.
type backupState uint8

const (
	bsStandby        backupState = iota // ready, not sending
	bsActiveFresh                       // just activated, probing
	bsActiveStable                      // sending and acking normally
	bsActiveUnstable                    // active but no recent ack progress
	bsBroken                            // dead
)

func (s backupState) active() bool {
	return s == bsActiveFresh || s == bsActiveStable || s == bsActiveUnstable
}

// groupMember is one bonded connection plus its backup-mode bookkeeping.
type groupMember struct {
	conn   *Conn
	weight uint16

	state        backupState
	activeSince  clock.Timestamp
	lastProgress clock.Timestamp // last time the send buffer advanced (an ACK arrived)
	lastAckSeq   seq.Number
	ackSeqSet    bool

	tbSynced bool // TSBPD time base aligned to the group reference
}

// bufferedMsg is a sent payload retained for failover replay.
type bufferedMsg struct {
	seqNo   seq.Number
	srcTime uint32
	payload []byte
}

const (
	defaultStabTimeout  = 1 * clock.Second
	defaultSenderBufCap = 2048
)

// Group is the pure coordination state machine for SRT connection bonding: a
// group is several full, independent connections (each its own handshake, ARQ,
// ACK/NAK, TSBPD, crypto) coordinated to share a sequence space and source
// timestamps, with deduplication by sequence at delivery. It performs no I/O
// and reads no clock; the host owns each member's socket and loop and drives
// the group (Write, Monitor, RouteMember/PollDelivery) from one goroutine.
type Group struct {
	mode        GroupMode
	members     []*groupMember
	stabTimeout clock.Microseconds

	// Send-side shared sequence + source-time epoch.
	nextSeq   seq.Number
	seqInit   bool
	sndTSBase uint32
	tsInit    bool

	// Backup-mode sender buffer (recent payloads, replayed on failover).
	senderBuf    []bufferedMsg
	senderBufCap int

	// Receive-side merge: members deliver their own streams in sequence order;
	// the group merges them in order via a small reorder buffer, delivering each
	// sequence once. deliverNext is the next sequence to deliver; pending holds
	// buffered out-of-merge-order deliveries; maxSeen is the highest sequence
	// seen. A gap at deliverNext is skipped only once the stream has advanced
	// past it by groupReorderWindow (i.e. every link has moved on — the packet
	// was lost on all of them).
	pending     map[uint32][]byte
	deliverNext seq.Number
	dnInit      bool
	maxSeen     seq.Number
	maxSeenSet  bool

	// Group TSBPD reference, captured from the first member to anchor and
	// applied to all members so they play out each sequence in lockstep.
	groupTB tsbpd.GroupTimeBase
	tbSet   bool

	delivered fifo[[]byte]
	dedups    uint64
}

// groupReorderWindow bounds how far past a gap the merge advances before
// declaring the gap lost on every link and skipping it.
const groupReorderWindow = 256

// NewGroup creates a bonding group in the given mode.
func NewGroup(mode GroupMode) *Group {
	return &Group{
		mode:         mode,
		stabTimeout:  defaultStabTimeout,
		senderBufCap: defaultSenderBufCap,
		pending:      make(map[uint32][]byte),
	}
}

// SetStabilityTimeout sets the minimum backup stability timeout (the period a
// member may go without ACK progress before it is considered unstable).
func (g *Group) SetStabilityTimeout(d clock.Microseconds) {
	if d > 0 {
		g.stabTimeout = d
	}
}

// AddMember registers an established member connection with a priority weight
// (used by backup mode; broadcast ignores it). The first member seeds the
// group's send sequence; later members are aligned to it.
func (g *Group) AddMember(c *Conn, weight uint16) {
	if !g.seqInit {
		g.nextSeq = c.sendBuf.NextSeq()
		g.seqInit = true
	} else if c.sendBuf.NextSeq() != g.nextSeq {
		c.sendBuf.OverrideNextSeq(g.nextSeq)
	}
	g.members = append(g.members, &groupMember{conn: c, weight: weight, state: bsStandby})
}

// Members returns the member connections (for the host to drive their I/O).
func (g *Group) Members() []*Conn {
	conns := make([]*Conn, len(g.members))
	for i, m := range g.members {
		conns[i] = m.conn
	}
	return conns
}

// Write sends payload on the appropriate member(s) with a shared sequence number
// and source timestamp. Outgoing packets land in the members' own output queues
// for the host to drain to each socket.
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

	switch g.mode {
	case GroupBackup:
		for _, mc := range g.activeMembers(now) {
			mc.conn.WriteCoordinated(now, payload, seqNo, srcTime)
		}
		g.bufferMsg(seqNo, srcTime, payload)
	default: // broadcast
		for _, mc := range g.members {
			mc.conn.WriteCoordinated(now, payload, seqNo, srcTime)
		}
	}
}

// Monitor re-qualifies backup member health; the host calls it periodically. It
// promotes a standby if no healthy active member remains (with sender-buffer
// replay), so failover happens even during a send pause.
func (g *Group) Monitor(now clock.Timestamp) {
	if g.mode != GroupBackup {
		return
	}
	g.activeMembers(now)
}

// activeMembers qualifies every member's backup state and returns those that
// should carry this write. If no healthy (fresh/stable) active member exists, it
// activates the highest-weight standby and replays the sender buffer onto it.
func (g *Group) activeMembers(now clock.Timestamp) []*groupMember {
	var active []*groupMember
	healthy := false
	for _, mc := range g.members {
		g.qualify(now, mc)
		if mc.state.active() {
			active = append(active, mc)
			if mc.state == bsActiveFresh || mc.state == bsActiveStable {
				healthy = true
			}
		}
	}
	if !healthy {
		if mc := g.bestStandby(); mc != nil {
			g.activate(now, mc)
			active = append(active, mc)
		}
	}
	return active
}

// qualify updates one member's backup state from its connection's progress.
func (g *Group) qualify(now clock.Timestamp, mc *groupMember) {
	if mc.conn.closed {
		mc.state = bsBroken
		return
	}
	if mc.state == bsStandby || mc.state == bsBroken {
		return
	}

	// Track ACK progress: the send buffer's start advances as the peer ACKs.
	acked := mc.conn.sendBuf.StartSeq()
	if !mc.ackSeqSet || acked.GreaterThan(mc.lastAckSeq) {
		mc.lastAckSeq = acked
		mc.ackSeqSet = true
		mc.lastProgress = now
	}

	// Dynamic stability timeout: max(min, 2*RTT + 4*RTTVar).
	timeout := g.stabTimeout
	if dyn := mc.conn.rtt*2 + mc.conn.rttVar*4; dyn > timeout {
		timeout = dyn
	}

	since := now.Sub(mc.lastProgress)
	switch {
	case since > 4*timeout:
		mc.state = bsBroken
	case since > timeout:
		mc.state = bsActiveUnstable
	case mc.state == bsActiveUnstable:
		mc.state = bsActiveStable // recovered
	case mc.state == bsActiveFresh && now.Sub(mc.activeSince) > timeout:
		mc.state = bsActiveStable
	}
}

// bestStandby returns the highest-weight standby member, or nil.
func (g *Group) bestStandby() *groupMember {
	var best *groupMember
	for _, mc := range g.members {
		if mc.state != bsStandby || mc.conn.closed {
			continue
		}
		if best == nil || mc.weight > best.weight {
			best = mc
		}
	}
	return best
}

// activate promotes a standby to active and replays the sender buffer onto it so
// the receiver catches the recent packets the failed link did not deliver.
// Duplicates are harmless: the receiver dedups them.
func (g *Group) activate(now clock.Timestamp, mc *groupMember) {
	mc.state = bsActiveFresh
	mc.activeSince = now
	mc.lastProgress = now
	mc.ackSeqSet = false
	for _, m := range g.senderBuf {
		mc.conn.WriteCoordinated(now, m.payload, m.seqNo, m.srcTime)
	}
}

// bufferMsg retains a sent payload for failover replay, pruning by both a count
// cap and the furthest-progressed link's ACK (delivered packets are safe at the
// receiver and need not be replayed).
func (g *Group) bufferMsg(seqNo seq.Number, srcTime uint32, payload []byte) {
	data := make([]byte, len(payload))
	copy(data, payload)
	g.senderBuf = append(g.senderBuf, bufferedMsg{seqNo: seqNo, srcTime: srcTime, payload: data})

	// Drop messages already acked on the furthest-progressed active link.
	var maxAcked seq.Number
	haveAck := false
	for _, mc := range g.members {
		if !mc.state.active() || !mc.ackSeqSet {
			continue
		}
		if !haveAck || mc.lastAckSeq.GreaterThan(maxAcked) {
			maxAcked, haveAck = mc.lastAckSeq, true
		}
	}
	if haveAck {
		i := 0
		for i < len(g.senderBuf) && g.senderBuf[i].seqNo.LessThan(maxAcked) {
			i++
		}
		if i > 0 {
			g.senderBuf = g.senderBuf[i:]
		}
	}
	if len(g.senderBuf) > g.senderBufCap {
		g.senderBuf = g.senderBuf[len(g.senderBuf)-g.senderBufCap:]
	}
}

// RouteMember drains one member connection's events, forwarding deduplicated
// payloads to the group's delivery queue and discarding cross-link duplicates.
// In backup mode it also advances standby (idle) members' receivers to the
// active link's *receive* progress (its ACK sequence, not the playout waterline)
// so a standby is ready to accept packets the instant a failover begins — TSBPD
// may hold delivery for seconds, far longer than the failover window.
func (g *Group) RouteMember(c *Conn) {
	var source *groupMember
	for _, mc := range g.members {
		if mc.conn == c {
			source = mc
			break
		}
	}

	// Keep all members' TSBPD time bases in lockstep before any delivery is due,
	// so the dedup waterline merges links without dropping a slower link's copy
	// of a packet the faster link skipped. (Members deliver only delay (>=tens of
	// ms) after their first packet, so the override always lands first.)
	g.syncTimebases()

	if g.mode == GroupBackup && source != nil {
		ackSeq := source.conn.recvBuf.ACKSequence() // highest contiguous received
		for _, mc := range g.members {
			if mc == source || mc.conn.closed {
				continue
			}
			if mc.conn.recvBuf.IsEmpty() && ackSeq.GreaterThan(mc.conn.recvBuf.StartSeq()) {
				mc.conn.resetRecvTo(ackSeq)
			}
		}
	}

	for {
		ev, ok := c.PollEvent()
		if !ok {
			return
		}
		if d, ok := ev.(DataReceived); ok {
			g.filterDelivery(seq.Number(d.Seq), d.Data)
		}
	}
}

// syncTimebases captures the group's TSBPD reference from the first member to
// anchor one, then applies it to every member that has not yet adopted it (new
// members, or a standby that was just reset for failover). All members then map
// a sequence to the same playout instant.
func (g *Group) syncTimebases() {
	if !g.tbSet {
		for _, mc := range g.members {
			if mc.conn.tsbpdTimer != nil && mc.conn.tsbpdBaseSet {
				g.groupTB = mc.conn.tsbpdTimer.GetInternalTimeBase()
				g.tbSet = true
				mc.tbSynced = true
				break
			}
		}
		if !g.tbSet {
			return
		}
	}
	for _, mc := range g.members {
		if mc.tbSynced || mc.conn.tsbpdTimer == nil {
			continue
		}
		mc.conn.tsbpdTimer.ApplyGroupTime(g.groupTB, mc.conn.tsbpdTimer.Delay())
		mc.conn.tsbpdBaseSet = true
		mc.tbSynced = true
	}
}

// PollDelivery drains the next deduplicated payload for the application.
func (g *Group) PollDelivery() ([]byte, bool) { return g.delivered.pop() }

func (g *Group) filterDelivery(s seq.Number, payload []byte) {
	if !g.dnInit {
		g.deliverNext = s
		g.dnInit = true
	}
	if s.LessThan(g.deliverNext) {
		g.dedups++ // already delivered (from this or another link)
		return
	}
	if _, ok := g.pending[s.Value()]; ok {
		g.dedups++ // duplicate copy from another link
		return
	}
	data := make([]byte, len(payload))
	copy(data, payload)
	g.pending[s.Value()] = data
	if !g.maxSeenSet || s.GreaterThan(g.maxSeen) {
		g.maxSeen, g.maxSeenSet = s, true
	}
	g.drainPending()
}

// drainPending delivers buffered packets in sequence order, skipping a gap only
// once the stream has advanced past it by groupReorderWindow (lost on all links).
func (g *Group) drainPending() {
	for {
		if d, ok := g.pending[g.deliverNext.Value()]; ok {
			delete(g.pending, g.deliverNext.Value())
			g.delivered.push(d)
			g.deliverNext = g.deliverNext.Inc()
			continue
		}
		if g.maxSeenSet && g.maxSeen.GreaterThan(g.deliverNext.Add(groupReorderWindow)) {
			g.deliverNext = g.deliverNext.Inc() // gap lost on every link; skip it
			continue
		}
		return
	}
}
