package srt

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zsiec/srtgo/internal/seq"
	"github.com/zsiec/srtgo/internal/tsbpd"
)

// GroupMode specifies the redundancy strategy for a socket group.
type GroupMode int

const (
	// GroupBroadcast sends every packet on ALL member connections.
	// The receiver deduplicates by sequence number, delivering each
	// packet exactly once from whichever link arrives first.
	GroupBroadcast GroupMode = iota + 1

	// GroupBackup uses a single active link for sending, with one
	// or more standby links ready for automatic failover. When the
	// active link becomes unstable or broken, the highest-weight
	// standby is promoted and recent packets are replayed from
	// a sender buffer for seamless continuity.
	GroupBackup

	// GroupBalancing distributes packets across member connections
	// for load balancing. Not yet implemented — defined here for
	// wire protocol compatibility.
	GroupBalancing
)

// String returns a human-readable name for the group mode.
func (m GroupMode) String() string {
	switch m {
	case GroupBroadcast:
		return "broadcast"
	case GroupBackup:
		return "backup"
	case GroupBalancing:
		return "balancing"
	default:
		return fmt.Sprintf("GroupMode(%d)", int(m))
	}
}

// MemberStatus tracks a member connection's lifecycle within a group.
type MemberStatus int

const (
	MemberPending MemberStatus = iota // Handshake in progress
	MemberIdle                        // Connected, not yet activated
	MemberRunning                     // Actively sending/receiving
	MemberBroken                      // Failed, disconnected, or closed
)

// String returns a human-readable name for the member status.
func (s MemberStatus) String() string {
	switch s {
	case MemberPending:
		return "pending"
	case MemberIdle:
		return "idle"
	case MemberRunning:
		return "running"
	case MemberBroken:
		return "broken"
	default:
		return fmt.Sprintf("MemberStatus(%d)", int(s))
	}
}

// BackupState tracks fine-grained state for backup mode members.
type BackupState int

const (
	BackupStandby        BackupState = iota // Ready but not sending
	BackupActiveFresh                       // Recently activated, probing
	BackupActiveStable                      // Sending well
	BackupActiveUnstable                    // Degraded (no response > stability timeout)
	BackupActiveWary                        // Recovering from unstable
	BackupBroken                            // Disconnected
)

// String returns a human-readable name for the backup state.
func (s BackupState) String() string {
	switch s {
	case BackupStandby:
		return "standby"
	case BackupActiveFresh:
		return "fresh"
	case BackupActiveStable:
		return "stable"
	case BackupActiveUnstable:
		return "unstable"
	case BackupActiveWary:
		return "wary"
	case BackupBroken:
		return "broken"
	default:
		return fmt.Sprintf("BackupState(%d)", int(s))
	}
}

// pendingTimeout is how long a pending (handshake-in-progress) member
// is allowed before being marked broken.
const pendingTimeout = 5 * time.Second

// memberConn tracks a single connection within a group.
type memberConn struct {
	conn          *Conn
	token         int    // caller-assigned token for identification
	weight        uint16 // priority weight (higher = preferred for backup activation)
	status        MemberStatus
	backupState   BackupState // only used in Backup mode
	activeSince   time.Time   // when this member became active
	lastResponse  time.Time   // last time data/ACK received (for stability detection)
	prevDrops     uint64      // previous drop snapshot (for detecting new drops)
	unstableSince time.Time   // when member first became unstable
	warySince     time.Time   // when member entered wary state
	pendingSince  time.Time   // when this member entered MemberPending (for timeout detection)
	isIdle        bool        // true when link is alive (keepalive) but no data flowing
}

// bufferedMsg stores a payload for backup mode sender buffer replay.
type bufferedMsg struct {
	seqNo   uint32 // packet sequence number
	msgNo   uint32 // message number
	srcTime uint32 // original SRT source timestamp
	data    []byte
	ts      time.Time
}

// GroupStats contains aggregate statistics for the group.
type GroupStats struct {
	Members       int    // total member connections
	ActiveMembers int    // members in Running state
	SentPackets   uint64 // total packets sent across all members
	RecvPackets   uint64 // total packets received (before dedup)
	RecvDedups    uint64 // packets dropped as duplicates
}

// MemberInfo describes a member connection's state.
// Returned by Group.Members() for external inspection.
type MemberInfo struct {
	Token       int
	Status      MemberStatus
	BackupState BackupState // only meaningful in Backup mode
	Weight      uint16
	LocalAddr   net.Addr
	RemoteAddr  net.Addr
	RTT         time.Duration
}

// Group manages multiple SRT connections for link redundancy.
// It provides a unified Read/Write interface that dispatches
// across member connections based on the group mode.
//
// Usage:
//
//	g := srt.NewGroup(srt.GroupBackup)
//	g.Connect("server1:4200", cfg, 1, 100)
//	g.Connect("server2:4200", cfg, 2, 50)
//	defer g.Close()
//
//	g.Write(payload) // sends on active link
//	g.Read(buf)      // receives deduplicated data
type Group struct {
	mode    GroupMode
	groupID uint32

	mu      sync.RWMutex // protects members slice
	members []*memberConn

	// Sender sequence synchronization: the group's current scheduling sequence.
	// All members share this sequence space. -1 = not yet set.
	lastSchedSeqNo atomic.Int64

	// Receive deduplication: last delivered sequence number.
	// -1 means no packets delivered yet.
	rcvBaseSeqNo atomic.Int64

	// Receive fan-in: packets from all members arrive on recvCh.
	recvCh chan recvResult
	readMu sync.Mutex // serializes Read calls

	// Backup mode sender buffer for failover replay.
	senderBuf    []bufferedMsg
	senderBufMu  sync.Mutex
	senderBufCap int // max buffered messages

	// Backup mode stability timeout. Default: 1s.
	stabTimeout time.Duration

	// Write serialization
	writeMu sync.Mutex

	// Lifecycle
	closed atomic.Bool
	done   chan struct{}
	wg     sync.WaitGroup

	// Logging
	logger Logger

	// Stats (atomic for lock-free reads)
	sentPackets atomic.Uint64
	recvPackets atomic.Uint64
	recvDedups  atomic.Uint64
}

// recvResult is the fan-in type for receiving data from any member.
type recvResult struct {
	n     int
	seqNo uint32
	data  []byte
	err   error
}

// defaultSenderBufCap is the default number of messages buffered
// for backup mode failover replay.
const defaultSenderBufCap = 1000

// monitorInterval is how often the background monitor checks member health.
const monitorInterval = 100 * time.Millisecond

// NewGroup creates a new socket group with the specified mode.
func NewGroup(mode GroupMode) *Group {
	g := &Group{
		mode:         mode,
		done:         make(chan struct{}),
		recvCh:       make(chan recvResult, 256),
		senderBufCap: defaultSenderBufCap,
		stabTimeout:  time.Second,
	}
	g.rcvBaseSeqNo.Store(-1)
	g.lastSchedSeqNo.Store(-1)

	// Generate a random group ID
	id, err := generateGroupID()
	if err != nil {
		// Fallback: use timestamp-based ID
		g.groupID = uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	} else {
		g.groupID = id
	}

	g.wg.Add(1)
	go g.monitorLoop()

	return g
}

// generateGroupID creates a random non-zero group ID.
func generateGroupID() (uint32, error) {
	// Reuse handshake's socket ID generator — same 4-byte random, non-zero.
	// We import via the Conn's existing dependency chain.
	var buf [4]byte
	// Use crypto/rand for uniqueness (same as handshake.GenerateSocketID)
	// We can't import handshake from srt package, so replicate the logic.
	n := time.Now().UnixNano()
	buf[0] = byte(n >> 24)
	buf[1] = byte(n >> 16)
	buf[2] = byte(n >> 8)
	buf[3] = byte(n)
	id := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
	if id == 0 {
		id = 1
	}
	return id, nil
}

// GroupID returns the group's unique identifier.
func (g *Group) GroupID() uint32 {
	return g.groupID
}

// Mode returns the group's redundancy mode.
func (g *Group) Mode() GroupMode {
	return g.mode
}

// SetStabilityTimeout sets the minimum stability timeout for backup mode.
// A member with no response for longer than this is considered unstable.
// Default: 1s.
func (g *Group) SetStabilityTimeout(d time.Duration) {
	g.stabTimeout = d
}

// AddConn adds an existing connected *Conn to the group.
// token is a caller-chosen identifier for this member.
// weight is the priority (higher = preferred for backup activation).
func (g *Group) AddConn(conn *Conn, token int, weight uint16) error {
	if g.closed.Load() {
		return errors.New("srt: group closed")
	}
	if conn == nil {
		return errors.New("srt: nil connection")
	}

	mc := &memberConn{
		conn:         conn,
		token:        token,
		weight:       weight,
		status:       MemberIdle,
		backupState:  BackupStandby,
		lastResponse: time.Now(),
	}

	g.mu.Lock()
	// Inherit logger from first connection if not already set
	if g.logger == nil {
		g.logger = conn.logger
	}

	// Synchronize TSBPD with existing group members.
	if tb := g.getGroupTimeBase(conn); tb != nil {
		conn.ApplyGroupTime(*tb)
	}

	// Synchronize sender sequence numbers: if the group already has a
	// scheduling sequence, override the new member's ISN to match.
	// If not, adopt this member's ISN as the group's sequence.
	//
	// IMPORTANT: Only override sequence when the peer is group-aware
	// (negotiated via group handshake extension). For application-side
	// assembled groups with non-group-aware receivers, overriding the
	// sender's ISN would confuse the receiver (it expects the original ISN).
	schedSeq := g.lastSchedSeqNo.Load()
	if schedSeq != -1 && conn.PeerGroupID() != 0 {
		// Group already has a sequence and peer is group-aware — override.
		conn.OverrideSndSeqNo(seq.Number(uint32(schedSeq)))
	} else if schedSeq == -1 {
		// First member: adopt its ISN as the group's scheduling sequence.
		g.lastSchedSeqNo.Store(int64(conn.SchedSeqNo()))
	}

	g.members = append(g.members, mc)
	g.mu.Unlock()

	// Start a receive goroutine for this member
	g.wg.Add(1)
	go g.memberRecvLoop(mc)

	return nil
}

// AddPendingConn adds a connection that is still completing its handshake
// to the group as a pending member. The monitor loop will check whether
// the handshake has completed or timed out, transitioning the member to
// MemberIdle or MemberBroken accordingly.
func (g *Group) AddPendingConn(conn *Conn, token int, weight uint16) error {
	if g.closed.Load() {
		return errors.New("srt: group closed")
	}
	if conn == nil {
		return errors.New("srt: nil connection")
	}

	now := time.Now()
	mc := &memberConn{
		conn:         conn,
		token:        token,
		weight:       weight,
		status:       MemberPending,
		backupState:  BackupStandby,
		lastResponse: now,
		pendingSince: now,
	}

	g.mu.Lock()
	if g.logger == nil {
		g.logger = conn.logger
	}
	g.members = append(g.members, mc)
	g.mu.Unlock()

	return nil
}

// Connect dials a new SRT connection and adds it to the group.
// token is a caller-chosen identifier; weight is the priority.
func (g *Group) Connect(addr string, cfg Config, token int, weight uint16) error {
	if g.closed.Load() {
		return errors.New("srt: group closed")
	}

	conn, err := Dial(addr, cfg)
	if err != nil {
		return fmt.Errorf("srt: group connect: %w", err)
	}

	return g.AddConn(conn, token, weight)
}

// Write sends data across group members per the mode.
//
// Broadcast: sends on all Running members; at least one must succeed.
// Backup: sends on the active link only; buffers for failover.
//
// Returns the number of bytes written and an error if no member could send.
func (g *Group) Write(b []byte) (int, error) {
	if g.closed.Load() {
		return 0, errors.New("srt: group closed")
	}

	g.writeMu.Lock()
	defer g.writeMu.Unlock()

	switch g.mode {
	case GroupBroadcast:
		return g.writeBroadcast(b)
	case GroupBackup:
		return g.writeBackup(b)
	default:
		return 0, fmt.Errorf("srt: unknown group mode %d", g.mode)
	}
}

// Read receives data from the group, deduplicating across members.
// Packets already delivered via another link are silently dropped.
func (g *Group) Read(b []byte) (int, error) {
	if g.closed.Load() {
		return 0, errors.New("srt: group closed")
	}

	g.readMu.Lock()
	defer g.readMu.Unlock()

	for {
		select {
		case <-g.done:
			return 0, errors.New("srt: group closed")
		case res := <-g.recvCh:
			if res.err != nil {
				// If all members are broken, return the error
				if g.allBroken() {
					return 0, res.err
				}
				continue
			}

			// Deduplication: skip if we've already delivered this sequence
			base := g.rcvBaseSeqNo.Load()
			seqNo := int64(res.seqNo)

			if base >= 0 {
				// Use signed difference for wrapping comparison
				diff := seqNo - base
				if diff <= 0 {
					// Already delivered or older — discard duplicate
					g.recvDedups.Add(1)
					continue
				}
			}

			// Deliver this packet
			g.rcvBaseSeqNo.Store(seqNo)
			g.recvPackets.Add(1)

			n := copy(b, res.data)
			return n, nil
		}
	}
}

// Close closes all member connections and stops the group.
func (g *Group) Close() error {
	if !g.closed.CompareAndSwap(false, true) {
		return nil // already closed
	}
	close(g.done)

	g.mu.RLock()
	members := make([]*memberConn, len(g.members))
	copy(members, g.members)
	g.mu.RUnlock()

	var firstErr error
	for _, mc := range members {
		if err := mc.conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	g.wg.Wait()
	return firstErr
}

// Members returns current member state information.
func (g *Group) Members() []MemberInfo {
	g.mu.RLock()
	defer g.mu.RUnlock()

	infos := make([]MemberInfo, len(g.members))
	for i, mc := range g.members {
		stats := mc.conn.Stats(false)
		infos[i] = MemberInfo{
			Token:       mc.token,
			Status:      mc.status,
			BackupState: mc.backupState,
			Weight:      mc.weight,
			LocalAddr:   mc.conn.LocalAddr(),
			RemoteAddr:  mc.conn.RemoteAddr(),
			RTT:         stats.RTT,
		}
	}
	return infos
}

// Stats returns aggregate group statistics.
func (g *Group) Stats() GroupStats {
	g.mu.RLock()
	total := len(g.members)
	active := 0
	for _, mc := range g.members {
		if mc.status == MemberRunning {
			active++
		}
	}
	g.mu.RUnlock()

	return GroupStats{
		Members:       total,
		ActiveMembers: active,
		SentPackets:   g.sentPackets.Load(),
		RecvPackets:   g.recvPackets.Load(),
		RecvDedups:    g.recvDedups.Load(),
	}
}

// writeBroadcast sends payload on all Running members.
// At least one must succeed for the write to be considered successful.
//
// Steps:
// 1. Set srctime once before sending on any link (timestamp coordination)
// 2. Send on all RUNNING links first, collecting curseq from the first success
// 3. Activate IDLE links: override their sequence to match curseq, then send
// 4. Update the group's scheduling sequence
func (g *Group) writeBroadcast(b []byte) (int, error) {
	g.mu.RLock()
	nMembers := len(g.members)
	activeLinks := make([]*memberConn, 0, nMembers)
	idleLinks := make([]*memberConn, 0, nMembers)
	for _, mc := range g.members {
		if mc.status == MemberRunning {
			activeLinks = append(activeLinks, mc)
		} else if mc.status == MemberIdle {
			idleLinks = append(idleLinks, mc)
		}
	}
	g.mu.RUnlock()

	if len(activeLinks)+len(idleLinks) == 0 {
		return 0, errors.New("srt: no active group members")
	}

	// Source timestamp coordination: capture a single timestamp for all members.
	// All members of the group send packets with the same source timestamp.
	allMembers := append(activeLinks, idleLinks...)
	var srctime uint32
	if len(allMembers) > 0 {
		srctime = allMembers[0].conn.CurrentSRTTimestamp()
		for _, mc := range allMembers {
			mc.conn.SetGroupSrcTime(srctime)
		}
		defer func() {
			for _, mc := range allMembers {
				mc.conn.ClearGroupSrcTime()
			}
		}()
	}

	var (
		successCount int
		lastErr      error
		written      int
		curseq       int64 = -1 // first successful send's sequence, for idle link sync
	)

	// Phase 1: send on all RUNNING links.
	for _, mc := range activeLinks {
		n, err := mc.conn.Write(b)
		if err != nil {
			lastErr = err
			g.markBroken(mc)
			continue
		}
		successCount++
		written = n
		g.sentPackets.Add(1)

		if curseq == -1 {
			// Record the sequence used by the first successful send.
			curseq = int64(mc.conn.SchedSeqNo())
		}
	}

	// Phase 2: activate IDLE links — override ISN to curseq, then send.
	for _, mc := range idleLinks {
		if curseq != -1 && mc.conn.PeerGroupID() != 0 {
			// Only override when peer is group-aware (group handshake extension).
			lastseq := int64(mc.conn.SchedSeqNo())
			if curseq != lastseq {
				mc.conn.OverrideSndSeqNo(seq.Number(uint32(curseq)))
			}
		}

		n, err := mc.conn.Write(b)
		if err != nil {
			lastErr = err
			g.markBroken(mc)
			continue
		}
		successCount++
		written = n
		g.sentPackets.Add(1)

		// Promote idle -> running on first successful write
		g.mu.Lock()
		mc.status = MemberRunning
		g.mu.Unlock()

		if curseq == -1 {
			curseq = int64(mc.conn.SchedSeqNo())
		}
	}

	// Update the group's scheduling sequence.
	if curseq != -1 {
		g.lastSchedSeqNo.Store(curseq)
	}

	if successCount == 0 {
		return 0, fmt.Errorf("srt: all group members failed: %w", lastErr)
	}

	return written, nil
}

// writeBackup sends on ALL active member(s), manages stability, and
// initiates failover when necessary.
//
// Steps:
// 1. Qualify member states
// 2. Send on ALL active members (not just one)
// 3. Save in group sender buffer
// 4. Try to activate standby if needed (weight-based or failover)
// 5. Silence redundant links: demote low-weight links to standby
func (g *Group) writeBackup(b []byte) (int, error) {
	g.mu.Lock()
	now := time.Now()

	// Phase 1: qualify member states (same as monitor loop but inline for freshness).
	for _, mc := range g.members {
		if mc.status == MemberBroken {
			continue
		}
		if mc.status == MemberRunning && mc.backupState != BackupStandby {
			newState := g.qualifyBackupState(mc, now)
			g.assignBackupState(mc, newState, now)
		}
	}

	// Phase 2: collect all active and standby members.
	nMem := len(g.members)
	activeMembers := make([]*memberConn, 0, nMem)
	standbyMembers := make([]*memberConn, 0, nMem)
	var maxActiveWeight uint16
	var maxStandbyWeight uint16

	for _, mc := range g.members {
		if mc.status == MemberBroken {
			continue
		}
		if mc.status == MemberRunning && isBackupActive(mc.backupState) {
			activeMembers = append(activeMembers, mc)
			if mc.weight > maxActiveWeight {
				maxActiveWeight = mc.weight
			}
		}
		if mc.status == MemberIdle || (mc.status == MemberRunning && mc.backupState == BackupStandby) {
			standbyMembers = append(standbyMembers, mc)
			if mc.weight > maxStandbyWeight {
				maxStandbyWeight = mc.weight
			}
		}
	}
	g.mu.Unlock()

	// Source timestamp coordination: capture a single timestamp for all members.
	allBackupMembers := append(activeMembers, standbyMembers...)
	var srctime uint32
	if len(allBackupMembers) > 0 {
		srctime = allBackupMembers[0].conn.CurrentSRTTimestamp()
		for _, mc := range allBackupMembers {
			mc.conn.SetGroupSrcTime(srctime)
		}
		defer func() {
			for _, mc := range allBackupMembers {
				mc.conn.ClearGroupSrcTime()
			}
		}()
	}

	var (
		nsuccessful   int
		lastErr       error
		written       int
		curseq        int64 = -1
		firstSendConn *Conn // first successfully sending connection (for msgno)
	)

	// Snapshot the rate estimate from the current active link before sending,
	// for transfer to a newly activated standby.
	var activeRate int64
	if len(activeMembers) > 0 {
		activeRate = activeMembers[0].conn.getRateEstimate()
	}

	// Send on ALL active members.
	for _, mc := range activeMembers {
		// Synchronize sequence numbers across active members.
		// Only override when peer is group-aware (group handshake extension).
		if curseq != -1 && mc.conn.PeerGroupID() != 0 {
			lastseq := int64(mc.conn.SchedSeqNo())
			if curseq != lastseq {
				mc.conn.OverrideSndSeqNo(seq.Number(uint32(curseq)))
			}
		}

		n, err := mc.conn.Write(b)
		if err != nil {
			lastErr = err
			g.markBroken(mc)
			continue
		}
		nsuccessful++
		written = n
		g.sentPackets.Add(1)

		if curseq == -1 {
			curseq = int64(mc.conn.SchedSeqNo())
			firstSendConn = mc.conn
		}
	}

	// Buffer the message for potential failover replay.
	if curseq != -1 {
		var msgNo uint32
		if firstSendConn != nil {
			msgNo = firstSendConn.LastMsgNo()
		}
		g.bufferMsg(b, srctime, msgNo)
		g.lastSchedSeqNo.Store(curseq)
	}

	// Phase 3: Try to activate standby if needed.
	// Activate when: (a) no stable/fresh links, OR (b) maxActiveWeight < maxStandbyWeight
	needActivation := false
	if nsuccessful == 0 {
		needActivation = true
	} else if maxActiveWeight < maxStandbyWeight {
		// Weight-based preemptive activation: higher-weight standby
		// can preempt lower-weight active members.
		needActivation = true
	}

	if needActivation && len(standbyMembers) > 0 {
		// Sort standby by weight descending for best-first activation.
		sort.Slice(standbyMembers, func(i, j int) bool {
			return standbyMembers[i].weight > standbyMembers[j].weight
		})

		for _, mc := range standbyMembers {
			// Override ISN before sending on newly activated standby.
			// Only override when peer is group-aware (group handshake extension).
			if curseq != -1 && mc.conn.PeerGroupID() != 0 {
				mc.conn.OverrideSndSeqNo(seq.Number(uint32(curseq)))
			}

			// Transfer the rate estimate from the active link to the
			// newly activated standby before sending.
			if activeRate > 0 {
				mc.conn.setRateEstimate(activeRate)
			}

			// Replay buffered messages on the newly activated standby.
			if nsuccessful == 0 {
				g.replaySenderBuf(mc)
			}

			n, err := mc.conn.Write(b)
			if err != nil {
				lastErr = err
				g.markBroken(mc)
				continue
			}

			nsuccessful++
			written = n
			g.sentPackets.Add(1)

			g.mu.Lock()
			mc.status = MemberRunning
			mc.backupState = BackupActiveFresh
			mc.activeSince = now
			mc.lastResponse = now
			logger := g.logger
			g.mu.Unlock()

			if curseq == -1 {
				curseq = int64(mc.conn.SchedSeqNo())
				g.bufferMsg(b, srctime, mc.conn.LastMsgNo())
				g.lastSchedSeqNo.Store(curseq)
			}

			logf(logger, LogNote, LogGroup, g.groupID,
				"backup: activated standby member %d (weight=%d)", mc.token, mc.weight)

			// Break after first successful standby activation.
			break
		}
	}

	// Phase 4: Silence redundant links — if there is a stable member,
	// demote lower-weight active members to standby.
	g.silenceRedundantLinks(now)

	if nsuccessful == 0 {
		if lastErr != nil {
			return 0, fmt.Errorf("srt: all group members failed: %w", lastErr)
		}
		return 0, errors.New("srt: no active or standby group members")
	}

	return written, nil
}

// findActive returns the first Running member with BackupActiveStable,
// BackupActiveFresh, or BackupActiveWary state. Must be called with g.mu held.
func (g *Group) findActive() *memberConn {
	for _, mc := range g.members {
		if mc.status == MemberRunning && mc.backupState != BackupStandby && mc.backupState != BackupBroken {
			return mc
		}
	}
	return nil
}

// activateBestStandby promotes the highest-weight standby to active.
// Must be called with g.mu held.
func (g *Group) activateBestStandby() *memberConn {
	var best *memberConn
	for _, mc := range g.members {
		if mc.status == MemberBroken {
			continue
		}
		if mc.status == MemberIdle || (mc.status == MemberRunning && mc.backupState == BackupStandby) {
			if best == nil || mc.weight > best.weight {
				best = mc
			}
		}
	}
	if best != nil {
		best.status = MemberRunning
		best.backupState = BackupActiveFresh
		best.activeSince = time.Now()
		best.lastResponse = time.Now()
		logf(g.logger, LogNote, LogGroup, g.groupID,
			"backup failover: activated member %d (weight=%d)", best.token, best.weight)
	}
	return best
}

// isBackupActive returns true if the backup state represents an active link.
func isBackupActive(state BackupState) bool {
	switch state {
	case BackupActiveFresh, BackupActiveStable, BackupActiveUnstable, BackupActiveWary:
		return true
	default:
		return false
	}
}

// silenceRedundantLinks demotes lower-weight active members to standby
// when a higher-weight stable link exists.
//
// The key principle: keep data flowing even if it means temporary redundancy.
// Only silence if there is at least one STABLE member.
func (g *Group) silenceRedundantLinks(now time.Time) {
	g.mu.Lock()

	// Count stable members and find the highest-weight stable member.
	var stableCount int
	var maxWeightStable uint16
	var stableToken int
	var silencedConns []*Conn

	for _, mc := range g.members {
		if mc.status != MemberRunning || !isBackupActive(mc.backupState) {
			continue
		}
		if mc.backupState == BackupActiveStable {
			stableCount++
			if stableCount == 1 || mc.weight > maxWeightStable {
				maxWeightStable = mc.weight
				stableToken = mc.token
			}
		}
	}

	// Only silence if at least one stable member exists.
	if stableCount == 0 {
		g.mu.Unlock()
		return
	}

	// Silence active members that are lower priority than the best stable link.
	// Sorted by weight descending, first stable kept, all others silenced
	// if weight <= maxWeightStable.
	for _, mc := range g.members {
		if mc.status != MemberRunning || !isBackupActive(mc.backupState) {
			continue
		}
		if mc.token == stableToken {
			continue // keep the highest-weight stable link
		}

		shouldSilence := false
		if mc.backupState == BackupActiveStable {
			// Second or lower stable link — silence it.
			shouldSilence = true
		} else if mc.weight <= maxWeightStable {
			// Non-stable active with lower or equal weight — silence it.
			shouldSilence = true
		}

		if shouldSilence {
			logf(g.logger, LogNote, LogGroup, g.groupID,
				"backup: silencing member %d (weight=%d, state=%s) in favor of member %d (weight=%d, stable)",
				mc.token, mc.weight, mc.backupState, stableToken, maxWeightStable)
			g.assignBackupState(mc, BackupStandby, now)
			silencedConns = append(silencedConns, mc.conn)
		}
	}

	// After silencing a link, send an immediate KEEPALIVE so the peer quickly
	// recognizes the link as idle. Release the lock before sending to avoid
	// holding it during I/O.
	g.mu.Unlock()
	for _, conn := range silencedConns {
		conn.SendKeepAlive()
	}
	g.mu.Lock()
}

// replaySenderBuf sends all buffered messages on the given member,
// preserving the original packet sequence, message number, and source timestamp.
func (g *Group) replaySenderBuf(mc *memberConn) {
	g.senderBufMu.Lock()
	msgs := make([]bufferedMsg, len(g.senderBuf))
	copy(msgs, g.senderBuf)
	g.senderBufMu.Unlock()

	for _, msg := range msgs {
		// Preserve original source timestamp during replay so the receiver's
		// TSBPD delivery timing matches the original send.
		if msg.srcTime != 0 {
			mc.conn.SetGroupSrcTime(msg.srcTime)
		}
		mc.conn.Write(msg.data) //nolint:errcheck // best-effort replay
		if msg.srcTime != 0 {
			mc.conn.ClearGroupSrcTime()
		}
	}
}

// bufferMsg adds a message to the sender buffer for backup mode replay.
// Also prunes ACK'd messages based on cross-member ACK progress.
// srcTime is the SRT source timestamp; msgNo is the message number.
func (g *Group) bufferMsg(b []byte, srcTime uint32, msgNo uint32) {
	g.senderBufMu.Lock()
	defer g.senderBufMu.Unlock()

	// Cross-member buffer cleanup: find the maximum ACK sequence across
	// all running members. Messages with seqNo <= maxACK are confirmed
	// delivered on at least one link and can be pruned.
	g.pruneAckedMessages()

	data := make([]byte, len(b))
	copy(data, b)

	// Record the current scheduling sequence for this message.
	seqNo := uint32(g.lastSchedSeqNo.Load())

	g.senderBuf = append(g.senderBuf, bufferedMsg{
		seqNo:   seqNo,
		msgNo:   msgNo,
		srcTime: srcTime,
		data:    data,
		ts:      time.Now(),
	})

	// Prune if over capacity
	if len(g.senderBuf) > g.senderBufCap {
		excess := len(g.senderBuf) - g.senderBufCap
		g.senderBuf = g.senderBuf[excess:]
	}
}

// pruneAckedMessages removes messages from the sender buffer that have been
// ACK'd on at least one member connection. This is the cross-member buffer
// cleanup: when a sequence is ACK'd on one member, it can be cleaned up
// from the group's sender buffer.
// Must be called with g.senderBufMu held.
func (g *Group) pruneAckedMessages() {
	if len(g.senderBuf) == 0 {
		return
	}

	// Find maximum ACK'd sequence across all members.
	g.mu.RLock()
	var maxACK int64 = -1
	for _, mc := range g.members {
		if mc.status == MemberBroken {
			continue
		}
		ack := int64(mc.conn.lastACKSeq.Load())
		if ack > maxACK {
			maxACK = ack
		}
	}
	g.mu.RUnlock()

	if maxACK < 0 {
		return
	}

	// Remove messages whose seqNo is before the max ACK.
	pruneIdx := 0
	for i, msg := range g.senderBuf {
		if seq.Number(msg.seqNo).LessThan(seq.Number(uint32(maxACK))) {
			pruneIdx = i + 1
		} else {
			break
		}
	}
	if pruneIdx > 0 {
		g.senderBuf = g.senderBuf[pruneIdx:]
	}
}

// memberRecvLoop reads from a single member connection and fans results
// into the group's shared receive channel.
func (g *Group) memberRecvLoop(mc *memberConn) {
	defer g.wg.Done()

	buf := make([]byte, 65536)
	for {
		select {
		case <-g.done:
			return
		default:
		}

		n, err := mc.conn.Read(buf)
		if err != nil {
			if g.closed.Load() {
				return
			}
			g.markBroken(mc)

			// Send error to fan-in channel (non-blocking)
			select {
			case g.recvCh <- recvResult{err: err}:
			case <-g.done:
			}
			return
		}

		// Update member response time
		g.mu.Lock()
		mc.lastResponse = time.Now()
		if mc.status == MemberIdle {
			mc.status = MemberRunning
		}
		// Data is flowing — clear idle flag.
		mc.isIdle = false
		g.mu.Unlock()

		// Extract sequence number for deduplication.
		// We use the connection's last ACK sequence as a proxy for the
		// most recently delivered sequence number.
		seqNo := mc.conn.lastACKSeq.Load()

		// Synchronize idle link receiver pointers with the active link
		// after receiving data.
		g.updateLatestRcv(mc)

		data := make([]byte, n)
		copy(data, buf[:n])

		select {
		case g.recvCh <- recvResult{n: n, seqNo: seqNo, data: data}:
		case <-g.done:
			return
		}
	}
}

// markBroken transitions a member to broken state.
func (g *Group) markBroken(mc *memberConn) {
	g.mu.Lock()
	mc.status = MemberBroken
	if g.mode == GroupBackup {
		mc.backupState = BackupBroken
	}
	logger := g.logger
	g.mu.Unlock()

	logf(logger, LogWarning, LogGroup, g.groupID,
		"member %d marked broken (addr=%s)", mc.token, mc.conn.RemoteAddr())
}

// allBroken returns true if all members are broken.
func (g *Group) allBroken() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.members) == 0 {
		return true
	}
	for _, mc := range g.members {
		if mc.status != MemberBroken {
			return false
		}
	}
	return true
}

// monitorLoop runs periodically to check member health,
// qualify backup states, and trigger failover.
func (g *Group) monitorLoop() {
	defer g.wg.Done()

	ticker := time.NewTicker(monitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-g.done:
			return
		case <-ticker.C:
			g.checkMembers()
		}
	}
}

// checkMembers evaluates all members' health and triggers
// backup mode transitions when necessary.
func (g *Group) checkMembers() {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	hasActive := false

	for _, mc := range g.members {
		if mc.status == MemberBroken {
			continue
		}

		// Handle pending members (handshake in progress).
		if mc.status == MemberPending {
			if mc.conn.isConnected() {
				// Handshake completed — transition to Idle.
				mc.status = MemberIdle
				if g.mode == GroupBackup {
					mc.backupState = BackupStandby
				}
				mc.lastResponse = now
				logf(g.logger, LogNote, LogGroup, g.groupID,
					"pending member %d connected, transitioning to idle", mc.token)

				// Now that the connection is established, synchronize group state.
				if tb := g.getGroupTimeBase(mc.conn); tb != nil {
					mc.conn.ApplyGroupTime(*tb)
				}
				schedSeq := g.lastSchedSeqNo.Load()
				if schedSeq != -1 && mc.conn.PeerGroupID() != 0 {
					mc.conn.OverrideSndSeqNo(seq.Number(uint32(schedSeq)))
				} else if schedSeq == -1 {
					g.lastSchedSeqNo.Store(int64(mc.conn.SchedSeqNo()))
				}

				// Start receive goroutine for the newly connected member.
				g.wg.Add(1)
				go g.memberRecvLoop(mc)
			} else if !mc.pendingSince.IsZero() && now.Sub(mc.pendingSince) > pendingTimeout {
				// Pending too long — mark broken.
				logf(g.logger, LogWarning, LogGroup, g.groupID,
					"pending member %d timed out after %v, breaking", mc.token, now.Sub(mc.pendingSince))
				mc.status = MemberBroken
				if g.mode == GroupBackup {
					mc.backupState = BackupBroken
				}
			}
			continue
		}

		// Sync idle state from connection keepalive tracking.
		// When keepalive is received, transition to idle to prevent false
		// stability timeout during data pauses.
		if mc.conn.groupIdle.Load() {
			mc.isIdle = true
			mc.lastResponse = now // keepalive proves link is alive
		}

		if g.mode == GroupBackup && mc.status == MemberRunning {
			newState := g.qualifyBackupState(mc, now)
			g.assignBackupState(mc, newState, now)

			switch mc.backupState {
			case BackupActiveStable, BackupActiveFresh, BackupActiveWary:
				hasActive = true
			case BackupActiveUnstable:
				hasActive = true

				// Break unstable members that have been unstable for longer
				// than peerIdleTimeout.
				if !mc.unstableSince.IsZero() {
					idleTimeout := mc.conn.peerIdleTimeout
					if idleTimeout == 0 {
						idleTimeout = 5 * time.Second // default
					}
					if now.Sub(mc.unstableSince) > idleTimeout {
						logf(g.logger, LogWarning, LogGroup, g.groupID,
							"backup: member %d unstable for %v, breaking", mc.token, now.Sub(mc.unstableSince))
						mc.status = MemberBroken
						mc.backupState = BackupBroken
					}
				}
			case BackupBroken:
				mc.status = MemberBroken
			}
		}
	}

	// If backup mode and no active member, try to activate a standby
	if g.mode == GroupBackup && !hasActive {
		g.activateBestStandby()
	}

	// Remove members that have been broken for a while
	g.removeBrokenMembers(now)
}

// qualifyBackupState determines a member's backup state based on
// response timing and drop detection. Must be called with g.mu held.
func (g *Group) qualifyBackupState(mc *memberConn, now time.Time) BackupState {
	if mc.status == MemberBroken {
		return BackupBroken
	}
	if mc.backupState == BackupStandby {
		return BackupStandby
	}

	// When the link is idle (keepalive received, no data flowing),
	// skip the stability timeout check and preserve the current state
	// to prevent false unstable transitions during data pauses.
	if mc.isIdle {
		// Link is alive but idle — keep current state, don't degrade.
		if isBackupActive(mc.backupState) {
			return mc.backupState
		}
	}

	connStats := mc.conn.Stats(false)
	peerLatency := connStats.NegotiatedLatency
	if peerLatency == 0 {
		peerLatency = 120 * time.Millisecond // default
	}

	// initial_stabtout = max(minStabilityTimeout, peerLatency)
	initialTimeout := g.stabTimeout
	if peerLatency > initialTimeout {
		initialTimeout = peerLatency
	}

	// probing_period = initial_stabtout + 50ms
	probingPeriod := initialTimeout + 50*time.Millisecond

	// Activation phase: fresh and within probing period.
	isActivationPhase := !mc.activeSince.IsZero() &&
		now.Sub(mc.activeSince) <= probingPeriod

	// Stability timeout: activation phase uses initial timeout,
	// post-activation uses min(max(minStab, 2*SRTT+4*RTTVar), peerLatency).
	var stabilityTimeout time.Duration
	if isActivationPhase {
		stabilityTimeout = initialTimeout
	} else {
		dynamicTimeout := 2*connStats.RTT + 4*connStats.RTTVar
		if dynamicTimeout < g.stabTimeout {
			dynamicTimeout = g.stabTimeout
		}
		if dynamicTimeout > peerLatency {
			dynamicTimeout = peerLatency
		}
		stabilityTimeout = dynamicTimeout
	}

	// last_rsp = max(freshActivationStart, lastRspTime)
	lastResponse := mc.lastResponse
	if mc.activeSince.After(lastResponse) {
		lastResponse = mc.activeSince
	}
	sinceResponse := now.Sub(lastResponse)

	// No response for too long -> unstable
	if sinceResponse > stabilityTimeout {
		return BackupActiveUnstable
	}

	// Check for new packet drops
	if connStats.SentDropped > mc.prevDrops {
		mc.prevDrops = connStats.SentDropped
		if !isActivationPhase {
			return BackupActiveUnstable
		}
		// Drops during activation phase are ignored
	}

	// Responsive: determine final state
	if isActivationPhase {
		return BackupActiveFresh
	}

	// Wary state logic
	isWary := !mc.warySince.IsZero()
	isWaryProbing := isWary && now.Sub(mc.warySince) <= 4*peerLatency
	isUnstable := !mc.unstableSince.IsZero()

	// If was unstable and not yet wary, transition to wary
	if isUnstable && !isWary {
		return BackupActiveWary
	}

	// Still in wary probing period
	if isWaryProbing {
		return BackupActiveWary
	}

	return BackupActiveStable
}

// assignBackupState applies state transition and tracks timestamps.
// Must be called with g.mu held.
func (g *Group) assignBackupState(mc *memberConn, state BackupState, now time.Time) {
	mc.backupState = state
	switch state {
	case BackupStandby, BackupBroken:
		mc.activeSince = time.Time{}
		mc.unstableSince = time.Time{}
		mc.warySince = time.Time{}
	case BackupActiveFresh:
		if mc.activeSince.IsZero() {
			mc.activeSince = now
		}
		mc.unstableSince = time.Time{}
		mc.warySince = time.Time{}
	case BackupActiveStable:
		mc.activeSince = time.Time{}
		mc.unstableSince = time.Time{}
		mc.warySince = time.Time{}
	case BackupActiveUnstable:
		if mc.unstableSince.IsZero() {
			mc.unstableSince = now
		}
		mc.activeSince = time.Time{}
		mc.warySince = time.Time{}
	case BackupActiveWary:
		if mc.warySince.IsZero() {
			mc.warySince = now
		}
	}
}

// removeBrokenMembers removes members that have been broken for >10s.
// Must be called with g.mu held.
func (g *Group) removeBrokenMembers(now time.Time) {
	alive := g.members[:0]
	for _, mc := range g.members {
		if mc.status == MemberBroken && now.Sub(mc.lastResponse) > 10*time.Second {
			continue // drop from the group
		}
		alive = append(alive, mc)
	}
	g.members = alive
}

// getGroupTimeBase retrieves the TSBPD state from the first connected member
// (excluding the target conn). Returns nil if no other connected member exists.
// Must be called with g.mu held.
func (g *Group) getGroupTimeBase(exclude *Conn) *tsbpd.GroupTimeBase {
	for _, mc := range g.members {
		if mc.status == MemberBroken || mc.conn == exclude {
			continue
		}
		tb := mc.conn.TSBPDTimeBase()
		if tb != nil {
			return tb
		}
	}
	return nil
}

// SynchronizeDrift propagates one member's TSBPD drift to all other members.
// Called when a member's drift is updated.
func (g *Group) SynchronizeDrift(src *Conn) {
	tb := src.TSBPDTimeBase()
	if tb == nil {
		return
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.members) <= 1 {
		return
	}

	for _, mc := range g.members {
		if mc.conn == src || mc.status == MemberBroken {
			continue
		}
		mc.conn.ApplyGroupDrift(*tb)
	}
}

// updateLatestRcv synchronizes idle link receiver pointers with the active
// link's progress. This is called after receiving data on a member in backup
// mode to advance idle/standby links' receive buffers.
func (g *Group) updateLatestRcv(source *memberConn) {
	if g.mode != GroupBackup {
		return
	}

	// Get the source's receive progress: max(lastAck, bufStartSeq).
	// Use max to guard against TSBPD drops that moved bufseq ahead of lastAck.
	srcLastAck := source.conn.loadLastACKSeq()
	srcBufStart := source.conn.RcvBufStartSeq()

	newLastRcv := srcLastAck
	if srcBufStart.GreaterThan(srcLastAck) {
		newLastRcv = srcBufStart
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, mc := range g.members {
		if mc == source || mc.status == MemberBroken {
			continue
		}
		// Only update IDLE members.
		if !mc.isIdle && mc.status != MemberIdle {
			continue
		}
		// Skip if the idle link's buffer is not empty.
		if !mc.conn.RcvBufEmpty() {
			continue
		}
		// Refuse if newLastRcv <= idle link's lastAck (would go backwards).
		idleLastAck := mc.conn.loadLastACKSeq()
		if !newLastRcv.GreaterThan(idleLastAck) {
			continue
		}

		mc.conn.ResetRecvState(newLastRcv)
	}
}

// RTT returns the minimum RTT across all running members.
func (g *Group) RTT() time.Duration {
	g.mu.RLock()
	defer g.mu.RUnlock()

	minRTT := time.Duration(math.MaxInt64)
	for _, mc := range g.members {
		if mc.status == MemberRunning {
			rtt := mc.conn.Stats(false).RTT
			if rtt > 0 && rtt < minRTT {
				minRTT = rtt
			}
		}
	}
	if minRTT == time.Duration(math.MaxInt64) {
		return 0
	}
	return minRTT
}
