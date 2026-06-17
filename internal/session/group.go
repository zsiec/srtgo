package session

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/packet"
)

// groupMonitorInterval is how often the backup health monitor runs.
const groupMonitorInterval = 100 * clock.Millisecond

// GroupMemberConfig describes one bonded member: its socket, the address of the
// peer member on that link, and its established connection parameters. Members
// must share a send/receive sequence space (the same SendISN / RecvISN across
// all members) so the group can deduplicate across links.
type GroupMemberConfig struct {
	Conn          net.PacketConn
	LocalSocketID uint32 // this member's socket ID (peers send to it)
	RemoteAddr    net.Addr
	Config        core.Config
	Weight        uint16
}

// Group is the I/O host for connection bonding: it owns one socket per member
// and drives a core.Group plus all member core.Conns from a single event loop.
// Write fans out across links (broadcast) or the active link (backup); Read
// returns the deduplicated, merged stream.
type Group struct {
	clk     clock.Clock
	core    *core.Group
	members []*groupMember

	inbound chan groupInbound
	writeC  chan []byte
	readC   chan []byte

	quit      chan struct{}
	loopDone  chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	timers map[groupTimerKey]clock.Timestamp
}

type groupMember struct {
	conn       *core.Conn
	mux        *mux.Mux
	recvC      <-chan packet.Packet
	remoteAddr net.Addr
}

type groupInbound struct {
	idx int
	pkt packet.Packet
}

// groupTimerKey identifies a timer in the unified wheel. idx == monitorIdx is
// the group monitor; otherwise it is member idx's core timer id.
type groupTimerKey struct {
	idx int
	id  core.TimerID
}

const monitorIdx = -1

// NewEstablishedGroup builds a bonding session over already-established members
// (handshake-based group dialing needs the group handshake extension, a later
// step). It starts the event loop immediately.
func NewEstablishedGroup(mode core.GroupMode, mcfgs []GroupMemberConfig, clk clock.Clock) *Group {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	cg := core.NewGroup(mode)
	g := &Group{
		clk:      clk,
		core:     cg,
		inbound:  make(chan groupInbound, 256*max1(len(mcfgs))),
		writeC:   make(chan []byte, 256),
		readC:    make(chan []byte, 2048),
		quit:     make(chan struct{}),
		loopDone: make(chan struct{}),
		timers:   make(map[groupTimerKey]clock.Timestamp),
	}
	now := clk.Now()
	for _, mc := range mcfgs {
		m := mux.New(mc.Conn, mux.DefaultMSS)
		recvC := m.Register(mc.LocalSocketID)
		conn := core.NewEstablished(mc.Config, now)
		cg.AddMember(conn, mc.Weight)
		g.members = append(g.members, &groupMember{conn: conn, mux: m, recvC: recvC, remoteAddr: mc.RemoteAddr})
	}
	for i, m := range g.members {
		g.wg.Add(1)
		go g.forward(i, m.recvC)
	}
	go g.loop()
	return g
}

// Write queues a payload to be sent across the group.
func (g *Group) Write(p []byte) error {
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case g.writeC <- cp:
		return nil
	case <-g.loopDone:
		return ErrClosed
	}
}

// Read returns the next merged, deduplicated payload.
func (g *Group) Read(b []byte) (int, error) {
	select {
	case d := <-g.readC:
		return copy(b, d), nil
	case <-g.loopDone:
		select {
		case d := <-g.readC:
			return copy(b, d), nil
		default:
			return 0, io.EOF
		}
	}
}

// Close stops the loop and closes every member socket.
func (g *Group) Close() error {
	g.closeOnce.Do(func() { close(g.quit) })
	<-g.loopDone
	g.wg.Wait()
	for _, m := range g.members {
		_ = m.mux.Close()
	}
	return nil
}

// forward pumps one member's inbound packets into the shared loop channel,
// tagged with the member index.
func (g *Group) forward(idx int, recvC <-chan packet.Packet) {
	defer g.wg.Done()
	for {
		select {
		case <-g.quit:
			return
		case p, ok := <-recvC:
			if !ok {
				return
			}
			select {
			case g.inbound <- groupInbound{idx: idx, pkt: p}:
			case <-g.quit:
				p.Release()
				return
			}
		}
	}
}

func (g *Group) loop() {
	defer close(g.loopDone)

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	var backlog [][]byte
	now := g.clk.Now()
	g.timers[groupTimerKey{idx: monitorIdx}] = now.Add(groupMonitorInterval)
	for i := range g.members {
		g.drainMember(now, i)
	}
	g.rearm(timer, now)

	for {
		backlog = g.flushGroupBacklog(backlog)

		select {
		case <-g.quit:
			return

		case in := <-g.inbound:
			now := g.clk.Now()
			g.members[in.idx].conn.HandlePacket(now, in.pkt)
			g.drainMember(now, in.idx)
			backlog = g.route(in.idx, backlog)
			g.rearm(timer, now)

		case payload := <-g.writeC:
			now := g.clk.Now()
			g.core.Write(now, payload)
			for i := range g.members {
				g.drainMember(now, i)
			}
			g.rearm(timer, now)

		case <-timer.C:
			now := g.clk.Now()
			fired := g.fireTimers(now)
			for i := range g.members {
				g.drainMember(now, i)
			}
			// A TSBPD timer or a failover may have produced deliveries; route
			// the members that fired (cheap to route all).
			for i := range g.members {
				if fired {
					backlog = g.route(i, backlog)
				}
			}
			g.rearm(timer, now)
		}
	}
}

func (g *Group) drainMember(now clock.Timestamp, idx int) {
	m := g.members[idx]
	for {
		out, ok := m.conn.PollOutput()
		if !ok {
			return
		}
		switch v := out.(type) {
		case core.SendPacket:
			v.Packet.Header.Addr = m.remoteAddr
			_ = m.mux.Send(v.Packet)
			if v.Owned {
				v.Packet.Release()
			}
		case core.SetTimer:
			g.timers[groupTimerKey{idx: idx, id: v.ID}] = v.Deadline
		case core.ClearTimer:
			delete(g.timers, groupTimerKey{idx: idx, id: v.ID})
		}
	}
}

// route forwards member idx's deliveries through the group's dedup into readC.
func (g *Group) route(idx int, backlog [][]byte) [][]byte {
	g.core.RouteMember(g.members[idx].conn)
	for {
		d, ok := g.core.PollDelivery()
		if !ok {
			return backlog
		}
		select {
		case g.readC <- d:
		default:
			backlog = append(backlog, d)
		}
	}
}

func (g *Group) fireTimers(now clock.Timestamp) bool {
	fired := false
	for k, dl := range g.timers {
		if dl.After(now) {
			continue
		}
		delete(g.timers, k)
		fired = true
		if k.idx == monitorIdx {
			g.core.Monitor(now)
			g.timers[groupTimerKey{idx: monitorIdx}] = now.Add(groupMonitorInterval)
		} else {
			g.members[k.idx].conn.HandleTimer(now, k.id)
		}
	}
	return fired
}

func (g *Group) rearm(timer *time.Timer, now clock.Timestamp) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	var earliest clock.Timestamp
	have := false
	for _, dl := range g.timers {
		if !have || dl.Before(earliest) {
			earliest, have = dl, true
		}
	}
	if !have {
		return
	}
	d := earliest.Sub(now)
	if d < 0 {
		d = 0
	}
	timer.Reset(d.Duration())
}

func (g *Group) flushGroupBacklog(backlog [][]byte) [][]byte {
	i := 0
	for i < len(backlog) {
		select {
		case g.readC <- backlog[i]:
			i++
		default:
			return backlog[i:]
		}
	}
	return backlog[:0]
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
