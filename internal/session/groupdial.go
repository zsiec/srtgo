package session

import (
	"fmt"
	"net"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/handshake"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/seq"
)

// GroupDialMember is one member link of a bonded group dial: its own socket and
// the peer address to reach on that link.
type GroupDialMember struct {
	Conn       net.PacketConn
	RemoteAddr net.Addr
	Weight     uint16 // member priority (backup mode)
}

// DialGroup opens a bonded group connection: it handshakes each member link
// (advertising a shared group ID and sequence space), then assembles the
// established members into a group host. base supplies the shared connection
// parameters (latency, bandwidth, live mode, ...); per-member socket IDs are
// generated, and all members share one group ID and ISN so the peer can
// deduplicate across links. It blocks until every member connects.
func DialGroup(mode core.GroupMode, base core.DialConfig, members []GroupDialMember, clk clock.Clock, timeout time.Duration) (*Group, error) {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("session: DialGroup needs at least one member")
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	// Shared group identity + sequence space across all member links.
	groupID := base.GroupID
	if groupID == 0 {
		id, err := handshake.GenerateSocketID()
		if err != nil {
			return nil, err
		}
		groupID = id
	}
	isn := base.CallerISN
	if isn == 0 {
		v, err := handshake.GenerateISN()
		if err != nil {
			return nil, err
		}
		isn = seq.Number(v)
	}

	built := make([]*groupMember, 0, len(members))
	for _, mc := range members {
		sockID, err := handshake.GenerateSocketID()
		if err != nil {
			closeMembers(built)
			return nil, err
		}
		dc := base
		dc.CallerSocketID = sockID
		dc.CallerISN = isn
		dc.GroupID = groupID
		dc.GroupType = uint8(mode)
		dc.GroupWeight = mc.Weight

		gm, err := dialGroupMember(mc.Conn, mc.RemoteAddr, dc, mc.Weight, clk, timeout)
		if err != nil {
			closeMembers(built)
			return nil, fmt.Errorf("session: dial group member: %w", err)
		}
		built = append(built, gm)
	}
	return newGroupFromMembers(mode, built, true, clk), nil
}

func closeMembers(members []*groupMember) {
	for _, m := range members {
		_ = m.mux.Close()
	}
}

// dialGroupMember drives one member's handshake to completion on its own socket
// and returns the established member (its core, mux, and inbound channel) for the
// group host to drive. It deliberately leaves the post-establish effects (the
// ACK/NAK timer arming) queued on the core so the group loop arms them.
func dialGroupMember(conn net.PacketConn, remoteAddr net.Addr, dc core.DialConfig, weight uint16, clk clock.Clock, timeout time.Duration) (*groupMember, error) {
	mss := int(dc.MSS)
	if mss == 0 {
		mss = mux.DefaultMSS
	}
	m := mux.New(conn, mss)
	recvC := m.Register(dc.CallerSocketID)
	cc := core.Dial(dc, clk.Now())

	// drain sends queued wire packets (induction/conclusion). It must NOT run
	// after Connected, so the establish's timer-arming effects stay queued.
	drain := func() {
		for {
			out, ok := cc.PollOutput()
			if !ok {
				return
			}
			if sp, ok := out.(core.SendPacket); ok {
				sp.Packet.Header.Addr = remoteAddr
				_ = m.Send(sp.Packet)
				if sp.Owned {
					sp.Packet.Release()
				}
			}
			// Pre-connect SetTimer/ClearTimer are the handshake retransmit, which
			// we drive with a fixed ticker below; ignore them.
		}
	}
	// settled reports the handshake outcome without draining outputs.
	settled := func() (done bool, err error) {
		for {
			ev, ok := cc.PollEvent()
			if !ok {
				return false, nil
			}
			switch e := ev.(type) {
			case core.Connected:
				return true, nil
			case core.Failed:
				return true, e.Err
			}
		}
	}

	drain() // send the induction
	retry := time.NewTicker(250 * time.Millisecond)
	defer retry.Stop()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		select {
		case p, ok := <-recvC:
			if !ok {
				m.Close()
				return nil, fmt.Errorf("mux closed during handshake")
			}
			cc.HandlePacket(clk.Now(), p)
			if done, err := settled(); done {
				if err != nil {
					m.Close()
					return nil, err
				}
				return &groupMember{conn: cc, mux: m, recvC: recvC, remoteAddr: remoteAddr, weight: weight}, nil
			}
			drain() // send the next handshake step (e.g. the conclusion)
		case <-retry.C:
			cc.HandleTimer(clk.Now(), core.TimerHandshake)
			drain()
		case <-deadline.C:
			m.Close()
			return nil, fmt.Errorf("handshake timeout after %s", timeout)
		}
	}
}
