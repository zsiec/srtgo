package session

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/mux"
)

// Listener is the I/O host for a core.Listener. It owns the mux, feeds inbound
// handshake datagrams to the listener core, executes its SendTo effects, and
// turns Accepted events into driven per-connection Sessions returned by Accept.
type Listener struct {
	mux  *mux.Mux
	clk  clock.Clock
	core *core.Listener

	addrs  map[core.PeerID]net.Addr // peer id -> resolved address
	accept chan *Session

	// Bonded-group members accepted via the handshake, collected by GroupID until
	// AcceptGroup assembles them into a shared-mux group host.
	groupMu     sync.Mutex
	groups      map[uint32][]*groupMember
	groupSignal chan struct{} // buffered(1); poked when a group member arrives

	quit      chan struct{}
	loopDone  chan struct{}
	closeOnce sync.Once
}

// Listen binds a core.Listener over conn and starts accepting. It owns conn
// (Close closes it). clk may be nil (defaults to a real clock).
func Listen(conn net.PacketConn, cfg core.ListenerConfig, clk clock.Clock) (*Listener, error) {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	var secretBuf [8]byte
	if _, err := rand.Read(secretBuf[:]); err != nil {
		return nil, err
	}
	secret := binary.BigEndian.Uint64(secretBuf[:])

	m := mux.New(conn, mux.DefaultMSS)
	l := &Listener{
		mux:         m,
		clk:         clk,
		core:        core.NewListener(cfg, secret, randFill, newCryptoCtx),
		addrs:       make(map[core.PeerID]net.Addr),
		accept:      make(chan *Session, 64),
		groups:      make(map[uint32][]*groupMember),
		groupSignal: make(chan struct{}, 1),
		quit:        make(chan struct{}),
		loopDone:    make(chan struct{}),
	}
	go l.loop()
	return l, nil
}

// Accept returns the next established connection as a driven Session.
func (l *Listener) Accept() (*Session, error) {
	select {
	case s := <-l.accept:
		return s, nil
	case <-l.loopDone:
		return nil, ErrClosed
	}
}

// AcceptGroup waits until some bonded group has accepted n member links over the
// handshake, then assembles them into a group host (sharing the listener's mux)
// and returns it. The members all advertised the same group ID and share a
// receive sequence space, so the group deduplicates their streams.
func (l *Listener) AcceptGroup(mode core.GroupMode, n int) (*Group, error) {
	for {
		l.groupMu.Lock()
		for gid, members := range l.groups {
			if len(members) >= n {
				picked := members[:n]
				l.groups[gid] = members[n:]
				if len(l.groups[gid]) == 0 {
					delete(l.groups, gid)
				}
				l.groupMu.Unlock()
				return newGroupFromMembers(mode, picked, false, l.clk), nil
			}
		}
		l.groupMu.Unlock()

		select {
		case <-l.groupSignal:
		case <-l.loopDone:
			return nil, ErrClosed
		}
	}
}

// Addr returns the listener's local address.
func (l *Listener) Addr() net.Addr { return l.mux.LocalAddr() }

// Close stops the listener and closes the underlying socket.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() { close(l.quit) })
	<-l.loopDone
	return l.mux.Close()
}

func (l *Listener) loop() {
	defer close(l.loopDone)
	for {
		select {
		case <-l.quit:
			return
		case p, ok := <-l.mux.Handshake:
			if !ok {
				return
			}
			now := l.clk.Now()
			peer := core.PeerID(p.Header.Addr.String())
			l.addrs[peer] = p.Header.Addr
			l.core.HandlePacket(now, p, peer)
			p.Release()
			l.drain(now)
		}
	}
}

func (l *Listener) drain(now clock.Timestamp) {
	for {
		out, ok := l.core.PollOutput()
		if !ok {
			break
		}
		if s, ok := out.(core.SendTo); ok {
			s.Packet.Header.Addr = l.addrs[s.Peer]
			_ = l.mux.Send(s.Packet)
			s.Packet.Release()
		}
	}
	for {
		ev, ok := l.core.PollEvent()
		if !ok {
			break
		}
		a, ok := ev.(core.Accepted)
		if !ok {
			continue
		}
		// Route this connection's data packets (DestinationSocketID == a.SocketID)
		// to its own registered channel on the shared mux.
		recvC := l.mux.Register(a.SocketID)

		// A group member is collected (not returned as a standalone session) until
		// AcceptGroup assembles the group; all members share the listener's mux.
		if a.GroupID != 0 {
			gm := &groupMember{conn: a.Conn, mux: l.mux, recvC: recvC, remoteAddr: l.addrs[a.Peer], weight: a.GroupWeight}
			l.groupMu.Lock()
			l.groups[a.GroupID] = append(l.groups[a.GroupID], gm)
			l.groupMu.Unlock()
			select {
			case l.groupSignal <- struct{}{}:
			default:
			}
			continue
		}

		sess := newSession(l.mux, recvC, false, l.addrs[a.Peer], l.clk, a.Conn)
		sess.groupID = a.GroupID
		sess.groupType = a.GroupType
		sess.groupWeight = a.GroupWeight
		sess.sharedISN = a.SharedISN
		sess.streamID = a.StreamID
		sess.socketID = a.SocketID
		select {
		case l.accept <- sess:
		default:
			sess.Close() // backlog full; drop
			l.mux.Unregister(a.SocketID)
		}
	}
}

// randFill fills b with cryptographically random bytes for the listener core's
// socket-ID and ISN generation.
func randFill(b []byte) {
	_, _ = rand.Read(b)
}

// newCryptoCtx builds a fresh crypto context (in the cipher mode the caller's
// KMREQ advertised) for the listener core to unwrap the caller's key material
// into — UnmarshalKM then overwrites the random keys.
func newCryptoCtx(keyLen int, mode crypto.CipherMode) (*crypto.Context, error) {
	return crypto.NewWithMode(keyLen, mode)
}
