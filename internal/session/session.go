// Package session is the I/O host for the Sans-I/O SRT core. It owns the UDP
// multiplexer, the real clock, the timer wheel, and exactly one event-loop
// goroutine that drives a pure core.Conn.
//
// The loop is the only goroutine that touches the core. It reads the real
// clock once per wake-up, feeds the core (HandlePacket / HandleTimer / Write),
// then drains the core's effects (send datagrams, arm/clear timers) and events
// (delivered payloads, close). This mirrors ristgo's internal/session and
// srtrust's driver. Per connection there are two goroutines — the mux read
// loop and this event loop — versus three in the legacy design.
package session

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/handshake"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
	"github.com/zsiec/srtgo/internal/tsbpd"
)

// ErrClosed is returned by Read/Write after the session is closed.
var ErrClosed = errors.New("session: closed")

// ErrWouldBlock is returned by a non-blocking Read/Write that cannot proceed.
var ErrWouldBlock = errors.New("srt: operation would block")

// timeoutErr is the net.Error returned when a read/write deadline expires.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "srt: i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// ErrTimeout is returned when a read/write deadline expires. It satisfies
// net.Error with Timeout() == true.
var ErrTimeout net.Error = timeoutErr{}

// MsgMetadata reports per-message metadata for a received message — the read
// half of the public MsgCtrl. Boundary is the packet position of the message's
// first packet (packet.PositionSingle for a single-packet message), MsgNo is
// the SRT message number, and Seq is the message's first packet sequence number.
type MsgMetadata struct {
	Boundary int
	MsgNo    uint32
	Seq      uint32
}

// writeReq is a queued application write plus its per-message send options.
type writeReq struct {
	payload []byte
	opts    core.MsgOptions
	pooled  bool // payload is a pooled send buffer (ownership transfers to the core)
}

// delivery is one received message handed from the loop to Read/ReadMsg.
type delivery struct {
	data []byte
	meta MsgMetadata
}

// Session drives one core.Conn over a mux. Construct it with NewEstablished or
// Dial; Write/Read/Close are safe to call from other goroutines.
type Session struct {
	mux        *mux.Mux
	ownsMux    bool
	remoteAddr net.Addr
	clk        clock.Clock
	core       *core.Conn

	recvC  <-chan packet.Packet
	writeC chan writeReq
	readC  chan delivery

	connected chan error           // receives nil on Connected, err on Failed (dial)
	statsReq  chan chan core.Stats // Stats() requests, answered on the loop goroutine
	ctrl      chan func()          // runtime control closures, run on the loop goroutine
	readable  chan struct{}        // buffered(1): poked when data becomes available (Watcher)
	writable  chan struct{}        // buffered(1): poked when send-buffer space opens (Watcher)
	quit      chan struct{}        // closed by Close to ask the loop to stop
	loopDone  chan struct{}        // closed by the loop on exit

	// net.Conn deadlines and SRTO_RCVSYN/SNDSYN blocking modes. Read/Write honor
	// these; blocking defaults to true.
	readDeadline  atomic.Value // time.Time
	writeDeadline atomic.Value // time.Time
	rcvSyn        atomic.Bool  // true = blocking Read (default)
	sndSyn        atomic.Bool  // true = blocking Write (default)

	timers        map[core.TimerID]clock.Timestamp
	closeOnce     sync.Once
	dead          bool          // set on the loop goroutine when the core fails / the peer closes
	linger        time.Duration // on Close, drain in-flight data up to this long before SHUTDOWN (0 = none)
	closing       bool          // Close requested; the loop is flushing/draining before SHUTDOWN
	closeDeadline time.Time     // linger cutoff once closing

	// Group membership negotiated in the handshake (0 GroupID = not a member).
	// Set at construction; read-only thereafter.
	groupID     uint32
	groupType   uint8
	groupWeight uint16
	sharedISN   seq.Number

	// Identity from the handshake; set at construction, read-only thereafter.
	streamID string
	socketID uint32
}

// StreamID returns the stream identifier negotiated in the handshake ("" if none).
func (s *Session) StreamID() string { return s.streamID }

// SocketID returns this connection's local SRT socket ID.
func (s *Session) SocketID() uint32 { return s.socketID }

// GroupID returns the bonding group this connection joined in the handshake, or
// 0 if it is not a group member.
func (s *Session) GroupID() uint32 { return s.groupID }

// GroupType returns the negotiated group type (1=broadcast, 2=backup).
func (s *Session) GroupType() uint8 { return s.groupType }

// GroupWeight returns the member's priority weight (backup mode).
func (s *Session) GroupWeight() uint16 { return s.groupWeight }

// SharedISN returns the group's shared send sequence space (members of the same
// group share it so the receiver can deduplicate across links).
func (s *Session) SharedISN() seq.Number { return s.sharedISN }

// newSession wires a session around a (possibly still-connecting) core and
// starts its event loop.
func newSession(m *mux.Mux, recvC <-chan packet.Packet, ownsMux bool, remoteAddr net.Addr, clk clock.Clock, cc *core.Conn) *Session {
	s := &Session{
		mux:        m,
		ownsMux:    ownsMux,
		remoteAddr: remoteAddr,
		clk:        clk,
		core:       cc,
		recvC:      recvC,
		writeC:     make(chan writeReq, 256),
		readC:      make(chan delivery, 2048),
		connected:  make(chan error, 1),
		statsReq:   make(chan chan core.Stats),
		ctrl:       make(chan func(), 8),
		readable:   make(chan struct{}, 1),
		writable:   make(chan struct{}, 1),
		quit:       make(chan struct{}),
		loopDone:   make(chan struct{}),
		timers:     make(map[core.TimerID]clock.Timestamp),
	}
	s.rcvSyn.Store(true)
	s.sndSyn.Store(true)
	go s.loop()
	return s
}

// Stats returns a snapshot of the connection's counters. It is answered on the
// loop goroutine, so it is safe to call concurrently.
func (s *Session) Stats() (core.Stats, error) {
	resp := make(chan core.Stats, 1)
	select {
	case s.statsReq <- resp:
		return <-resp, nil
	case <-s.loopDone:
		return core.Stats{}, ErrClosed
	}
}

// NewEstablished builds a session for an already-connected core and starts its
// event loop.
//
//   - m / recvC: the multiplexer and this connection's inbound packet channel.
//   - ownsMux: if true, Close also closes the mux (client owns its socket).
//   - remoteAddr: where outgoing packets are written.
//   - cfg: the negotiated connection parameters.
//   - clk: the clock (RealClock in production, MockClock in tests).
func NewEstablished(m *mux.Mux, recvC <-chan packet.Packet, ownsMux bool, remoteAddr net.Addr, cfg core.Config, clk clock.Clock) *Session {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	return newSession(m, recvC, ownsMux, remoteAddr, clk, core.NewEstablished(cfg, clk.Now()))
}

// Dial performs a caller-side HSv5 handshake over conn to remoteAddr and
// returns a connected Session. It owns conn (Close closes it). The handshake
// retransmits until it completes or timeout elapses.
func Dial(conn net.PacketConn, remoteAddr net.Addr, dc core.DialConfig, clk clock.Clock, timeout time.Duration) (*Session, error) {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	if dc.CallerSocketID == 0 {
		id, err := handshake.GenerateSocketID()
		if err != nil {
			return nil, err
		}
		dc.CallerSocketID = id
	}
	if dc.CallerISN == 0 {
		isn, err := handshake.GenerateISN()
		if err != nil {
			return nil, err
		}
		dc.CallerISN = seq.Number(isn)
	}
	// Build the crypto context here (the I/O layer owns the entropy used for the
	// salt and session keys), keeping the core deterministic.
	if dc.Passphrase != "" && dc.CryptoCtx == nil {
		keyLen := dc.KeyLength
		if keyLen == 0 {
			keyLen = 16
		}
		mode := crypto.CipherCTR
		if dc.CryptoMode == 2 {
			mode = crypto.CipherGCM
		}
		ctx, err := crypto.NewWithMode(keyLen, mode)
		if err != nil {
			return nil, err
		}
		dc.CryptoCtx = ctx
	}
	mss := int(dc.MSS)
	if mss == 0 {
		mss = mux.DefaultMSS
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	m := mux.New(conn, mss)
	recvC := m.Register(dc.CallerSocketID)
	s := newSession(m, recvC, true, remoteAddr, clk, core.Dial(dc, clk.Now()))
	s.groupID = dc.GroupID
	s.groupType = dc.GroupType
	s.groupWeight = dc.GroupWeight
	s.sharedISN = dc.CallerISN
	s.streamID = dc.StreamID
	s.socketID = dc.CallerSocketID

	select {
	case err := <-s.connected:
		if err != nil {
			s.Close()
			return nil, err
		}
		return s, nil
	case <-time.After(timeout):
		s.Close()
		return nil, fmt.Errorf("session: handshake timeout after %s", timeout)
	}
}

// DialRendezvous performs a rendezvous (simultaneous-open) handshake: both peers
// call it with each other's address. The host supplies the entropy (socket ID,
// ISN, cookie) if rc leaves them zero. It blocks until the connection is
// established or the timeout elapses.
//
// Rendezvous needs both the initial peer WAVEHAND (which arrives with
// DestinationSocketID 0, so the mux routes it to its Handshake channel) and the
// later CONCLUSION/AGREEMENT/data (addressed to our socket ID). A small
// forwarder merges both into the session's input for the duration of the loop.
func DialRendezvous(conn net.PacketConn, remoteAddr net.Addr, rc core.RendezvousConfig, clk clock.Clock, timeout time.Duration) (*Session, error) {
	if clk == nil {
		clk = clock.NewRealClock()
	}
	if rc.SocketID == 0 {
		id, err := handshake.GenerateSocketID()
		if err != nil {
			return nil, err
		}
		rc.SocketID = id
	}
	if rc.ISN == 0 {
		isn, err := handshake.GenerateISN()
		if err != nil {
			return nil, err
		}
		rc.ISN = seq.Number(isn)
	}
	if rc.Cookie == 0 {
		ck, err := handshake.GenerateRandomCookie()
		if err != nil {
			return nil, err
		}
		rc.Cookie = ck
	}
	// Build the crypto context (the I/O layer owns the entropy); the core decides
	// at handshake time whether this peer generates the key material (initiator) or
	// adopts the peer's (responder), keeping the core deterministic.
	if rc.Passphrase != "" && rc.CryptoCtx == nil {
		keyLen := rc.KeyLength
		if keyLen == 0 {
			keyLen = 16
		}
		mode := crypto.CipherCTR
		if rc.CryptoMode == 2 {
			mode = crypto.CipherGCM
		}
		ctx, err := crypto.NewWithMode(keyLen, mode)
		if err != nil {
			return nil, err
		}
		rc.CryptoCtx = ctx
	}
	mss := int(rc.MSS)
	if mss == 0 {
		mss = mux.DefaultMSS
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	m := mux.New(conn, mss)
	recvC := m.Register(rc.SocketID)
	merged := make(chan packet.Packet, 256)
	stop := make(chan struct{})

	s := newSession(m, merged, true, remoteAddr, clk, core.DialRendezvous(rc, clk.Now()))

	// Merge the mux's handshake channel (peer WAVEHANDs, dest 0) and our socket's
	// channel (everything addressed to us) into the session input until the loop
	// exits.
	go func() {
		for {
			select {
			case p := <-recvC:
				select {
				case merged <- p:
				case <-stop:
					return
				}
			case p := <-m.Handshake:
				select {
				case merged <- p:
				case <-stop:
					return
				}
			case <-stop:
				return
			}
		}
	}()
	go func() { <-s.loopDone; close(stop) }()

	select {
	case err := <-s.connected:
		if err != nil {
			s.Close()
			return nil, err
		}
		return s, nil
	case <-time.After(timeout):
		s.Close()
		return nil, fmt.Errorf("session: rendezvous timeout after %s", timeout)
	}
}

// Write queues a payload for transmission. In blocking mode it waits for queue
// space (natural backpressure), honoring the write deadline; in non-blocking
// mode it returns ErrWouldBlock if the queue is full. It returns ErrClosed once
// the session is closed.
func (s *Session) Write(p []byte) error {
	return s.WriteMsg(p, core.MsgOptions{InOrder: true})
}

// WriteMsg writes one message with per-message options (source timestamp
// override, in-order bit) — the send half of the public WriteMsgCtrl. Blocking
// and deadline behavior matches Write.
func (s *Session) WriteMsg(p []byte, opts core.MsgOptions) error {
	// Snapshot the caller's payload (it may be reused after Write returns). For a
	// single-packet-sized payload the snapshot comes from the packet pool and its
	// ownership transfers to the core, which hands it to the send buffer with no
	// further copy (zero-copy send path). Larger payloads (which the core will
	// fragment) use a plain allocation. On any path that does not reach the core,
	// the pooled buffer is returned here.
	var cp []byte
	pooled := false
	if len(p) <= packet.MaxPayloadSize {
		cp = append(packet.GetSendBuffer(), p...)
		pooled = true
	} else {
		cp = make([]byte, len(p))
		copy(cp, p)
	}
	req := writeReq{payload: cp, opts: opts, pooled: pooled}
	recycle := func() {
		if pooled {
			packet.PutSendBuffer(cp)
		}
	}

	if !s.sndSyn.Load() {
		select {
		case s.writeC <- req:
			return nil
		case <-s.loopDone:
			recycle()
			return ErrClosed
		default:
			recycle()
			return ErrWouldBlock
		}
	}

	timeout, stop, expired := s.deadlineChan(&s.writeDeadline)
	if expired {
		recycle()
		return ErrTimeout
	}
	if stop != nil {
		defer stop()
	}
	select {
	case s.writeC <- req:
		return nil
	case <-timeout:
		recycle()
		return ErrTimeout
	case <-s.loopDone:
		recycle()
		return ErrClosed
	}
}

// Read returns the next delivered payload, copied into b. In blocking mode it
// waits for data, honoring the read deadline; in non-blocking mode it returns
// ErrWouldBlock if none is ready. It returns io.EOF once the session is closed
// and drained.
func (s *Session) Read(b []byte) (int, error) {
	n, _, err := s.ReadMsg(b)
	return n, err
}

// ReadMsg reads the next message into b and returns its metadata — the read half
// of the public ReadMsgCtrl. Blocking, deadline, and EOF behavior match Read.
func (s *Session) ReadMsg(b []byte) (int, MsgMetadata, error) {
	if !s.rcvSyn.Load() {
		select {
		case d := <-s.readC:
			n := copy(b, d.data)
			core.PutPayload(d.data) // recycle the pooled delivery payload; dead after copy-out
			return n, d.meta, nil
		case <-s.loopDone:
			return s.drainRead(b)
		default:
			return 0, MsgMetadata{}, ErrWouldBlock
		}
	}

	timeout, stop, expired := s.deadlineChan(&s.readDeadline)
	if expired {
		return 0, MsgMetadata{}, ErrTimeout
	}
	if stop != nil {
		defer stop()
	}
	select {
	case d := <-s.readC:
		n := copy(b, d.data)
		core.PutPayload(d.data) // recycle the pooled delivery payload; dead after copy-out
		return n, d.meta, nil
	case <-timeout:
		return 0, MsgMetadata{}, ErrTimeout
	case <-s.loopDone:
		return s.drainRead(b)
	}
}

// drainRead returns any message delivered before the loop exited, else io.EOF.
func (s *Session) drainRead(b []byte) (int, MsgMetadata, error) {
	select {
	case d := <-s.readC:
		n := copy(b, d.data)
		core.PutPayload(d.data) // recycle the pooled delivery payload; dead after copy-out
		return n, d.meta, nil
	default:
		return 0, MsgMetadata{}, io.EOF
	}
}

// deadlineChan returns a timer channel for the given deadline (nil if none),
// plus a stop func, and whether the deadline has already passed.
func (s *Session) deadlineChan(dl *atomic.Value) (<-chan time.Time, func() bool, bool) {
	v := dl.Load()
	if v == nil {
		return nil, nil, false
	}
	t, _ := v.(time.Time)
	if t.IsZero() {
		return nil, nil, false
	}
	d := time.Until(t)
	if d <= 0 {
		return nil, nil, true
	}
	timer := time.NewTimer(d)
	return timer.C, timer.Stop, false
}

// SetReadDeadline sets the deadline for future Read calls; a zero time clears it.
func (s *Session) SetReadDeadline(t time.Time) error {
	s.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls; a zero time clears it.
func (s *Session) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Store(t)
	return nil
}

// SetDeadline sets both the read and write deadlines.
func (s *Session) SetDeadline(t time.Time) error {
	s.readDeadline.Store(t)
	s.writeDeadline.Store(t)
	return nil
}

// control runs fn on the loop goroutine (where it may safely touch the core).
// Dropped if the loop has already exited.
func (s *Session) control(fn func()) {
	select {
	case s.ctrl <- fn:
	case <-s.loopDone:
	}
}

// SetMaxBW changes the max sending bandwidth (bytes/sec) at runtime; 0 = auto.
func (s *Session) SetMaxBW(bw int64) { s.control(func() { s.core.SetMaxBW(bw) }) }

// SetInputBW updates the estimated input bandwidth (bytes/sec) for auto-rate.
func (s *Session) SetInputBW(bw int64) { s.control(func() { s.core.SetInputBW(bw) }) }

// SetOverhead updates the retransmit bandwidth overhead percentage.
func (s *Session) SetOverhead(pct int) { s.control(func() { s.core.SetOverhead(pct) }) }

// SetReorderTolerance updates the reorder tolerance (SRTO_LOSSMAXTTL) at runtime.
func (s *Session) SetReorderTolerance(n int) { s.control(func() { s.core.SetReorderTolerance(n) }) }

// SetSndDropDelay updates the extra sender-drop delay (ms) at runtime.
func (s *Session) SetSndDropDelay(ms int) { s.control(func() { s.core.SetSndDropDelay(ms) }) }

// SendISN returns the local initial send sequence number.
func (s *Session) SendISN() uint32 {
	var v uint32
	s.onLoop(func() { v = s.core.SendISN() })
	return v
}

// RecvISN returns the peer's initial sequence number.
func (s *Session) RecvISN() uint32 {
	var v uint32
	s.onLoop(func() { v = s.core.RecvISN() })
	return v
}

// PeerVersion returns the peer's SRT version from the handshake (0 if unknown).
func (s *Session) PeerVersion() uint32 {
	var v uint32
	s.onLoop(func() { v = s.core.PeerVersion() })
	return v
}

// onLoop runs fn on the loop goroutine and waits for it (so reads of core state
// are race-free). Returns immediately if the loop has exited.
func (s *Session) onLoop(fn func()) {
	done := make(chan struct{})
	select {
	case s.ctrl <- func() { fn(); close(done) }:
	case <-s.loopDone:
		return
	}
	select {
	case <-done:
	case <-s.loopDone:
	}
}

// ---- group bonding primitives (used by the bonded Group host) ----

// SchedSeqNo returns the next send sequence number the core will assign.
func (s *Session) SchedSeqNo() seq.Number {
	var v seq.Number
	s.onLoop(func() { v = s.core.SchedSeqNo() })
	return v
}

// OverrideSndSeqNo forces the next send sequence number (group sequence sync).
func (s *Session) OverrideSndSeqNo(n seq.Number) bool {
	var ok bool
	s.onLoop(func() { ok = s.core.OverrideSndSeqNo(n) })
	return ok
}

// LastMsgNo returns the most recently assigned message number.
func (s *Session) LastMsgNo() uint32 {
	var v uint32
	s.onLoop(func() { v = s.core.LastMsgNo() })
	return v
}

// RcvBufEmpty reports whether the receive buffer has no available packets.
func (s *Session) RcvBufEmpty() bool {
	var v bool
	s.onLoop(func() { v = s.core.RcvBufEmpty() })
	return v
}

// RcvBufStartSeq returns the first sequence number in the receive buffer.
func (s *Session) RcvBufStartSeq() seq.Number {
	var v seq.Number
	s.onLoop(func() { v = s.core.RcvBufStartSeq() })
	return v
}

// ResetRecvState realigns the receiver to nextSeq (group failover).
func (s *Session) ResetRecvState(n seq.Number) { s.control(func() { s.core.ResetRecvState(n) }) }

// TSBPDTimeBase returns the TSBPD time base for group drift sync (nil if not live).
func (s *Session) TSBPDTimeBase() *tsbpd.GroupTimeBase {
	var v *tsbpd.GroupTimeBase
	s.onLoop(func() { v = s.core.TSBPDTimeBase() })
	return v
}

// ApplyGroupDrift applies a group-wide drift correction.
func (s *Session) ApplyGroupDrift(tb tsbpd.GroupTimeBase) {
	s.control(func() { s.core.ApplyGroupDrift(tb) })
}

// ApplyGroupTime applies a group-wide time base.
func (s *Session) ApplyGroupTime(tb tsbpd.GroupTimeBase) {
	s.control(func() { s.core.ApplyGroupTime(tb) })
}

// SendKeepAlive emits a KEEPALIVE immediately.
func (s *Session) SendKeepAlive() { s.control(func() { s.core.SendKeepAlive(s.clk.Now()) }) }

// CurrentSRTTimestamp returns the current SRT wire timestamp from the clock.
func (s *Session) CurrentSRTTimestamp() uint32 { return s.clk.Now().SRTTimestamp() }

// signal does a non-blocking poke of a buffered(1) readiness channel.
func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// Readable is signaled (buffered, edge-ish) when delivered data becomes
// available; the Watcher selects on it. Use len(readC)>0 / a non-blocking Read
// to confirm.
func (s *Session) Readable() <-chan struct{} { return s.readable }

// Writable is signaled when a send-buffer slot frees up (Watcher).
func (s *Session) Writable() <-chan struct{} { return s.writable }

// Done is closed when the event loop exits (peer close, failure, or Close).
func (s *Session) Done() <-chan struct{} { return s.loopDone }

// ReadReady reports whether a delivered message is buffered for Read.
func (s *Session) ReadReady() bool { return len(s.readC) > 0 }

// WriteReady reports whether a Write can proceed without blocking.
func (s *Session) WriteReady() bool { return len(s.writeC) < cap(s.writeC) }

// PeerGroupID returns the negotiated bonding group ID (0 if not a group member).
func (s *Session) PeerGroupID() uint32 { return s.groupID }

// GroupIdle reports whether the link is alive but idle (group backup monitor).
func (s *Session) GroupIdle() bool {
	var v bool
	s.onLoop(func() { v = s.core.GroupIdle() })
	return v
}

// AckSeqNo returns the receiver's current ACK point (group backup progress).
func (s *Session) AckSeqNo() seq.Number {
	var v seq.Number
	s.onLoop(func() { v = s.core.AckSeqNo() })
	return v
}

// Alive reports whether the event loop is still running.
func (s *Session) Alive() bool {
	select {
	case <-s.loopDone:
		return false
	default:
		return true
	}
}

// SetLinger sets how long Close drains in-flight data before sending SHUTDOWN.
// Zero (the default) closes immediately (still sending SHUTDOWN). Call before
// Close. Not safe to call concurrently with the event loop after Close begins.
func (s *Session) SetLinger(d time.Duration) { s.linger = d }

// SetReadBlocking sets blocking (SRTO_RCVSYN) for Read; non-blocking Read
// returns ErrWouldBlock when no data is ready.
func (s *Session) SetReadBlocking(blocking bool) { s.rcvSyn.Store(blocking) }

// SetWriteBlocking sets blocking (SRTO_SNDSYN) for Write.
func (s *Session) SetWriteBlocking(blocking bool) { s.sndSyn.Store(blocking) }

// Close stops the event loop and, if the session owns the mux, closes it.
func (s *Session) Close() error {
	s.closeOnce.Do(func() { close(s.quit) })
	<-s.loopDone
	if s.ownsMux {
		return s.mux.Close()
	}
	return nil
}

// RemoteAddr returns the peer address.
func (s *Session) RemoteAddr() net.Addr { return s.remoteAddr }

// LocalAddr returns the local socket address.
func (s *Session) LocalAddr() net.Addr { return s.mux.LocalAddr() }

// ---- event loop ----

func (s *Session) loop() {
	defer close(s.loopDone)

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	var backlog []delivery
	quit := s.quit // nil'd once closing so the closed channel stops re-selecting

	// Drain the effects the constructor queued (initial ACK/NAK timers).
	backlog = s.drain(s.clk.Now(), timer, backlog)

	for {
		backlog = s.flushBacklog(backlog)
		if s.dead {
			return // core failed mid-stream (e.g. peer idle timeout)
		}
		if s.closeFinished() {
			// Drained (or lingered out): tell the peer and exit.
			now := s.clk.Now()
			s.core.Shutdown(now)
			s.drain(now, timer, nil)
			return
		}

		select {
		case <-quit:
			// Begin graceful close: keep running so the loop flushes queued
			// writes and drains in-flight data; closeFinished() ends it.
			s.closing = true
			s.closeDeadline = time.Now().Add(s.linger)
			quit = nil
			s.rearm(timer, s.clk.Now()) // ensure a wakeup to re-check drain state

		case p, ok := <-s.recvC:
			if !ok {
				return
			}
			now := s.clk.Now()
			s.core.HandlePacket(now, p)
			backlog = s.drain(now, timer, backlog)

		case req := <-s.writeC:
			now := s.clk.Now()
			if req.pooled {
				s.core.WriteMsgOwned(now, req.payload, req.opts) // transfer the pooled buffer
			} else {
				s.core.WriteMsg(now, req.payload, req.opts)
			}
			backlog = s.drain(now, timer, backlog)
			signal(s.writable) // a write slot just freed

		case <-timer.C:
			now := s.clk.Now()
			s.fireTimers(now)
			backlog = s.drain(now, timer, backlog)

		case resp := <-s.statsReq:
			resp <- s.core.Stats()

		case fn := <-s.ctrl:
			fn()
			backlog = s.drain(s.clk.Now(), timer, backlog)
		}
	}
}

// closeFinished reports whether a closing session has finished draining and
// should send SHUTDOWN and exit: when queued writes are flushed and either the
// send buffer is empty (or no linger was requested), or the linger deadline has
// passed.
func (s *Session) closeFinished() bool {
	if !s.closing {
		return false
	}
	if len(s.writeC) > 0 {
		return false // always flush queued writes into the core first
	}
	if s.linger <= 0 {
		return true // no linger: SHUTDOWN once the queued writes are sent
	}
	if s.core.PendingSend() == 0 {
		return true // everything acknowledged
	}
	return time.Now().After(s.closeDeadline) // lingered out
}

// fireTimers delivers every timer whose deadline has passed to the core. The
// re-arm a fired timer requests arrives as a SetTimer effect drained afterward.
func (s *Session) fireTimers(now clock.Timestamp) {
	for id, deadline := range s.timers {
		if !deadline.After(now) {
			delete(s.timers, id)
			s.core.HandleTimer(now, id)
		}
	}
}

// drain executes all pending core effects and queues delivered messages, then
// re-arms the OS timer to the earliest pending deadline.
func (s *Session) drain(now clock.Timestamp, timer *time.Timer, backlog []delivery) []delivery {
	for {
		out, ok := s.core.PollOutput()
		if !ok {
			break
		}
		switch v := out.(type) {
		case core.SendPacket:
			v.Packet.Header.Addr = s.remoteAddr
			_ = s.mux.Send(v.Packet)
			if v.Owned {
				v.Packet.Release()
			}
		case core.SetTimer:
			s.timers[v.ID] = v.Deadline
		case core.ClearTimer:
			delete(s.timers, v.ID)
		}
	}
	for {
		ev, ok := s.core.PollEvent()
		if !ok {
			break
		}
		switch e := ev.(type) {
		case core.DataReceived:
			d := delivery{
				data: e.Data,
				meta: MsgMetadata{Boundary: e.Boundary, MsgNo: e.MsgNo, Seq: e.Seq},
			}
			select {
			case s.readC <- d:
			default:
				backlog = append(backlog, d)
			}
			signal(s.readable)
		case core.Connected:
			select {
			case s.connected <- nil:
			default:
			}
		case core.Failed:
			// Surface to a dial waiter (handshake failure) and tear down the loop
			// so a mid-stream failure (e.g. peer idle timeout) unblocks Read/Write.
			select {
			case s.connected <- e.Err:
			default:
			}
			s.dead = true
		case core.Closed:
			// Peer sent SHUTDOWN. Tear down the loop so Read drains any buffered
			// deliveries and then returns io.EOF, and Write returns ErrClosed.
			s.dead = true
		}
	}
	s.rearm(timer, now)
	return backlog
}

// flushBacklog pushes as many backlogged deliveries into readC as fit without
// blocking, so a slow Reader never stalls the protocol loop.
func (s *Session) flushBacklog(backlog []delivery) []delivery {
	i := 0
	for i < len(backlog) {
		select {
		case s.readC <- backlog[i]:
			i++
		default:
			return backlog[i:]
		}
	}
	return backlog[:0]
}

// rearm resets the OS timer to fire at the soonest pending core deadline.
func (s *Session) rearm(timer *time.Timer, now clock.Timestamp) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	earliest, ok := s.earliest()
	if !ok {
		return // no timers armed
	}
	d := earliest.Sub(now)
	if d < 0 {
		d = 0
	}
	timer.Reset(d.Duration())
}

func (s *Session) earliest() (clock.Timestamp, bool) {
	var best clock.Timestamp
	have := false
	for _, deadline := range s.timers {
		if !have || deadline.Before(best) {
			best, have = deadline, true
		}
	}
	return best, have
}
