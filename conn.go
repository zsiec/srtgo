package srt

import (
	"net"
	"sync"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/session"
)

// Conn is an established SRT connection. It implements net.Conn (Read/Write/
// Close/Local-Remote-Addr/deadlines) and adds SRT-specific accessors. It is a
// thin façade over the Sans-I/O core driven by internal/session; all protocol
// state lives there.
type Conn struct {
	s   *session.Session
	cfg Config

	// Runtime option state (GetOption/SetOption). cfg holds the configured/
	// updated values; these track live blocking/timeout state and the role.
	isServer bool
	sndSyn   bool
	rcvSyn   bool
	sndTimeo time.Duration
	rcvTimeo time.Duration

	// SendRate sampling state.
	rateMu sync.Mutex
	rateAt time.Time
	rateP  uint64
	rateB  uint64
}

// newConn wraps an established session, applying the blocking-mode and linger
// configuration the public Config selected. isServer marks accepted (listener-
// side) connections.
func newConn(s *session.Session, cfg Config, isServer bool) *Conn {
	c := &Conn{
		s:        s,
		cfg:      cfg,
		isServer: isServer,
		sndSyn:   cfg.sndSynEnabled(),
		rcvSyn:   cfg.rcvSynEnabled(),
	}
	s.SetReadBlocking(c.rcvSyn)
	s.SetWriteBlocking(c.sndSyn)
	if cfg.Linger > 0 {
		s.SetLinger(cfg.Linger)
	}
	return c
}

// Read reads the next available data into b (net.Conn semantics). In blocking
// mode it waits for data honoring the read deadline; in non-blocking mode
// (RcvSyn=false) it returns ErrWouldBlock when nothing is ready, and io.EOF once
// the connection is closed and drained.
func (c *Conn) Read(b []byte) (int, error) { return c.s.Read(b) }

// Write sends b on the connection (net.Conn semantics), returning len(b) on
// success. In blocking mode it waits for send-buffer space honoring the write
// deadline; in non-blocking mode (SndSyn=false) it returns ErrWouldBlock when
// the buffer is full.
func (c *Conn) Write(b []byte) (int, error) {
	if err := c.s.Write(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close shuts the connection down. With a positive Linger it drains the send
// buffer (up to Linger) before sending SHUTDOWN; otherwise it closes promptly.
func (c *Conn) Close() error { return c.s.Close() }

// LocalAddr returns the local UDP address.
func (c *Conn) LocalAddr() net.Addr { return c.s.LocalAddr() }

// RemoteAddr returns the peer's UDP address.
func (c *Conn) RemoteAddr() net.Addr { return c.s.RemoteAddr() }

// SetDeadline sets both the read and write deadlines.
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.s.SetReadDeadline(t); err != nil {
		return err
	}
	return c.s.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls (zero clears it).
func (c *Conn) SetReadDeadline(t time.Time) error { return c.s.SetReadDeadline(t) }

// SetWriteDeadline sets the deadline for future Write calls (zero clears it).
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.s.SetWriteDeadline(t) }

// GroupID returns the bonding group this connection joined in the handshake, or
// 0 if it is not a group member.
func (c *Conn) GroupID() uint32 { return c.s.GroupID() }

// SetMaxBW changes the maximum sending bandwidth in bytes/sec at runtime (0 =
// auto). It takes effect on the running connection.
func (c *Conn) SetMaxBW(bw int64) {
	c.cfg.MaxBW = bw
	c.s.SetMaxBW(bw)
}

// SendRate returns the send rate (packets/sec, bytes/sec) measured since the
// previous SendRate call. The first call returns (0, 0).
func (c *Conn) SendRate() (pktPerSec int64, bytesPerSec int64) {
	st, err := c.s.Stats()
	if err != nil {
		return 0, 0
	}
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	now := time.Now()
	if !c.rateAt.IsZero() {
		if dt := now.Sub(c.rateAt).Seconds(); dt > 0 {
			pktPerSec = int64(float64(st.SentPackets-c.rateP) / dt)
			bytesPerSec = int64(float64(st.SentBytes-c.rateB) / dt)
		}
	}
	c.rateAt, c.rateP, c.rateB = now, st.SentPackets, st.SentBytes
	return pktPerSec, bytesPerSec
}

// StreamID returns the stream identifier negotiated in the handshake ("" if none).
func (c *Conn) StreamID() string { return c.s.StreamID() }

// SocketID returns this connection's local SRT socket ID.
func (c *Conn) SocketID() uint32 { return c.s.SocketID() }

// WriteMessage sends b as a single SRT message (message-mode framing). In live
// mode it is equivalent to Write.
func (c *Conn) WriteMessage(b []byte) (int, error) {
	return c.WriteMsgCtrl(b, nil)
}

// ReadMessage reads the next complete message into b.
func (c *Conn) ReadMessage(b []byte) (int, error) {
	return c.ReadMsgCtrl(b, nil)
}

// WriteMsgCtrl sends b as one message with the per-message options in mc (nil
// means defaults: in-order, no TTL, current source time). Returns len(b).
func (c *Conn) WriteMsgCtrl(b []byte, mc *MsgCtrl) (int, error) {
	opts := core.MsgOptions{InOrder: true}
	if mc != nil {
		opts.InOrder = mc.InOrder
		if mc.MsgTTL > 0 {
			opts.TTL = clock.Microseconds(mc.MsgTTL.Microseconds())
		}
	}
	if err := c.s.WriteMsg(b, opts); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadMsgCtrl reads the next complete message into b, filling mc (if non-nil)
// with the message's read-only metadata (boundary, first packet seq, msg no).
func (c *Conn) ReadMsgCtrl(b []byte, mc *MsgCtrl) (int, error) {
	n, meta, err := c.s.ReadMsg(b)
	if err != nil {
		return n, err
	}
	if mc != nil {
		mc.Boundary = meta.Boundary
		mc.PktSeq = meta.Seq
		mc.MsgNo = meta.MsgNo
	}
	return n, nil
}
