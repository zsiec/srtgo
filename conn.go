package srt

import (
	"net"
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
}

// newConn wraps an established session, applying the blocking-mode and linger
// configuration the public Config selected.
func newConn(s *session.Session, cfg Config) *Conn {
	s.SetReadBlocking(cfg.rcvSynEnabled())
	s.SetWriteBlocking(cfg.sndSynEnabled())
	if cfg.Linger > 0 {
		s.SetLinger(cfg.Linger)
	}
	return &Conn{s: s, cfg: cfg}
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
