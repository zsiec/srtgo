package srt

import (
	"net"

	"github.com/zsiec/srtgo/internal/session"
)

// ConnRequest describes an incoming connection during the handshake, passed to
// a listener accept callback to authorize or reject it (e.g. by StreamID).
type ConnRequest struct {
	StreamID   string   // stream ID from the caller's handshake
	RemoteAddr net.Addr // caller's address
	HSVersion  uint32   // handshake version (4 or 5)
	GroupID    uint32   // group ID if a bonded-group connection, else 0
	GroupType  uint8    // group type (1=broadcast, 2=backup) when GroupID != 0
}

// AcceptFunc gates an incoming connection: return false to reject it (with the
// default code). Set via Listener.SetAcceptFunc.
type AcceptFunc func(req ConnRequest) bool

// AcceptRejectFunc gates an incoming connection with a specific rejection code:
// return 0 to accept, or a non-zero RejectReason to reject with that code. Set
// via Listener.SetAcceptRejectFunc.
type AcceptRejectFunc func(req ConnRequest) RejectReason

func connRequest(r session.AcceptRequest) ConnRequest {
	return ConnRequest{
		StreamID:   r.StreamID,
		RemoteAddr: r.RemoteAddr,
		HSVersion:  r.HSVersion,
		GroupID:    r.GroupID,
		GroupType:  r.GroupType,
	}
}

// SetAcceptFunc installs a callback consulted once per incoming connection
// during the handshake; returning false rejects it. Pass nil to clear.
func (l *Listener) SetAcceptFunc(fn AcceptFunc) {
	if fn == nil {
		l.l.SetAcceptGate(nil)
		return
	}
	l.l.SetAcceptGate(func(r session.AcceptRequest) (bool, uint32) {
		return fn(connRequest(r)), 0
	})
}

// SetAcceptRejectFunc installs a callback consulted once per incoming connection
// during the handshake; return 0 to accept or a non-zero RejectReason to reject
// with that handshake code. Pass nil to clear.
func (l *Listener) SetAcceptRejectFunc(fn AcceptRejectFunc) {
	if fn == nil {
		l.l.SetAcceptGate(nil)
		return
	}
	l.l.SetAcceptGate(func(r session.AcceptRequest) (bool, uint32) {
		code := fn(connRequest(r))
		if code == 0 {
			return true, 0
		}
		return false, uint32(code)
	})
}
