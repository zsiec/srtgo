package srt

import "time"

// MsgCtrl carries per-message metadata for the message-mode send/receive calls
// WriteMsgCtrl / ReadMsgCtrl.
type MsgCtrl struct {
	// SrcTime is a custom source timestamp for the message (send only). Zero uses
	// the current time. TODO(cutover): a non-zero SrcTime override is not yet
	// applied (it requires converting wall-clock time to the connection's wire
	// time base); the current time is used regardless.
	SrcTime time.Time

	// MsgTTL is a per-message time-to-live (send only). The sender drops the
	// message (and tells the receiver to skip it) if it is still unacknowledged
	// this long after first transmission. Zero means no per-message TTL.
	MsgTTL time.Duration

	// InOrder requests in-order delivery for this message (send only). In live /
	// stream mode delivery is always in order; in message mode a false value lets
	// the receiver deliver this message ahead of an earlier incomplete one.
	InOrder bool

	// Boundary is the packet position within the message (read only): one of
	// packet.PositionSingle / First / Middle / Last.
	Boundary int

	// PktSeq is the message's first packet sequence number (read only).
	PktSeq uint32

	// MsgNo is the message number (read only).
	MsgNo uint32

	// GroupData (per-member status when reading from a bonded group) is added with
	// the public Group API.
}
