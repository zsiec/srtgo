package legacy

import (
	"time"

	"github.com/zsiec/srtgo/internal/packet"
)

// MsgCtrl provides per-message metadata for advanced send/receive operations.
// It allows setting a custom source timestamp and per-message TTL on send,
// and reading message boundary and sequence information on receive.
// SRT_MSGCTRL equivalent for per-message metadata.
type MsgCtrl struct {
	// SrcTime is a custom source timestamp for the message (send only).
	// When zero, the current time is used (default behavior).
	SrcTime time.Time

	// MsgTTL is a per-message time-to-live (send only). Packets older than
	// this are dropped from the send buffer before retransmission.
	// Zero means no per-message TTL (use the global TSBPD drop threshold).
	MsgTTL time.Duration

	// InOrder specifies whether this message must be delivered in order (send only).
	// When true, the receiver will only deliver this message after all
	// earlier messages have been delivered. When false, the receiver may
	// deliver this message out of order if it arrives before earlier ones.
	// Default true for live, false allowed for file.
	InOrder bool

	// Boundary indicates the packet position within a message (read only).
	// One of: packet.PositionSingle, PositionFirst, PositionMiddle, PositionLast.
	Boundary int

	// PktSeq is the first packet sequence number of the message (read only).
	PktSeq uint32

	// MsgNo is the message number (read only).
	MsgNo uint32

	// GroupData provides per-member status when reading from a bonded group.
	// Each entry corresponds to one group member connection and reports its
	// current state and RTT. Nil for non-group connections.
	GroupData []GroupMemberData
}

// GroupMemberData reports the status of one member in a bonded connection group.
// SRT_MEMBER_STATUS equivalent.
type GroupMemberData struct {
	// State is the backup state of this member (e.g., ActiveStable, Standby).
	State BackupState
	// Weight is the member's priority weight (higher = preferred for backup).
	Weight uint16
	// RTT is the member's current smoothed round-trip time.
	RTT time.Duration
}

// boundaryFromPosition converts a PacketPosition to the Boundary int value.
func boundaryFromPosition(pos packet.PacketPosition) int {
	return int(pos)
}
