package core

import (
	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/packet"
)

// Output is a wire or timer effect the core asks the host to perform. The set is
// sealed (only this package implements isOutput), so a host can switch over it
// exhaustively. The host pulls outputs via Conn.PollOutput until it returns
// ok=false.
type Output interface {
	isOutput()
}

// SendPacket asks the host to transmit one SRT packet to the peer.
//
// The core leaves Packet.Header.Addr nil; the host attaches the destination
// address before writing to the socket. (Keeping addresses out of the core is
// what lets this package avoid a direct dependency on net.)
//
// Owned tells the host who owns the packet's pooled buffer:
//   - Owned == false: the packet is still owned by the core's send buffer (an
//     original data send retained for possible retransmission). The host must
//     marshal it read-only and MUST NOT Release it.
//   - Owned == true: the packet was freshly built (control packets) or cloned
//     (retransmissions) for this send. The host owns it and SHOULD Release it
//     after marshaling, to return the pooled buffer.
//
// Distinguishing the two keeps the hot original-send path free of per-packet
// clones while still letting the host pool control/retransmit buffers.
type SendPacket struct {
	Packet packet.Packet
	Owned  bool
}

// SetTimer asks the host to arm — or re-arm — timer ID so that it fires at
// Deadline. Re-arming an already-armed timer replaces its deadline.
type SetTimer struct {
	ID       TimerID
	Deadline clock.Timestamp
}

// ClearTimer asks the host to cancel timer ID if it is armed.
type ClearTimer struct {
	ID TimerID
}

func (SendPacket) isOutput() {}
func (SetTimer) isOutput()   {}
func (ClearTimer) isOutput() {}
