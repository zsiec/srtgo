package packet

import "net"

// GetSendBuffer returns a pooled, zero-length payload buffer (cap
// MaxPayloadSize+HeaderSize) for the send path. The session fills it with one
// message's payload snapshot and hands it to NewDataOwned, so the send buffer
// takes ownership of it without a second copy; Release (on ACK/drop) returns it
// to the pool. Return an unused buffer (a write that never reached the core)
// with PutSendBuffer.
func GetSendBuffer() []byte { return getBuffer() }

// PutSendBuffer returns an unused send buffer to the pool.
func PutSendBuffer(b []byte) { putBuffer(b) }

// NewDataOwned builds a data packet that TAKES OWNERSHIP of owned as its payload
// buffer, with no copy. owned MUST come from GetSendBuffer (so Release returns it
// to the pool) and MUST NOT be referenced or reused by the caller afterwards.
// Use it only for a whole single-packet message — never a fragment sub-slice,
// which would alias one backing array across packets and double-free on Release.
func NewDataOwned(addr net.Addr, seqNo uint32, timestamp uint32, destSocketID uint32, owned []byte) Packet {
	return Packet{
		Header: Header{
			Addr:                addr,
			SequenceNumber:      seqNo,
			Timestamp:           timestamp,
			DestinationSocketID: destSocketID,
			PacketPosition:      PositionSingle,
			MessageNumber:       1,
		},
		Data:   owned,
		pooled: owned,
	}
}
