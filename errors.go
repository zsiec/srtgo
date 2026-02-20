package srt

import (
	"errors"

	"github.com/zsiec/srtgo/internal/packet"
)

// Rejection reasons for handshake failures.
// These are sent in the HandshakeType field of a rejection response.
const (
	RejUnknown    = packet.HandshakeType(1000) // unknown reason
	RejSystem     = packet.HandshakeType(1001) // system function error
	RejPeer       = packet.HandshakeType(1002) // rejected by peer
	RejResource   = packet.HandshakeType(1003) // resource allocation problem
	RejRogue      = packet.HandshakeType(1004) // incorrect data in handshake
	RejBacklog    = packet.HandshakeType(1005) // listener's backlog exceeded
	RejIPE        = packet.HandshakeType(1006) // internal program error
	RejClose      = packet.HandshakeType(1007) // socket is closing
	RejVersion    = packet.HandshakeType(1008) // peer version too old
	RejRdvCookie  = packet.HandshakeType(1009) // rendezvous cookie collision (reserved)
	RejBadSecret  = packet.HandshakeType(1010) // wrong password
	RejUnsecure   = packet.HandshakeType(1011) // password required or unexpected
	RejMessageAPI = packet.HandshakeType(1012) // stream flag collision
	RejCongestion = packet.HandshakeType(1013) // incompatible congestion controller
	RejFilter     = packet.HandshakeType(1014) // incompatible packet filter
	RejGroup      = packet.HandshakeType(1015) // incompatible group
	RejTimeout    = packet.HandshakeType(1016) // connection timeout
	RejCrypto     = packet.HandshakeType(1017) // conflicting cryptographic configurations

	// RejUserDefined is the base for user-defined rejection codes.
	// Codes 2000+ are passed through unchanged in the rejection handshake.
	RejUserDefined = packet.HandshakeType(2000)

	// Extended rejection codes for access control (matching C++ access_control.h).
	// These are within the user-defined range (>= 1000) and pass through
	// the wire format unchanged.
	RejXBadRequest    = packet.HandshakeType(1400) // malformed stream ID
	RejXUnauthorized  = packet.HandshakeType(1401) // authentication required
	RejXOverloaded    = packet.HandshakeType(1402) // server overloaded
	RejXForbidden     = packet.HandshakeType(1403) // access denied
	RejXNotFound      = packet.HandshakeType(1404) // resource not found
	RejXBadMode       = packet.HandshakeType(1405) // unsupported mode
	RejXUnacceptable  = packet.HandshakeType(1406) // parameters unacceptable
	RejXConflict      = packet.HandshakeType(1409) // resource conflict
	RejXLocked        = packet.HandshakeType(1423) // resource locked
	RejXInternalError = packet.HandshakeType(1500) // server internal error
	RejXUnavailable   = packet.HandshakeType(1503) // service unavailable
)

// Peer error codes sent via PEERERROR control packets (Section 3.2.10).
// The error code is carried in the TypeSpecific field of the control header.
const (
	// PeerErrorFileSystem indicates a filesystem error on the peer (e.g. disk
	// write failure during file transfer). This is the only error code defined
	// in the SRT specification and the C++ reference implementation.
	// Matches C++ CUDTException::EFILE = MJ_FILESYSTEM * 1000 = 4000.
	PeerErrorFileSystem uint32 = 4000
)

// RejectReason is a type alias for rejection codes used in AcceptRejectFunc.
type RejectReason = packet.HandshakeType

// AcceptRejectFunc is called for each incoming connection during the handshake.
// It receives the connection request and returns a rejection reason.
// Return 0 to accept the connection. Return any non-zero HandshakeType to reject
// with that code (e.g., RejPeer, or user-defined codes >= RejUserDefined).
type AcceptRejectFunc func(req ConnRequest) RejectReason

// Sentinel errors for common conditions.
var (
	// ErrWouldBlock is returned when a non-blocking send or receive cannot complete
	// immediately (SRTO_SNDSYN=false or SRTO_RCVSYN=false).
	ErrWouldBlock = errors.New("srt: operation would block")

	// ErrGroupClosed is returned when operating on a closed Group.
	ErrGroupClosed = errors.New("srt: group closed")

	// ErrListenerClosed is returned when Accept is called on a closed Listener.
	ErrListenerClosed = errors.New("srt: listener closed")

	// ErrNilConnection is returned when a nil Conn is passed to a group or watcher.
	ErrNilConnection = errors.New("srt: nil connection")

	// ErrPeerError is returned when the peer sends an error.
	ErrPeerError = errors.New("srt: peer error")

	// ErrConnectionTimeout is returned when the connection times out due to inactivity.
	ErrConnectionTimeout = errors.New("srt: connection timeout")

	// ErrPeerShutdown is returned when the peer sends a shutdown control packet.
	ErrPeerShutdown = errors.New("srt: peer shutdown")
)
