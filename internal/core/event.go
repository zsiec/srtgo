package core

// Event is an application-visible occurrence the core surfaces to the host. The
// set is sealed (only this package implements isEvent). The host pulls events
// via Conn.PollEvent until it returns ok=false and translates them into the
// public API (Read returns, handshake completion, errors, close).
type Event interface {
	isEvent()
}

// Connected reports that the handshake completed and the connection is ready.
// It carries the peer's socket ID; the negotiated parameters (latency, payload
// size, flags, …) are applied to the connection during establish and read back
// via Stats and the accessor methods rather than echoed in this event.
type Connected struct {
	PeerSocketID uint32
}

// DataReceived hands one fully reassembled payload to the host for delivery to
// Read. The host takes ownership of Data. Seq is the (first) packet's SRT
// sequence number, used by connection bonding to deduplicate across links and
// surfaced to the application as the message's PktSeq. MsgNo is the SRT message
// number and Boundary is the packet position (packet.PositionSingle/First/...)
// — both surfaced through the message-mode read API (ReadMsg/MsgCtrl).
type DataReceived struct {
	Data     []byte
	Seq      uint32
	MsgNo    uint32
	Boundary int
}

// Failed reports a fatal connection error (handshake timeout, crypto mismatch,
// protocol violation). After Failed the connection is dead.
type Failed struct {
	Err error
}

// Closed reports that the peer sent SHUTDOWN (orderly close).
type Closed struct{}

// KeyRefreshNeeded reports that key rotation is due and the host should supply
// new key material of KeySize bytes.
type KeyRefreshNeeded struct {
	KeySize int
}

func (Connected) isEvent()        {}
func (DataReceived) isEvent()     {}
func (Failed) isEvent()           {}
func (Closed) isEvent()           {}
func (KeyRefreshNeeded) isEvent() {}
