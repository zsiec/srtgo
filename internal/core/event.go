package core

// Event is an application-visible occurrence the core surfaces to the host. The
// set is sealed (only this package implements isEvent). The host pulls events
// via Conn.PollEvent until it returns ok=false and translates them into the
// public API (Read returns, handshake completion, errors, close).
type Event interface {
	isEvent()
}

// Connected reports that the handshake completed and the connection is ready.
// Negotiated parameters are filled in during the handshake phase of the
// migration; for now it carries the peer's socket ID.
type Connected struct {
	PeerSocketID uint32
}

// DataReceived hands one in-order, fully reassembled payload to the host for
// delivery to Read. The host takes ownership of Data.
type DataReceived struct {
	Data []byte
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
