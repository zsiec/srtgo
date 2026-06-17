package core

// TimerID names a logical timer the core depends on. The core never owns a real
// timer: it asks the host to arm a deadline via SetTimer and is called back via
// HandleTimer when the deadline passes. The set mirrors srtrust's TimerId.
type TimerID uint8

const (
	// TimerHandshake — caller: resend induction/conclusion until answered.
	TimerHandshake TimerID = iota
	// TimerACK — receiver: periodic full ACK (the SYN interval, 10ms).
	TimerACK
	// TimerNAK — receiver: periodic loss report.
	TimerNAK
	// TimerEXP — sender: retransmit timeout (RTO).
	TimerEXP
	// TimerTSBPD — receiver: timestamp-based packet delivery (playout).
	TimerTSBPD
	// TimerSndPacing — sender: live-CC pacing of the next send.
	TimerSndPacing
	// TimerLinger — sender: graceful-close linger cap.
	TimerLinger
	// TimerKeepalive — periodic keepalive.
	TimerKeepalive
	// TimerPeerIdle — idle/dead-peer timeout.
	TimerPeerIdle
)

// String returns a human-readable timer name for logging and tests.
func (id TimerID) String() string {
	switch id {
	case TimerHandshake:
		return "Handshake"
	case TimerACK:
		return "ACK"
	case TimerNAK:
		return "NAK"
	case TimerEXP:
		return "EXP"
	case TimerTSBPD:
		return "TSBPD"
	case TimerSndPacing:
		return "SndPacing"
	case TimerLinger:
		return "Linger"
	case TimerKeepalive:
		return "Keepalive"
	case TimerPeerIdle:
		return "PeerIdle"
	default:
		return "TimerID(?)"
	}
}
