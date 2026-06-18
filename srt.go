// Package srt implements the SRT (Secure Reliable Transport) protocol in pure Go.
//
// The public API (Dial, Listen, Conn, Listener, Config, …) is a thin façade over
// a Sans-I/O protocol core: a pure state machine in internal/core driven by an
// I/O host in internal/session that owns the UDP socket, clock, and event loop.
// All protocol behavior — handshake, ACK/NAK/retransmit, TSBPD playout,
// encryption, FEC, congestion control, bonding — lives in those packages.
package srt
