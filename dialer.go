package srt

import (
	"net"

	"github.com/zsiec/srtgo/internal/seq"
	"github.com/zsiec/srtgo/internal/session"
)

// Dial connects to an SRT listener at addr (host:port) and returns an
// established connection. It performs the HSv5 caller handshake (INDUCTION +
// CONCLUSION), retransmitting until the connection completes or ConnTimeout
// elapses. The local UDP socket is created with the configured OS socket
// options applied.
func Dial(addr string, cfg Config) (*Conn, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := session.ListenUDP(udpNetwork(raddr), nil, cfg.udpSocketOptions())
	if err != nil {
		return nil, err
	}
	s, err := session.Dial(pc, raddr, cfg.dialConfig(), nil, cfg.ConnTimeout)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return newConn(s, cfg, false), nil
}

// dialGroupMember dials a connection that shares the group's send ISN, so all
// members' send sequence spaces stay in lockstep (each broadcast payload gets
// the same seqno on every link) and the receiver can deduplicate by sequence
// number. It deliberately does NOT advertise the group in the handshake: that
// keeps each accepted link a plain connection the listener returns via Accept
// (so the application assembles them into its own Group), rather than being
// captured by the session's internal AcceptGroup assembly.
func dialGroupMember(addr string, cfg Config, isn seq.Number) (*Conn, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := session.ListenUDP(udpNetwork(raddr), nil, cfg.udpSocketOptions())
	if err != nil {
		return nil, err
	}
	dc := cfg.dialConfig()
	dc.CallerISN = isn
	s, err := session.Dial(pc, raddr, dc, nil, cfg.ConnTimeout)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return newConn(s, cfg, false), nil
}
