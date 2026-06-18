package srt

import (
	"net"

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
