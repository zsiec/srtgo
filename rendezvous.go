package srt

import (
	"net"

	"github.com/zsiec/srtgo/internal/session"
)

// DialRendezvous establishes a peer-to-peer connection by simultaneous open:
// both endpoints call it with their own local address and the other's address
// (no listener). It is the standard way through symmetric NATs/firewalls.
//
// NOTE: rendezvous is currently unencrypted (Passphrase is ignored).
func DialRendezvous(localAddr, remoteAddr string, cfg Config) (*Conn, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, err
	}
	pc, err := session.ListenUDP(udpNetwork(laddr), laddr, cfg.udpSocketOptions())
	if err != nil {
		return nil, err
	}
	s, err := session.DialRendezvous(pc, raddr, cfg.rendezvousConfig(), nil, cfg.ConnTimeout)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return newConn(s, cfg), nil
}

// DialRendezvousPacketConn is DialRendezvous over a caller-supplied
// net.PacketConn instead of a UDP socket.
func DialRendezvousPacketConn(conn net.PacketConn, remoteAddr net.Addr, cfg Config) (*Conn, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s, err := session.DialRendezvous(conn, remoteAddr, cfg.rendezvousConfig(), nil, cfg.ConnTimeout)
	if err != nil {
		return nil, err
	}
	return newConn(s, cfg), nil
}
