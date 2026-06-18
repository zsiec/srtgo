package srt

import (
	"net"

	"github.com/zsiec/srtgo/internal/session"
)

// udpNetwork picks the UDP network for a local/remote address: udp4 for an IPv4
// address, udp6 for IPv6, and the unspecified "udp" for a wildcard (nil IP) so
// the OS chooses (typically dual-stack).
func udpNetwork(a *net.UDPAddr) string {
	if a == nil || a.IP == nil {
		return "udp"
	}
	if a.IP.To4() != nil {
		return "udp4"
	}
	return "udp6"
}

// DialPacketConn dials an SRT listener over a caller-supplied net.PacketConn
// (e.g. a QUIC/WebRTC datagram channel) instead of a UDP socket. The session
// takes ownership of conn.
func DialPacketConn(conn net.PacketConn, remoteAddr net.Addr, cfg Config) (*Conn, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s, err := session.Dial(conn, remoteAddr, cfg.dialConfig(), nil, cfg.ConnTimeout)
	if err != nil {
		return nil, err
	}
	return newConn(s, cfg, false), nil
}

// ListenPacketConn creates an SRT listener over a caller-supplied
// net.PacketConn instead of a UDP socket.
func ListenPacketConn(conn net.PacketConn, cfg Config) (*Listener, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	sl, err := session.Listen(conn, cfg.listenerConfig(), nil)
	if err != nil {
		return nil, err
	}
	return &Listener{l: sl, cfg: cfg}, nil
}
