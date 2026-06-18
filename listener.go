package srt

import (
	"net"

	"github.com/zsiec/srtgo/internal/session"
)

// Listener accepts incoming SRT connections. Create one with Listen or
// ListenPacketConn.
type Listener struct {
	l   *session.Listener
	cfg Config
}

// Listen creates an SRT listener bound to addr (host:port). The UDP socket is
// created with the configured OS socket options applied.
func Listen(addr string, cfg Config) (*Listener, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := session.ListenUDP(udpNetwork(laddr), laddr, cfg.udpSocketOptions())
	if err != nil {
		return nil, err
	}
	sl, err := session.Listen(pc, cfg.listenerConfig(), nil)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return &Listener{l: sl, cfg: cfg}, nil
}

// Accept blocks until the next connection is established and returns it.
func (l *Listener) Accept() (*Conn, error) {
	s, err := l.l.Accept()
	if err != nil {
		return nil, err
	}
	return newConn(s, l.cfg, true), nil
}

// Close stops the listener and releases its socket.
func (l *Listener) Close() error { return l.l.Close() }

// Addr returns the listener's local UDP address.
func (l *Listener) Addr() net.Addr { return l.l.Addr() }
