package srt

import (
	"net"
)

// DialPacketConn connects to an SRT listener using an existing PacketConn.
// This enables custom transports (WebRTC DataChannels, QUIC, etc.)
// instead of the default UDP socket created by Dial.
//
// The remoteAddr specifies the address of the SRT listener.
// The caller is responsible for creating and managing the PacketConn lifetime
// until the SRT connection is established; after that, closing the SRT Conn
// will close the underlying PacketConn.
func DialPacketConn(conn net.PacketConn, remoteAddr net.Addr, cfg Config) (*Conn, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return dial(conn, remoteAddr, cfg, nil)
}

// ListenPacketConn creates an SRT listener on an existing PacketConn.
// This enables custom transports (WebRTC DataChannels, QUIC, etc.)
// instead of the default UDP socket created by Listen.
//
// The caller is responsible for creating and managing the PacketConn;
// closing the Listener will close the underlying PacketConn.
func ListenPacketConn(conn net.PacketConn, cfg Config) (*Listener, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return newListener(conn, cfg, nil)
}

// DialRendezvousPacketConn connects to a peer using rendezvous mode over
// an existing PacketConn. Both peers call this with the other's address.
// This enables custom transports instead of the default UDP socket.
func DialRendezvousPacketConn(conn net.PacketConn, remoteAddr net.Addr, cfg Config) (*Conn, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return dialRendezvous(conn, remoteAddr, cfg, nil)
}
