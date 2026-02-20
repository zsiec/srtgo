//go:build !js

package srt

import (
	"context"
	"net"
	"syscall"
)

// listenUDP creates a UDP PacketConn with OS-level socket options applied.
// It replaces direct net.ListenUDP calls to apply IPTTL, IPTOS, IPv6Only,
// and BindToDevice before the socket is bound.
func listenUDP(network string, laddr *net.UDPAddr, cfg Config) (net.PacketConn, error) {
	ctrl := makeSocketControl(cfg)
	if ctrl == nil {
		// No socket options to set — fast path
		return net.ListenUDP(network, laddr)
	}

	lc := net.ListenConfig{
		Control: ctrl,
	}

	addr := ""
	if laddr != nil {
		addr = laddr.String()
	}

	return lc.ListenPacket(context.Background(), network, addr)
}

// makeSocketControl returns a Control callback for net.ListenConfig that
// applies IPTTL, IPTOS, IPv6Only, BindToDevice, and UDP buffer sizes via setsockopt.
// Returns nil if no socket options need to be set.
func makeSocketControl(cfg Config) func(network, address string, c syscall.RawConn) error {
	needsControl := cfg.IPTTL > 0 || cfg.IPTOS >= 0 || cfg.IPv6Only != nil || cfg.BindToDevice != "" ||
		cfg.UDPSendBufSize > 0 || cfg.UDPRecvBufSize > 0
	if !needsControl {
		return nil
	}

	return func(network, address string, c syscall.RawConn) error {
		isIPv6 := network == "udp6" || network == "tcp6"

		var opErr error
		err := c.Control(func(fd uintptr) {
			fdInt := int(fd)

			// UDP send buffer: SO_SNDBUF
			if cfg.UDPSendBufSize > 0 {
				opErr = syscall.SetsockoptInt(fdInt, syscall.SOL_SOCKET, syscall.SO_SNDBUF, cfg.UDPSendBufSize)
				if opErr != nil {
					return
				}
			}

			// UDP receive buffer: SO_RCVBUF
			if cfg.UDPRecvBufSize > 0 {
				opErr = syscall.SetsockoptInt(fdInt, syscall.SOL_SOCKET, syscall.SO_RCVBUF, cfg.UDPRecvBufSize)
				if opErr != nil {
					return
				}
			}

			// TTL: IP_TTL (IPv4) or IPV6_UNICAST_HOPS (IPv6)
			if cfg.IPTTL > 0 {
				if isIPv6 {
					opErr = syscall.SetsockoptInt(fdInt, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, cfg.IPTTL)
				} else {
					opErr = syscall.SetsockoptInt(fdInt, syscall.IPPROTO_IP, syscall.IP_TTL, cfg.IPTTL)
				}
				if opErr != nil {
					return
				}
			}

			// TOS: IP_TOS (IPv4) or IPV6_TCLASS (IPv6)
			if cfg.IPTOS >= 0 {
				if isIPv6 {
					opErr = syscall.SetsockoptInt(fdInt, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, cfg.IPTOS)
				} else {
					opErr = syscall.SetsockoptInt(fdInt, syscall.IPPROTO_IP, syscall.IP_TOS, cfg.IPTOS)
				}
				if opErr != nil {
					return
				}
			}

			// IPv6Only: IPV6_V6ONLY (only meaningful for IPv6 sockets)
			if cfg.IPv6Only != nil && isIPv6 {
				v := 0
				if *cfg.IPv6Only {
					v = 1
				}
				opErr = syscall.SetsockoptInt(fdInt, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, v)
				if opErr != nil {
					return
				}
			}

			// BindToDevice: SO_BINDTODEVICE (Linux-only)
			if cfg.BindToDevice != "" {
				opErr = setBindToDevice(fdInt, cfg.BindToDevice)
				if opErr != nil {
					return
				}
			}
		})
		if err != nil {
			return err
		}
		return opErr
	}
}
