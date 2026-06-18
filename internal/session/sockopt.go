//go:build !js

package session

import (
	"context"
	"net"
	"syscall"
)

// UDPSocketOptions are OS-level options applied to the UDP socket before it is
// bound. They mirror the SRT socket options that act on the underlying datagram
// socket (SRTO_IPTTL, SRTO_IPTOS, SRTO_UDP_SNDBUF/RCVBUF, IPV6_V6ONLY,
// SRTO_BINDTODEVICE). The zero value applies nothing.
type UDPSocketOptions struct {
	IPTTL          int    // IP TTL / IPv6 hop limit; >0 to set (0 = OS default)
	IPTOS          int    // IP TOS / IPv6 traffic class; >=0 to set (-1 = OS default)
	IPv6Only       *bool  // IPV6_V6ONLY for IPv6 sockets (nil = OS default)
	BindToDevice   string // SO_BINDTODEVICE interface name (Linux only; "" = none)
	UDPSendBufSize int    // SO_SNDBUF in bytes; >0 to set
	UDPRecvBufSize int    // SO_RCVBUF in bytes; >0 to set
}

func (o UDPSocketOptions) needsControl() bool {
	return o.IPTTL > 0 || o.IPTOS >= 0 || o.IPv6Only != nil || o.BindToDevice != "" ||
		o.UDPSendBufSize > 0 || o.UDPRecvBufSize > 0
}

// ListenUDP creates a UDP socket with the given OS-level options applied before
// bind. With no options set it is equivalent to net.ListenUDP. The host (or the
// public façade) uses this to build the net.PacketConn it hands to Dial/Listen.
func ListenUDP(network string, laddr *net.UDPAddr, opts UDPSocketOptions) (net.PacketConn, error) {
	if !opts.needsControl() {
		return net.ListenUDP(network, laddr)
	}
	lc := net.ListenConfig{Control: opts.control()}
	addr := ""
	if laddr != nil {
		addr = laddr.String()
	}
	return lc.ListenPacket(context.Background(), network, addr)
}

// control returns a net.ListenConfig.Control callback that applies the options
// via setsockopt on the raw fd.
func (o UDPSocketOptions) control() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		isIPv6 := network == "udp6" || network == "tcp6"
		var opErr error
		err := c.Control(func(fd uintptr) {
			fdInt := int(fd)
			if o.UDPSendBufSize > 0 {
				if opErr = syscall.SetsockoptInt(fdInt, syscall.SOL_SOCKET, syscall.SO_SNDBUF, o.UDPSendBufSize); opErr != nil {
					return
				}
			}
			if o.UDPRecvBufSize > 0 {
				if opErr = syscall.SetsockoptInt(fdInt, syscall.SOL_SOCKET, syscall.SO_RCVBUF, o.UDPRecvBufSize); opErr != nil {
					return
				}
			}
			if o.IPTTL > 0 {
				if isIPv6 {
					opErr = syscall.SetsockoptInt(fdInt, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, o.IPTTL)
				} else {
					opErr = syscall.SetsockoptInt(fdInt, syscall.IPPROTO_IP, syscall.IP_TTL, o.IPTTL)
				}
				if opErr != nil {
					return
				}
			}
			if o.IPTOS >= 0 {
				if isIPv6 {
					opErr = syscall.SetsockoptInt(fdInt, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, o.IPTOS)
				} else {
					opErr = syscall.SetsockoptInt(fdInt, syscall.IPPROTO_IP, syscall.IP_TOS, o.IPTOS)
				}
				if opErr != nil {
					return
				}
			}
			if o.IPv6Only != nil && isIPv6 {
				v := 0
				if *o.IPv6Only {
					v = 1
				}
				if opErr = syscall.SetsockoptInt(fdInt, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, v); opErr != nil {
					return
				}
			}
			if o.BindToDevice != "" {
				opErr = setBindToDevice(fdInt, o.BindToDevice)
			}
		})
		if err != nil {
			return err
		}
		return opErr
	}
}
