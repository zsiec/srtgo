//go:build !js

package session_test

import (
	"net"
	"syscall"
	"testing"

	"github.com/zsiec/srtgo/internal/session"
)

// TestListenUDPSocketOptions proves ListenUDP applies OS-level socket options:
// the fast path (no options) yields a working socket, and a configured IP TTL is
// actually set on the underlying fd (read back via getsockopt).
func TestListenUDPSocketOptions(t *testing.T) {
	// Fast path: no options -> a plain, working UDP socket.
	plain, err := session.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, session.UDPSocketOptions{IPTOS: -1})
	if err != nil {
		t.Fatalf("ListenUDP (no options): %v", err)
	}
	plain.Close()

	// With IPTTL set, the option must be present on the socket.
	const ttl = 7
	c, err := session.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		session.UDPSocketOptions{IPTTL: ttl, IPTOS: -1, UDPRecvBufSize: 1 << 20})
	if err != nil {
		t.Fatalf("ListenUDP (with options): %v", err)
	}
	defer c.Close()

	uc, ok := c.(*net.UDPConn)
	if !ok {
		t.Fatalf("ListenUDP returned %T, want *net.UDPConn", c)
	}
	sc, err := uc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var gotTTL, rcvBuf int
	if err := sc.Control(func(fd uintptr) {
		gotTTL, _ = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
		rcvBuf, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	}); err != nil {
		t.Fatal(err)
	}
	if gotTTL != ttl {
		t.Fatalf("IP_TTL = %d, want %d", gotTTL, ttl)
	}
	// SO_RCVBUF is often rounded/doubled by the kernel; just confirm it grew well
	// past a default by requesting 1 MiB.
	if rcvBuf < 1<<19 {
		t.Fatalf("SO_RCVBUF = %d, want >= %d (requested 1 MiB)", rcvBuf, 1<<19)
	}
}
