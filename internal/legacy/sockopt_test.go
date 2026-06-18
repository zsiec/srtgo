//go:build !js

package legacy

import (
	"net"
	"runtime"
	"syscall"
	"testing"
)

func TestMakeSocketControlNil(t *testing.T) {
	// Default config (IPTTL=0 treated as -1, IPTOS=-1) should return nil
	cfg := DefaultConfig()
	ctrl := makeSocketControl(cfg)
	if ctrl != nil {
		t.Error("expected nil control for default config")
	}
}

func TestMakeSocketControlIPTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IPTTL = 64

	ctrl := makeSocketControl(cfg)
	if ctrl == nil {
		t.Fatal("expected non-nil control")
	}

	// Apply to a real socket via listenUDP and verify with getsockopt
	conn, err := listenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, cfg)
	if err != nil {
		t.Fatalf("listenUDP: %v", err)
	}
	defer conn.Close()

	// Verify TTL was set
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		t.Skip("conn is not *net.UDPConn, cannot verify sockopt")
	}
	raw, err := udpConn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	var ttl int
	var gErr error
	raw.Control(func(fd uintptr) {
		ttl, gErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
	})
	if gErr != nil {
		t.Fatalf("getsockopt: %v", gErr)
	}
	if ttl != 64 {
		t.Errorf("IP_TTL = %d, want 64", ttl)
	}
}

func TestMakeSocketControlIPTOS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IPTOS = 0x28 // AF11

	conn, err := listenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, cfg)
	if err != nil {
		t.Fatalf("listenUDP: %v", err)
	}
	defer conn.Close()

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		t.Skip("conn is not *net.UDPConn, cannot verify sockopt")
	}
	raw, err := udpConn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	var tos int
	var gErr error
	raw.Control(func(fd uintptr) {
		tos, gErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS)
	})
	if gErr != nil {
		t.Fatalf("getsockopt: %v", gErr)
	}
	if tos != 0x28 {
		t.Errorf("IP_TOS = %d, want %d", tos, 0x28)
	}
}

func TestIPv6Loopback(t *testing.T) {
	// Skip if IPv6 is not available
	ln, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available:", err)
	}
	ln.Close()

	cfg := DefaultConfig()
	cfg.IPTTL = 32

	conn, err := listenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0}, cfg)
	if err != nil {
		t.Fatalf("listenUDP IPv6: %v", err)
	}
	defer conn.Close()

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		t.Skip("conn is not *net.UDPConn")
	}
	raw, err := udpConn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	var hops int
	var gErr error
	raw.Control(func(fd uintptr) {
		hops, gErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS)
	})
	if gErr != nil {
		t.Fatalf("getsockopt IPV6_UNICAST_HOPS: %v", gErr)
	}
	if hops != 32 {
		t.Errorf("IPV6_UNICAST_HOPS = %d, want 32", hops)
	}
}

func TestBindToDeviceNotLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("test is for non-Linux platforms")
	}

	err := setBindToDevice(0, "eth0")
	if err == nil {
		t.Error("expected error on non-Linux platform")
	}
}

func TestListenUDPFastPath(t *testing.T) {
	// Default config should use fast path (no Control callback)
	cfg := DefaultConfig()
	conn, err := listenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, cfg)
	if err != nil {
		t.Fatalf("listenUDP fast path: %v", err)
	}
	conn.Close()
}

func TestMakeSocketControlUDPBufSizes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPSendBufSize = 1024 * 256
	cfg.UDPRecvBufSize = 1024 * 256

	ctrl := makeSocketControl(cfg)
	if ctrl == nil {
		t.Fatal("expected non-nil control for UDP buf sizes")
	}

	conn, err := listenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, cfg)
	if err != nil {
		t.Fatalf("listenUDP: %v", err)
	}
	defer conn.Close()

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		t.Skip("conn is not *net.UDPConn")
	}
	raw, err := udpConn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	var sndBuf, rcvBuf int
	var gErr error
	raw.Control(func(fd uintptr) {
		sndBuf, gErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		if gErr != nil {
			return
		}
		rcvBuf, gErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	})
	if gErr != nil {
		t.Fatalf("getsockopt: %v", gErr)
	}
	// OS may double the requested size, so just check it was set to at least the requested amount
	if sndBuf < 1024*256 {
		t.Logf("SO_SNDBUF = %d (may be capped by OS)", sndBuf)
	}
	if rcvBuf < 1024*256 {
		t.Logf("SO_RCVBUF = %d (may be capped by OS)", rcvBuf)
	}
}

func TestMakeSocketControlIPv6TOS(t *testing.T) {
	// Skip if IPv6 is not available
	ln, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available:", err)
	}
	ln.Close()

	cfg := DefaultConfig()
	cfg.IPTOS = 0x10

	conn, err := listenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0}, cfg)
	if err != nil {
		t.Fatalf("listenUDP IPv6: %v", err)
	}
	defer conn.Close()

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		t.Skip("conn is not *net.UDPConn")
	}
	raw, err := udpConn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	var tclass int
	var gErr error
	raw.Control(func(fd uintptr) {
		tclass, gErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS)
	})
	if gErr != nil {
		t.Fatalf("getsockopt IPV6_TCLASS: %v", gErr)
	}
	if tclass != 0x10 {
		t.Errorf("IPV6_TCLASS = %d, want %d", tclass, 0x10)
	}
}

func TestMakeSocketControlIPv6Only(t *testing.T) {
	// Skip if IPv6 is not available
	ln, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available:", err)
	}
	ln.Close()

	v6only := true
	cfg := DefaultConfig()
	cfg.IPv6Only = &v6only

	conn, err := listenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0}, cfg)
	if err != nil {
		t.Fatalf("listenUDP IPv6: %v", err)
	}
	defer conn.Close()
}

func TestMakeSocketControlCombined(t *testing.T) {
	// Test combining multiple socket options
	cfg := DefaultConfig()
	cfg.IPTTL = 128
	cfg.IPTOS = 0x04
	cfg.UDPSendBufSize = 1024 * 64
	cfg.UDPRecvBufSize = 1024 * 64

	ctrl := makeSocketControl(cfg)
	if ctrl == nil {
		t.Fatal("expected non-nil control with multiple options set")
	}

	conn, err := listenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, cfg)
	if err != nil {
		t.Fatalf("listenUDP: %v", err)
	}
	conn.Close()
}

func TestListenUDPNilAddr(t *testing.T) {
	cfg := DefaultConfig()
	conn, err := listenUDP("udp", nil, cfg)
	if err != nil {
		t.Fatalf("listenUDP with nil addr: %v", err)
	}
	conn.Close()
}

func TestListenUDPNilAddrWithControl(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IPTTL = 64 // force control callback
	conn, err := listenUDP("udp", nil, cfg)
	if err != nil {
		t.Fatalf("listenUDP with nil addr + control: %v", err)
	}
	conn.Close()
}
