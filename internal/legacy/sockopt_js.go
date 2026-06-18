//go:build js

package legacy

import (
	"errors"
	"net"
)

// listenUDP is not supported in js/wasm — use DialPacketConn/ListenPacketConn
// with a custom PacketConn instead.
func listenUDP(_ string, _ *net.UDPAddr, _ Config) (net.PacketConn, error) {
	return nil, errors.New("srt: UDP sockets are not available in js/wasm; use DialPacketConn or ListenPacketConn with a custom net.PacketConn")
}

func setBindToDevice(_ int, _ string) error {
	return errors.New("srt: BindToDevice is not supported in js/wasm")
}
