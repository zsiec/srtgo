//go:build js

package session

import (
	"errors"
	"net"
)

// ListenUDP is unavailable in js/wasm; build the net.PacketConn yourself and
// pass it to Dial/Listen.
func ListenUDP(_ string, _ *net.UDPAddr, _ UDPSocketOptions) (net.PacketConn, error) {
	return nil, errors.New("srt: UDP sockets are not available in js/wasm")
}

func setBindToDevice(_ int, _ string) error {
	return errors.New("srt: BindToDevice is not supported in js/wasm")
}
