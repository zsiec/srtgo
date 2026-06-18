//go:build linux && !js

package session

import "syscall"

func setBindToDevice(fd int, device string) error {
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
}
