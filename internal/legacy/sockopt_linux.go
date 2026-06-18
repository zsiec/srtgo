//go:build linux && !js

package legacy

import "syscall"

func setBindToDevice(fd int, device string) error {
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
}
