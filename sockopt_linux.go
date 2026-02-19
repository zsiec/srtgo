//go:build linux

package srt

import "syscall"

func setBindToDevice(fd int, device string) error {
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
}
