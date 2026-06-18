//go:build !linux && !js

package session

import "errors"

func setBindToDevice(_ int, _ string) error {
	return errors.New("srt: BindToDevice is only supported on Linux")
}
