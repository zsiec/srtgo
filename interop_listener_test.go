//go:build interop

package srt_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	srt "github.com/zsiec/srtgo"
)

func buildLibsrtCaller(t *testing.T) string {
	t.Helper()
	for _, tool := range []string{"cc", "pkg-config"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("interop listener tests require %s: %v", tool, err)
		}
	}
	flags, err := exec.Command("pkg-config", "--cflags", "--libs", "srt").Output()
	if err != nil {
		t.Fatalf("libsrt development files required: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "libsrt-caller")
	args := append([]string{"testdata/interop_caller.c", "-o", bin}, strings.Fields(string(flags))...)
	if out, err := exec.Command("cc", args...).CombinedOutput(); err != nil {
		t.Fatalf("compile caller: %v\n%s", err, out)
	}
	return bin
}

// TestInteropListener covers the connection role missing from TestInterop:
// a real libsrt caller connects to Go, with both blocking and async connect.
func TestInteropListener(t *testing.T) {
	bin := buildLibsrtCaller(t)
	for _, mode := range []string{"sync", "async"} {
		for _, direction := range []string{"send", "recv"} {
			for _, keylen := range []int{0, 16, 32} {
				t.Run(fmt.Sprintf("%s/%s/key-%d", mode, direction, keylen), func(t *testing.T) {
					cfg := srt.DefaultConfig()
					if keylen != 0 {
						cfg.Passphrase = interopPass
						cfg.KeyLength = keylen
					}
					ln, err := srt.Listen("127.0.0.1:0", cfg)
					if err != nil {
						t.Fatal(err)
					}
					defer ln.Close()
					serverDone := make(chan error, 1)
					go func() {
						c, err := ln.Accept()
						if err != nil {
							serverDone <- err
							return
						}
						defer c.Close()
						_ = c.SetDeadline(time.Now().Add(6 * time.Second))
						for i := 0; i < 20; i++ {
							want := make([]byte, 1316)
							for j := range want {
								want[j] = byte(i + j)
							}
							if direction == "recv" {
								if _, err = c.Write(want); err != nil {
									serverDone <- err
									return
								}
								time.Sleep(5 * time.Millisecond)
							} else {
								got := make([]byte, 1500)
								n, err := c.Read(got)
								if err != nil {
									serverDone <- err
									return
								}
								if !bytes.Equal(got[:n], want) {
									serverDone <- fmt.Errorf("message %d mismatch (len=%d first=%x want=%x dropped=%d)", i, n, got[:min(n, 8)], want[:8], c.Stats(false).RecvDropped)
									return
								}
							}
						}
						if direction == "recv" {
							time.Sleep(300 * time.Millisecond)
						}
						serverDone <- nil
					}()
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					defer cancel()
					port := strconv.Itoa(ln.Addr().(*net.UDPAddr).Port)
					out, err := exec.CommandContext(ctx, bin, port, mode, direction, cfg.Passphrase, strconv.Itoa(keylen)).CombinedOutput()
					if err != nil {
						t.Fatalf("libsrt caller: %v\n%s", err, out)
					}
					select {
					case err := <-serverDone:
						if err != nil {
							t.Fatal(err)
						}
					case <-ctx.Done():
						t.Fatal("server did not finish")
					}
				})
			}
		}
	}
}
