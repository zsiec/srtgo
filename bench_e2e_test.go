package srt_test

import (
	"sync"
	"testing"
	"time"

	srt "github.com/zsiec/srtgo"
)

// End-to-end benchmarks over a real loopback connection. They exercise the full
// public path — handshake, the session event loop, the channel hand-off, and the
// UDP mux — not just the pure core, so they catch regressions the package-level
// micro-benchmarks cannot.

func benchDialCfg() srt.Config {
	cfg := srt.DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 5 * time.Second
	cfg.MaxBW = 1_000_000_000 / 8 // 1 Gbps (125 MB/s), matching C++ SRT's default
	return cfg
}

// BenchmarkWrite measures sustained send throughput with the receiver draining.
func BenchmarkWrite(b *testing.B) {
	l, err := srt.Listen("127.0.0.1:0", benchDialCfg())
	if err != nil {
		b.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	var server *srt.Conn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var aerr error
		if server, aerr = l.Accept(); aerr != nil {
			b.Errorf("Accept: %v", aerr)
		}
	}()
	client, err := srt.Dial(l.Addr().String(), benchDialCfg())
	if err != nil {
		b.Fatalf("Dial: %v", err)
	}
	wg.Wait()
	defer client.Close()
	defer server.Close()

	go func() {
		buf := make([]byte, 1500)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()

	payload := make([]byte, 1316)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := client.Write(payload); err != nil {
			b.Fatalf("Write: %v", err)
		}
	}
}

// BenchmarkReadWrite measures throughput with an explicit reader on the far end.
func BenchmarkReadWrite(b *testing.B) {
	l, err := srt.Listen("127.0.0.1:0", benchDialCfg())
	if err != nil {
		b.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	var server *srt.Conn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var aerr error
		if server, aerr = l.Accept(); aerr != nil {
			b.Errorf("Accept: %v", aerr)
		}
	}()
	client, err := srt.Dial(l.Addr().String(), benchDialCfg())
	if err != nil {
		b.Fatalf("Dial: %v", err)
	}
	wg.Wait()
	defer client.Close()
	defer server.Close()

	payload := make([]byte, 1316)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 1500)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		client.Write(payload)
	}
	b.StopTimer()
	time.Sleep(100 * time.Millisecond)
	client.Close()
	<-readDone
}

// BenchmarkDialAccept measures connection establishment (handshake) cost.
func BenchmarkDialAccept(b *testing.B) {
	l, err := srt.Listen("127.0.0.1:0", benchDialCfg())
	if err != nil {
		b.Fatalf("Listen: %v", err)
	}
	defer l.Close()
	addr := l.Addr().String()

	b.ResetTimer()
	for b.Loop() {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c, aerr := l.Accept(); aerr == nil {
				c.Close()
			}
		}()
		c, err := srt.Dial(addr, benchDialCfg())
		if err != nil {
			l.Close()
			wg.Wait()
			b.Skipf("Dial: %v (OS UDP buffer pressure at high iteration count)", err)
			return
		}
		c.Close()
		wg.Wait()
	}
}
