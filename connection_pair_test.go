package srt_test

import (
	"bytes"
	"strconv"
	"testing"
	"time"

	srt "github.com/zsiec/srtgo"
)

func testConnectionPair(t *testing.T, listenerConfig, callerConfig srt.Config) (caller, listener *srt.Conn) {
	t.Helper()
	ln, err := srt.Listen("127.0.0.1:0", listenerConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	caller, err = srt.Dial(ln.Addr().String(), callerConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { caller.Close() })
	type result struct {
		conn *srt.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() { c, e := ln.Accept(); accepted <- result{c, e} }()
	select {
	case a := <-accepted:
		if a.err != nil {
			t.Fatal(a.err)
		}
		listener = a.conn
	case <-time.After(3 * time.Second):
		t.Fatal("accept timed out")
	}
	t.Cleanup(func() { listener.Close() })
	return
}

func TestNegotiatedPayloadSizes(t *testing.T) {
	for _, mss := range []int{1500, 1200} {
		t.Run(strconv.Itoa(mss), func(t *testing.T) {
			lc, cc := srt.DefaultConfig(), srt.DefaultConfig()
			lc.MSS = mss
			a, b := testConnectionPair(t, lc, cc)
			want := min(1316, mss-44)
			for _, pair := range [][2]*srt.Conn{{a, b}, {b, a}} {
				if got := pair[0].Stats(false).NegotiatedMSS; got != mss {
					t.Fatalf("MSS=%d want %d", got, mss)
				}
				if got, err := pair[0].GetOption(srt.SockOptPayloadSize); err != nil || got != want {
					t.Fatalf("payload option=%v, %v want %d", got, err, want)
				}
				if n, err := pair[0].Write(make([]byte, want+1)); err == nil || n != 0 {
					t.Fatalf("oversize write=(%d,%v)", n, err)
				}
				if n, err := pair[0].WriteMessage(make([]byte, want+1)); err == nil || n != 0 {
					t.Fatalf("oversize message=(%d,%v)", n, err)
				}
				payload := bytes.Repeat([]byte{42}, want)
				if _, err := pair[0].Write(payload); err != nil {
					t.Fatal(err)
				}
				pair[1].SetReadDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 2000)
				got, err := pair[1].Read(buf)
				if err != nil || got != want || !bytes.Equal(buf[:got], payload) {
					t.Fatalf("read=(%d,%v), want %d", got, err, want)
				}

			}
		})
	}
}
