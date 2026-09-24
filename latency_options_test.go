package srt_test

import (
	srt "github.com/zsiec/srtgo"
	"testing"
	"time"
)

func TestNegotiatedLatencyOptions(t *testing.T) {
	lc, dc := srt.DefaultConfig(), srt.DefaultConfig()
	lc.RecvLatency, lc.PeerLatency = 200*time.Millisecond, 150*time.Millisecond
	dc.RecvLatency, dc.PeerLatency = 300*time.Millisecond, 100*time.Millisecond
	a, b, ln := dialAccept(t, lc, dc)
	defer ln.Close()
	defer a.Close()
	defer b.Close()
	for _, tc := range []struct {
		c          *srt.Conn
		recv, peer time.Duration
	}{{a, 300 * time.Millisecond, 200 * time.Millisecond}, {b, 200 * time.Millisecond, 300 * time.Millisecond}} {
		for opt, want := range map[srt.SockOpt]time.Duration{srt.SockOptRcvLatency: tc.recv, srt.SockOptSndLatency: tc.peer} {
			got, err := tc.c.GetOption(opt)
			if err != nil || got != want {
				t.Fatalf("option %v=%v,%v want %v", opt, got, err, want)
			}
		}
	}
}
