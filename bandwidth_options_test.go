package srt_test

import (
	srt "github.com/zsiec/srtgo"
	"sync"
	"testing"
)

func TestPublicBandwidthOptions(t *testing.T) {
	cfg := srt.DefaultConfig()
	cfg.MaxBW = 0
	cfg.InputBW = 100000
	cfg.OverheadBW = 50
	a, b := testConnectionPair(t, cfg, cfg)
	for _, c := range []*srt.Conn{a, b} {
		if got := c.Stats(false).MbpsMaxBW; got != 1.2 {
			t.Fatalf("initial MbpsMaxBW=%v", got)
		}
		for _, tc := range []struct {
			opt   srt.SockOpt
			value any
			want  float64
		}{
			{srt.SockOptInputBW, int64(200000), 2.4},
			{srt.SockOptOverheadBW, 100, 3.2},
			{srt.SockOptMaxBW, int64(900000), 7.2},
			{srt.SockOptInputBW, int64(300000), 7.2},
			{srt.SockOptMaxBW, int64(0), 4.8},
			{srt.SockOptMinInputBW, int64(1000000), 4.8},
			{srt.SockOptInputBW, int64(0), 16},
		} {
			if err := c.SetOption(tc.opt, tc.value); err != nil {
				t.Fatal(err)
			}
			if got := c.Stats(false).MbpsMaxBW; got != tc.want {
				t.Fatalf("option %v bandwidth=%v want %v", tc.opt, got, tc.want)
			}
		}
	}
	// Options and stats can be used while an application adjusts the pacer.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			a.SetMaxBW(int64(100000 + i))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			a.Stats(false)
			a.GetOption(srt.SockOptMaxBW)
		}
	}()
	wg.Wait()
}
