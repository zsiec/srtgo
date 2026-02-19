package srt

import (
	"testing"
	"time"
)

func TestSndRateEstimator_Basic(t *testing.T) {
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	// Send 100 packets of 1000 bytes in the first window
	for i := 0; i < 100; i++ {
		e.onPacketSent(now.Add(time.Duration(i)*time.Millisecond), 1, 1000)
	}

	// Advance to next window
	e.rotate(now.Add(150 * time.Millisecond))

	pps, bps := e.getRate()
	if pps == 0 || bps == 0 {
		t.Errorf("expected non-zero rate, got pps=%d bps=%d", pps, bps)
	}

	// 100 packets in 100ms = ~1000 pps
	if pps < 500 || pps > 2000 {
		t.Errorf("pps=%d, expected ~1000", pps)
	}

	// 100*1000 bytes in 100ms = ~1,000,000 bps
	if bps < 500000 || bps > 2000000 {
		t.Errorf("bps=%d, expected ~1000000", bps)
	}
}

func TestSndRateEstimator_MultipleWindows(t *testing.T) {
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	// Send packets across 5 windows
	for w := 0; w < 5; w++ {
		windowStart := now.Add(time.Duration(w) * sndRateWindow)
		for i := 0; i < 10; i++ {
			e.onPacketSent(windowStart.Add(time.Duration(i)*5*time.Millisecond), 1, 500)
		}
	}

	// Advance past 5th window
	e.rotate(now.Add(6 * sndRateWindow))

	pps, bps := e.getRate()
	if pps == 0 || bps == 0 {
		t.Errorf("expected non-zero rate after 5 windows, got pps=%d bps=%d", pps, bps)
	}
}

func TestSndRateEstimator_EmptyRate(t *testing.T) {
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	pps, bps := e.getRate()
	if pps != 0 || bps != 0 {
		t.Errorf("expected zero rate for empty estimator, got pps=%d bps=%d", pps, bps)
	}
}

func TestSndRateEstimator_WrapAround(t *testing.T) {
	var e sndRateEstimator
	now := time.Now()
	e.init(now)

	// Fill all 10 slots and then some to test wrap-around
	for w := 0; w < 15; w++ {
		windowStart := now.Add(time.Duration(w) * sndRateWindow)
		e.onPacketSent(windowStart, 10, 5000)
		e.rotate(windowStart.Add(sndRateWindow))
	}

	pps, bps := e.getRate()
	if pps == 0 || bps == 0 {
		t.Errorf("expected non-zero rate after wrap-around, got pps=%d bps=%d", pps, bps)
	}
}
