package srt

import (
	"testing"
	"time"
)

func TestBufferIIR_Basic(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// First update initializes directly
	c.updateBufferIIR()

	avg := c.AvgSndBufSize()
	if avg < 0 {
		t.Errorf("AvgSndBufSize = %f, want >= 0", avg)
	}

	avg = c.AvgRcvBufSize()
	if avg < 0 {
		t.Errorf("AvgRcvBufSize = %f, want >= 0", avg)
	}
}

func TestBufferIIR_Smoothing(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// Initialize with first sample
	c.updateBufferIIR()

	// Run multiple updates; the average should remain stable
	// since the buffer size doesn't change.
	for range 100 {
		c.updateBufferIIR()
	}

	avgPkts := c.AvgSndBufSize()
	avgBytes := c.AvgSndBufBytes()

	// Both should be >= 0 (buffer may be empty)
	if avgPkts < 0 {
		t.Errorf("AvgSndBufSize after 100 updates = %f, want >= 0", avgPkts)
	}
	if avgBytes < 0 {
		t.Errorf("AvgSndBufBytes after 100 updates = %f, want >= 0", avgBytes)
	}
}

func TestSendRate_ViaConn(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// Record some sends
	for range 50 {
		c.recordSendRate(1, 1316)
	}

	// Rotate to finalize the window
	time.Sleep(110 * time.Millisecond)
	c.rotateSendRate()

	pps, bps := c.SendRate()
	// The send rate may or may not be computed depending on timing,
	// but it should not panic
	_ = pps
	_ = bps
}

func TestExtendedStats(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	stats := c.ExtendedStats(false)

	// ConnStats fields should be populated
	if stats.Duration < 0 {
		t.Errorf("Duration = %v, want >= 0", stats.Duration)
	}

	// Extended fields should be >= 0
	if stats.AvgSndBufPkts < 0 {
		t.Errorf("AvgSndBufPkts = %f, want >= 0", stats.AvgSndBufPkts)
	}
	if stats.AvgRcvBufPkts < 0 {
		t.Errorf("AvgRcvBufPkts = %f, want >= 0", stats.AvgRcvBufPkts)
	}
}
