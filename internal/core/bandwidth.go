package core

import (
	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/congestion"
)

// Keep the configured maximum separate from the controller's effective rate:
// a positive auto-derived rate must never turn into an explicit maximum.
func (c *Conn) applyBandwidth() {
	if c.sendCC == nil {
		return
	}
	if _, live := c.sendCC.(*congestion.LiveCC); !live {
		c.sendCC.SetMaxBandwidth(c.configuredMaxBW)
		return
	}
	input := c.inputBW
	if input == 0 {
		input = max(c.sampledInputBW, c.minInputBW)
	}
	if c.configuredMaxBW == 0 && input == 0 {
		c.sendCC.SetMaxBandwidth(congestion.DefaultMaxBW)
	} else {
		c.sendCC.UpdateBandwidth(c.configuredMaxBW, input)
	}
}

// SetMaxBW changes the configured maximum; zero selects input-rate pacing.
func (c *Conn) SetMaxBW(bw int64)      { c.configuredMaxBW = max(int64(0), bw); c.applyBandwidth() }
func (c *Conn) SetInputBW(bw int64)    { c.inputBW = max(int64(0), bw); c.applyBandwidth() }
func (c *Conn) SetMinInputBW(bw int64) { c.minInputBW = max(int64(0), bw); c.applyBandwidth() }
func (c *Conn) SetOverhead(pct int) {
	if c.sendCC != nil {
		c.sendCC.SetOverhead(pct)
		c.applyBandwidth()
	}
}

// Sample bytes accepted from the application over a one-second window. The
// injected core clock makes this independent of wall-clock scheduling. Keep
// the last nonzero estimate while idle so outstanding retransmits stay paced.
func (c *Conn) sampleInputBandwidth(now clock.Timestamp) {
	elapsed := now.Sub(c.inputSampleStart)
	if elapsed < clock.Second {
		return
	}
	if c.inputSampleBytes > 0 {
		c.sampledInputBW = int64(float64(c.inputSampleBytes) * float64(clock.Second) / float64(elapsed))
	}
	c.inputSampleBytes = 0
	c.inputSampleStart = now
	if c.configuredMaxBW == 0 && c.inputBW == 0 {
		c.applyBandwidth()
	}
}
