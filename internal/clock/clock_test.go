package clock

import (
	"testing"
	"time"
)

func TestMicroseconds(t *testing.T) {
	t.Run("Duration", func(t *testing.T) {
		d := Microseconds(1500000)
		if got := d.Duration(); got != 1500*time.Millisecond {
			t.Errorf("Duration() = %v, want %v", got, 1500*time.Millisecond)
		}
	})

	t.Run("FromDuration", func(t *testing.T) {
		d := FromDuration(2 * time.Second)
		if d != 2*Second {
			t.Errorf("FromDuration(2s) = %d, want %d", d, 2*Second)
		}
	})

	t.Run("Abs", func(t *testing.T) {
		if Microseconds(-100).Abs() != 100 {
			t.Error("Abs(-100) should be 100")
		}
		if Microseconds(100).Abs() != 100 {
			t.Error("Abs(100) should be 100")
		}
		if Microseconds(0).Abs() != 0 {
			t.Error("Abs(0) should be 0")
		}
	})

	t.Run("Constants", func(t *testing.T) {
		if Millisecond != 1000 {
			t.Errorf("Millisecond = %d, want 1000", Millisecond)
		}
		if Second != 1_000_000 {
			t.Errorf("Second = %d, want 1000000", Second)
		}
		if Minute != 60_000_000 {
			t.Errorf("Minute = %d, want 60000000", Minute)
		}
	})
}

func TestTimestamp(t *testing.T) {
	t.Run("AddSub", func(t *testing.T) {
		ts := Timestamp(1000000)
		ts2 := ts.Add(500000)
		if ts2 != 1500000 {
			t.Errorf("Add: got %d, want 1500000", ts2)
		}
		if ts2.Sub(ts) != 500000 {
			t.Errorf("Sub: got %d, want 500000", ts2.Sub(ts))
		}
	})

	t.Run("Comparison", func(t *testing.T) {
		a := Timestamp(100)
		b := Timestamp(200)
		if !a.Before(b) {
			t.Error("100 should be before 200")
		}
		if !b.After(a) {
			t.Error("200 should be after 100")
		}
		if a.After(b) {
			t.Error("100 should not be after 200")
		}
	})

	t.Run("IsZero", func(t *testing.T) {
		if !Timestamp(0).IsZero() {
			t.Error("Timestamp(0).IsZero() should be true")
		}
		if Timestamp(1).IsZero() {
			t.Error("Timestamp(1).IsZero() should be false")
		}
	})
}

func TestSRTTimestamp(t *testing.T) {
	t.Run("Lower32bits", func(t *testing.T) {
		ts := Timestamp(0x1_FFFFFFFF) // 33 bits set
		got := ts.SRTTimestamp()
		if got != 0xFFFFFFFF {
			t.Errorf("SRTTimestamp() = 0x%X, want 0xFFFFFFFF", got)
		}
	})

	t.Run("WrapPeriod", func(t *testing.T) {
		period := SRTTimestampWrapPeriod()
		// 2^32 microseconds ≈ 4294.967296 seconds ≈ 71.58 minutes
		if period != 1<<32 {
			t.Errorf("WrapPeriod = %d, want %d", period, Microseconds(1<<32))
		}
	})
}

func TestFromSRTTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		srtTS     uint32
		reference Timestamp
		expected  Timestamp
	}{
		{
			name:      "same epoch, no wrap",
			srtTS:     1000,
			reference: Timestamp(500),
			expected:  Timestamp(1000),
		},
		{
			name:      "same epoch, before reference",
			srtTS:     500,
			reference: Timestamp(1000),
			expected:  Timestamp(500),
		},
		{
			name:      "second epoch, no wrap",
			srtTS:     1000,
			reference: Timestamp(int64(srtTimestampWrapPeriod) + 500),
			expected:  Timestamp(int64(srtTimestampWrapPeriod) + 1000),
		},
		{
			name:      "wrap forward: srtTS near 0, reference near max",
			srtTS:     100,
			reference: Timestamp(int64(srtTimestampWrapPeriod) - 100),
			expected:  Timestamp(int64(srtTimestampWrapPeriod) + 100),
		},
		{
			name:      "wrap backward: srtTS near max, reference near 0 of next epoch",
			srtTS:     0xFFFFFF00,
			reference: Timestamp(int64(srtTimestampWrapPeriod) + 100),
			expected:  Timestamp(0xFFFFFF00),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromSRTTimestamp(tt.srtTS, tt.reference)
			if got != tt.expected {
				t.Errorf("FromSRTTimestamp(0x%X, %d) = %d, want %d",
					tt.srtTS, tt.reference, got, tt.expected)
			}
		})
	}
}

func TestMockClock(t *testing.T) {
	c := NewMockClock()
	if c.Now() != 0 {
		t.Errorf("initial time should be 0, got %d", c.Now())
	}

	c.Advance(1000)
	if c.Now() != 1000 {
		t.Errorf("after Advance(1000), got %d", c.Now())
	}

	c.Set(Timestamp(5000))
	if c.Now() != 5000 {
		t.Errorf("after Set(5000), got %d", c.Now())
	}

	c.Advance(Second)
	if c.Now() != Timestamp(5000+Second) {
		t.Errorf("after Advance(Second), got %d, want %d", c.Now(), Timestamp(5000+Second))
	}
}

func TestRealClock(t *testing.T) {
	c := NewRealClock()
	t1 := c.Now()
	time.Sleep(1 * time.Millisecond)
	t2 := c.Now()

	if !t2.After(Timestamp(t1)) {
		t.Error("RealClock should advance with time")
	}

	diff := t2.Sub(t1)
	if diff < 1000 { // at least 1ms = 1000μs
		t.Errorf("expected at least 1000μs difference, got %d", diff)
	}
}

// Benchmarks

func BenchmarkTimestampAdd(b *testing.B) {
	ts := Timestamp(1000000)
	d := Microseconds(500)
	for b.Loop() {
		ts = ts.Add(d)
	}
}

func BenchmarkSRTTimestamp(b *testing.B) {
	ts := Timestamp(5_000_000_000)
	for b.Loop() {
		_ = ts.SRTTimestamp()
	}
}

func BenchmarkFromSRTTimestamp(b *testing.B) {
	ref := Timestamp(5_000_000_000)
	srtTS := uint32(1000)
	for b.Loop() {
		FromSRTTimestamp(srtTS, ref)
	}
}
