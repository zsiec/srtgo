package clock

import "time"

// Microseconds represents a duration in microseconds.
type Microseconds int64

// Common duration constants.
const (
	Millisecond Microseconds = 1000
	Second      Microseconds = 1000 * Millisecond
	Minute      Microseconds = 60 * Second
)

// Duration converts to a standard time.Duration.
func (d Microseconds) Duration() time.Duration {
	return time.Duration(d) * time.Microsecond
}

// FromDuration converts a time.Duration to Microseconds.
func FromDuration(d time.Duration) Microseconds {
	return Microseconds(d.Microseconds())
}

// Abs returns the absolute value of d.
func (d Microseconds) Abs() Microseconds {
	if d < 0 {
		return -d
	}
	return d
}

// Timestamp represents an absolute point in time in microseconds
// since an arbitrary epoch (typically connection start).
type Timestamp int64

// Add returns t + d.
func (t Timestamp) Add(d Microseconds) Timestamp {
	return Timestamp(int64(t) + int64(d))
}

// Sub returns the duration between t and other (t - other).
func (t Timestamp) Sub(other Timestamp) Microseconds {
	return Microseconds(int64(t) - int64(other))
}

// Before reports whether t is before other.
func (t Timestamp) Before(other Timestamp) bool {
	return t < other
}

// After reports whether t is after other.
func (t Timestamp) After(other Timestamp) bool {
	return t > other
}

// IsZero reports whether t is the zero timestamp.
func (t Timestamp) IsZero() bool {
	return t == 0
}

// SRTTimestamp returns the lower 32 bits of the timestamp for the SRT
// wire format. SRT timestamps are 32-bit unsigned microsecond values
// that wrap every ~71.6 minutes (2^32 microseconds ≈ 4295 seconds).
func (t Timestamp) SRTTimestamp() uint32 {
	return uint32(t)
}

// srtTimestampWrapPeriod is 2^32 microseconds.
const srtTimestampWrapPeriod Microseconds = 1 << 32

// SRTTimestampWrapPeriod returns the wrap period for 32-bit SRT timestamps.
func SRTTimestampWrapPeriod() Microseconds {
	return srtTimestampWrapPeriod
}

// FromSRTTimestamp reconstructs a full Timestamp from a 32-bit SRT
// timestamp and a reference timestamp. It picks the interpretation
// closest to the reference (handling wrap-around).
func FromSRTTimestamp(srtTS uint32, reference Timestamp) Timestamp {
	refLow := uint32(reference)

	// Calculate the base (high bits of the reference)
	base := int64(reference) - int64(refLow)

	// The candidate in the same epoch as reference
	candidate := Timestamp(base + int64(srtTS))

	// Check if a wrapped interpretation is closer
	diff := candidate.Sub(reference)
	if diff > srtTimestampWrapPeriod/2 {
		// srtTS is probably from the previous epoch
		return Timestamp(base - int64(srtTimestampWrapPeriod) + int64(srtTS))
	}
	if diff < -srtTimestampWrapPeriod/2 {
		// srtTS is probably from the next epoch
		return Timestamp(base + int64(srtTimestampWrapPeriod) + int64(srtTS))
	}

	return candidate
}
