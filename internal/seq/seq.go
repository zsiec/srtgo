// Package seq implements 31-bit wrapping sequence number arithmetic for SRT.
//
// SRT sequence numbers are unsigned 31-bit integers that wrap from Max (0x7FFFFFFF)
// back to 0. Comparison uses a threshold of Max/2 to determine ordering across
// the wrap boundary: if two numbers are within Threshold of each other, the
// numerically smaller one is considered "less than" the other; beyond that
// threshold, the relationship inverts to account for wrapping.
package seq

// Number is a 31-bit wrapping sequence number as defined by the SRT protocol.
type Number uint32

const (
	Max       Number = 0x7FFFFFFF // 31-bit maximum (2^31 - 1)
	Threshold Number = 0x3FFFFFFF // Max / 2, used for wrap-aware comparison
)

// Value returns the raw uint32 value of the sequence number.
func (a Number) Value() uint32 {
	return uint32(a)
}

// Inc returns the next sequence number, wrapping from Max to 0.
func (a Number) Inc() Number {
	if a >= Max {
		return 0
	}
	return a + 1
}

// Dec returns the previous sequence number, wrapping from 0 to Max.
func (a Number) Dec() Number {
	if a == 0 {
		return Max
	}
	return a - 1
}

// Add returns a + n with wrapping.
func (a Number) Add(n uint32) Number {
	sum := uint32(a) + n
	if sum > uint32(Max) {
		sum -= uint32(Max) + 1
	}
	return Number(sum)
}

// Sub returns a - n with wrapping.
func (a Number) Sub(n uint32) Number {
	if uint32(a) >= n {
		return Number(uint32(a) - n)
	}
	return Number(uint32(Max) + 1 - (n - uint32(a)))
}

// Distance returns the signed distance from a to b: positive if b is ahead of a,
// negative if b is behind a. The magnitude is always <= Threshold.
func (a Number) Distance(b Number) int32 {
	if a == b {
		return 0
	}

	var d uint32
	if b > a {
		d = uint32(b) - uint32(a)
	} else {
		d = uint32(a) - uint32(b)
	}

	if d <= uint32(Threshold) {
		// Within threshold: normal ordering
		if b > a {
			return int32(d)
		}
		return -int32(d)
	}

	// Beyond threshold: wrapped ordering
	wrapped := uint32(Max) - d + 1
	if b > a {
		// b is numerically larger but logically behind (wrapped)
		return -int32(wrapped)
	}
	// a is numerically larger but b is logically ahead (wrapped)
	return int32(wrapped)
}

// LessThan returns true if a is logically before b in wrap-aware ordering.
func (a Number) LessThan(b Number) bool {
	if a == b {
		return false
	}

	var d uint32
	aLessNumerically := false

	if a > b {
		d = uint32(a) - uint32(b)
	} else {
		d = uint32(b) - uint32(a)
		aLessNumerically = true
	}

	if d <= uint32(Threshold) {
		return aLessNumerically
	}
	return !aLessNumerically
}

// LessThanOrEqual returns true if a <= b in wrap-aware ordering.
func (a Number) LessThanOrEqual(b Number) bool {
	return a == b || a.LessThan(b)
}

// GreaterThan returns true if a is logically after b in wrap-aware ordering.
func (a Number) GreaterThan(b Number) bool {
	if a == b {
		return false
	}
	return !a.LessThan(b)
}

// GreaterThanOrEqual returns true if a >= b in wrap-aware ordering.
func (a Number) GreaterThanOrEqual(b Number) bool {
	return a == b || a.GreaterThan(b)
}
