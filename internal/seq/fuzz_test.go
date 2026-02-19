package seq

import "testing"

// FuzzDistance tests that Distance never panics and maintains consistency
// with LessThan.
func FuzzDistance(f *testing.F) {
	f.Add(uint32(0), uint32(0))
	f.Add(uint32(0), uint32(Max))
	f.Add(uint32(Max), uint32(0))
	f.Add(uint32(Max/2), uint32(Max/2+1))
	f.Add(uint32(1000), uint32(2000))

	f.Fuzz(func(t *testing.T, a, b uint32) {
		na := Number(a & 0x7FFFFFFF) // ensure 31-bit
		nb := Number(b & 0x7FFFFFFF)

		d := na.Distance(nb)

		// Consistency: if a < b, distance should be positive
		if na.LessThan(nb) && d <= 0 && na != nb {
			t.Errorf("LessThan(%d, %d) but Distance=%d", na, nb, d)
		}

		// Distance from self should be 0
		if na.Distance(na) != 0 {
			t.Errorf("Distance(%d, %d) = %d, want 0", na, na, na.Distance(na))
		}
	})
}

// FuzzAddSub tests Add/Sub roundtrip.
func FuzzAddSub(f *testing.F) {
	f.Add(uint32(0), uint32(100))
	f.Add(uint32(Max-10), uint32(20))
	f.Add(uint32(1000), uint32(0))

	f.Fuzz(func(t *testing.T, base, offset uint32) {
		base &= 0x7FFFFFFF
		offset &= 0x7FFFFFFF

		n := Number(base)
		result := n.Add(offset).Sub(offset)

		if result != n {
			t.Errorf("(%d).Add(%d).Sub(%d) = %d, want %d", n, offset, offset, result, n)
		}
	})
}
