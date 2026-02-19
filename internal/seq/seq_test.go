package seq

import (
	"fmt"
	"testing"
)

func TestInc(t *testing.T) {
	tests := []struct {
		input    Number
		expected Number
	}{
		{0, 1},
		{1, 2},
		{100, 101},
		{Max - 1, Max},
		{Max, 0}, // wrap
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.input), func(t *testing.T) {
			got := tt.input.Inc()
			if got != tt.expected {
				t.Errorf("(%d).Inc() = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDec(t *testing.T) {
	tests := []struct {
		input    Number
		expected Number
	}{
		{1, 0},
		{2, 1},
		{100, 99},
		{Max, Max - 1},
		{0, Max}, // wrap
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.input), func(t *testing.T) {
			got := tt.input.Dec()
			if got != tt.expected {
				t.Errorf("(%d).Dec() = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestAdd(t *testing.T) {
	tests := []struct {
		a        Number
		n        uint32
		expected Number
	}{
		{0, 0, 0},
		{0, 1, 1},
		{0, 100, 100},
		{Max - 1, 1, Max},
		{Max, 1, 0},      // wrap
		{Max - 5, 10, 4}, // wrap across boundary
		{0, uint32(Max), Max},
		{1, uint32(Max), 0}, // 1 + Max wraps to 0
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d+%d", tt.a, tt.n), func(t *testing.T) {
			got := tt.a.Add(tt.n)
			if got != tt.expected {
				t.Errorf("(%d).Add(%d) = %d, want %d", tt.a, tt.n, got, tt.expected)
			}
		})
	}
}

func TestSub(t *testing.T) {
	tests := []struct {
		a        Number
		n        uint32
		expected Number
	}{
		{0, 0, 0},
		{1, 1, 0},
		{100, 50, 50},
		{0, 1, Max},      // wrap
		{5, 10, Max - 4}, // wrap across boundary
		{Max, uint32(Max), 0},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d-%d", tt.a, tt.n), func(t *testing.T) {
			got := tt.a.Sub(tt.n)
			if got != tt.expected {
				t.Errorf("(%d).Sub(%d) = %d, want %d", tt.a, tt.n, got, tt.expected)
			}
		})
	}
}

func TestDistance(t *testing.T) {
	tests := []struct {
		a        Number
		b        Number
		expected int32
	}{
		// Same value
		{0, 0, 0},
		{100, 100, 0},
		{Max, Max, 0},

		// Normal ordering (no wrap)
		{0, 1, 1},
		{0, 100, 100},
		{100, 200, 100},
		{1, 0, -1},
		{200, 100, -100},

		// Near threshold
		{0, Number(Threshold), int32(Threshold)},
		{Number(Threshold), 0, -int32(Threshold)},

		// Wrap-around: b just past the wrap from a's perspective
		{Max - 5, 5, 11},  // distance across the wrap boundary
		{5, Max - 5, -11}, // reverse

		// Large wrap-around
		{Max, 0, 1},
		{0, Max, -1},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("dist(%d,%d)", tt.a, tt.b), func(t *testing.T) {
			got := tt.a.Distance(tt.b)
			if got != tt.expected {
				t.Errorf("(%d).Distance(%d) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestLessThan(t *testing.T) {
	tests := []struct {
		a        Number
		b        Number
		expected bool
	}{
		// Same value
		{0, 0, false},
		{100, 100, false},

		// Normal ordering
		{0, 1, true},
		{1, 0, false},
		{100, 200, true},
		{200, 100, false},

		// Wrap-around: Max is before 0
		{Max, 0, true},
		{0, Max, false},

		// Near wrap boundary
		{Max - 5, 5, true},  // Max-5 < 5 (across wrap)
		{5, Max - 5, false}, // 5 > Max-5 (across wrap)

		// At threshold boundary
		{0, Number(Threshold), true},
		{Number(Threshold), 0, false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d<%d", tt.a, tt.b), func(t *testing.T) {
			got := tt.a.LessThan(tt.b)
			if got != tt.expected {
				t.Errorf("(%d).LessThan(%d) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestLessThanOrEqual(t *testing.T) {
	tests := []struct {
		a, b     Number
		expected bool
	}{
		{0, 0, true},
		{0, 1, true},
		{1, 0, false},
		{Max, 0, true},
		{0, Max, false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d<=%d", tt.a, tt.b), func(t *testing.T) {
			got := tt.a.LessThanOrEqual(tt.b)
			if got != tt.expected {
				t.Errorf("(%d).LessThanOrEqual(%d) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestGreaterThan(t *testing.T) {
	tests := []struct {
		a, b     Number
		expected bool
	}{
		{0, 0, false},
		{1, 0, true},
		{0, 1, false},
		{0, Max, true},  // 0 > Max (Max wraps before 0)
		{Max, 0, false}, // Max < 0
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d>%d", tt.a, tt.b), func(t *testing.T) {
			got := tt.a.GreaterThan(tt.b)
			if got != tt.expected {
				t.Errorf("(%d).GreaterThan(%d) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestIncDecRoundtrip(t *testing.T) {
	// Inc then Dec should return to the same value
	values := []Number{0, 1, 100, Max / 2, Max - 1, Max}
	for _, v := range values {
		if got := v.Inc().Dec(); got != v {
			t.Errorf("(%d).Inc().Dec() = %d, want %d", v, got, v)
		}
		if got := v.Dec().Inc(); got != v {
			t.Errorf("(%d).Dec().Inc() = %d, want %d", v, got, v)
		}
	}
}

func TestAddSubRoundtrip(t *testing.T) {
	// Add then Sub should return to the same value
	tests := []struct {
		start Number
		n     uint32
	}{
		{0, 1},
		{0, 100},
		{Max - 5, 10},
		{Max, 1},
		{100, uint32(Max)},
	}

	for _, tt := range tests {
		if got := tt.start.Add(tt.n).Sub(tt.n); got != tt.start {
			t.Errorf("(%d).Add(%d).Sub(%d) = %d, want %d", tt.start, tt.n, tt.n, got, tt.start)
		}
	}
}

func TestValue(t *testing.T) {
	n := Number(42)
	if n.Value() != 42 {
		t.Errorf("Number(42).Value() = %d, want 42", n.Value())
	}
}

// Benchmarks

func BenchmarkInc(b *testing.B) {
	n := Number(0)
	for b.Loop() {
		n = n.Inc()
	}
}

func BenchmarkAdd(b *testing.B) {
	n := Number(0)
	for b.Loop() {
		n = n.Add(7)
	}
}

func BenchmarkDistance(b *testing.B) {
	a := Number(1000)
	bv := Number(2000)
	for b.Loop() {
		a.Distance(bv)
	}
}

func BenchmarkLessThan(b *testing.B) {
	a := Number(1000)
	bv := Number(2000)
	for b.Loop() {
		a.LessThan(bv)
	}
}

func BenchmarkDistanceWrapped(b *testing.B) {
	a := Max - 5
	bv := Number(5)
	for b.Loop() {
		a.Distance(bv)
	}
}
