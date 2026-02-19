package seq

// Tests ported from the C++ SRT implementation's test_seqno.cpp to verify
// that Go's seq package matches C++ CSeqNo behavior exactly.

import (
	"fmt"
	"testing"
)

// seqOff computes the offset from seq1 to seq2 with 31-bit wrapping.
// This is the Go-native version (exclusive/0-based).
func seqOff(seq1, seq2 uint32) int {
	return int((seq2 - seq1 + 0x80000000) & 0x7FFFFFFF)
}

// cppSeqLen computes inclusive length from seq1 to seq2, matching CSeqNo::seqlen.
// seqlen(a, a) = 1, seqlen(a, a+1) = 2, etc.
func cppSeqLen(seq1, seq2 uint32) int {
	return seqOff(seq1, seq2) + 1
}

// seqcmp mirrors CSeqNo::seqcmp(a, b) = a - b (signed, within threshold).
// In Go terms: -a.Distance(b).
func seqcmp(a, b Number) int32 {
	return -a.Distance(b)
}

func TestCppCompat_Constants(t *testing.T) {
	if Max != 0x7FFFFFFF {
		t.Errorf("Max = 0x%X, want 0x7FFFFFFF", Max)
	}
	if Threshold != 0x3FFFFFFF {
		t.Errorf("Threshold = 0x%X, want 0x3FFFFFFF", Threshold)
	}
}

func TestCppCompat_SeqCmp(t *testing.T) {
	tests := []struct {
		a, b     Number
		expected int32
	}{
		{0x7FFFFFFF, 0x7FFFFFFF, 0},
		{128, 1, 127},
		{1, 128, -127},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("seqcmp(0x%X,0x%X)", tt.a, tt.b), func(t *testing.T) {
			got := seqcmp(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("seqcmp(0x%X, 0x%X) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestCppCompat_IncSeq(t *testing.T) {
	tests := []struct {
		input    Number
		expected Number
	}{
		{1, 2},
		{125, 126},
		{0x7FFFFFFF, 0},
		{0x3FFFFFFF, 0x40000000},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("incseq(0x%X)", tt.input), func(t *testing.T) {
			got := tt.input.Inc()
			if got != tt.expected {
				t.Errorf("Number(0x%X).Inc() = 0x%X, want 0x%X", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCppCompat_DecSeq(t *testing.T) {
	tests := []struct {
		input    Number
		expected Number
	}{
		{1, 0},
		{125, 124},
		{0, 0x7FFFFFFF},
		{0x40000000, 0x3FFFFFFF},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("decseq(0x%X)", tt.input), func(t *testing.T) {
			got := tt.input.Dec()
			if got != tt.expected {
				t.Errorf("Number(0x%X).Dec() = 0x%X, want 0x%X", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCppCompat_IncSeqOffset(t *testing.T) {
	tests := []struct {
		input    Number
		offset   uint32
		expected Number
	}{
		{1, 1, 2},
		{125, 1, 126},
		{0x7FFFFFFF, 1, 0},
		{0x3FFFFFFF, 1, 0x40000000},
		{0x3FFFFFFF, 0x3FFFFFFF, 0x7FFFFFFE},
		{0x3FFFFFFF, 0x40000000, 0x7FFFFFFF},
		{0x3FFFFFFF, 0x40000001, 0x00000000},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("incseq(0x%X,0x%X)", tt.input, tt.offset), func(t *testing.T) {
			got := tt.input.Add(tt.offset)
			if got != tt.expected {
				t.Errorf("Number(0x%X).Add(0x%X) = 0x%X, want 0x%X",
					tt.input, tt.offset, got, tt.expected)
			}
		})
	}
}

func TestCppCompat_DecSeqOffset(t *testing.T) {
	tests := []struct {
		input    Number
		offset   uint32
		expected Number
	}{
		{1, 1, 0},
		{125, 1, 124},
		{0, 1, 0x7FFFFFFF},
		{0x40000000, 1, 0x3FFFFFFF},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("decseq(0x%X,0x%X)", tt.input, tt.offset), func(t *testing.T) {
			got := tt.input.Sub(tt.offset)
			if got != tt.expected {
				t.Errorf("Number(0x%X).Sub(0x%X) = 0x%X, want 0x%X",
					tt.input, tt.offset, got, tt.expected)
			}
		})
	}
}

func TestCppCompat_FlightSpan(t *testing.T) {
	tests := []struct {
		lastack Number
		curseq  Number
		span    int
	}{
		{125, 124, 0}, // all sent packets acknowledged
		{125, 125, 1},
		{125, 130, 6},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("flight(%d,%d)", tt.lastack, tt.curseq), func(t *testing.T) {
			var got int
			if tt.curseq.LessThan(tt.lastack) {
				got = 0
			} else {
				got = cppSeqLen(uint32(tt.lastack), uint32(tt.curseq))
			}
			if got != tt.span {
				t.Errorf("flightSpan(%d, %d) = %d, want %d",
					tt.lastack, tt.curseq, got, tt.span)
			}
		})
	}
}

func TestCppCompat_SeqLen(t *testing.T) {
	tests := []struct {
		seq1     uint32
		seq2     uint32
		expected int
	}{
		{125, 125, 1},
		{125, 126, 2},
		{0x7FFFFFFF, 0, 2}, // seqlen(Max, 0) = 2 (Max, then 0)
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("seqlen(%d,%d)", tt.seq1, tt.seq2), func(t *testing.T) {
			got := cppSeqLen(tt.seq1, tt.seq2)
			if got != tt.expected {
				t.Errorf("seqLen(%d, %d) = %d, want %d",
					tt.seq1, tt.seq2, got, tt.expected)
			}
		})
	}
}
