package packet

import (
	"net"
	"testing"
)

var fuzzAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6000}

// FuzzParse tests that Parse never panics on arbitrary input.
func FuzzParse(f *testing.F) {
	// Seed with valid data packet
	validData := make([]byte, 24)
	validData[0] = 0x00 // data packet, seq=0
	f.Add(validData)

	// Seed with valid control packet (ACK)
	validCtrl := make([]byte, 44)
	validCtrl[0] = 0x80 // control packet
	validCtrl[1] = 0x02 // ACK type
	f.Add(validCtrl)

	// Seed with handshake packet
	handshake := make([]byte, 64)
	handshake[0] = 0x80 // control packet
	handshake[1] = 0x00 // handshake type
	f.Add(handshake)

	// Seed with minimal packet (just header)
	f.Add(make([]byte, 16))

	// Seed with too-short data
	f.Add(make([]byte, 4))

	// Seed with empty
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data, fuzzAddr)
		if err != nil {
			return
		}

		// If parsing succeeded, marshaling should also not panic
		buf := make([]byte, HeaderSize+len(p.Data)+64)
		p.Marshal(buf)

		// Clone should not panic
		clone := p.Clone()
		clone.Release()

		p.Release()
	})
}

// FuzzHeaderUnmarshal tests that Header.Unmarshal never panics.
func FuzzHeaderUnmarshal(f *testing.F) {
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 4))
	f.Add([]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		var h Header
		err := h.Unmarshal(data)
		if err != nil {
			return
		}

		// If unmarshal succeeded, marshal should produce valid output
		var buf [HeaderSize]byte
		h.Marshal(buf[:])
	})
}

// FuzzCIFACK tests that CIFACK unmarshal never panics.
func FuzzCIFACK(f *testing.F) {
	// Valid 28-byte full ACK
	f.Add(make([]byte, 28))
	// Valid 4-byte lite ACK
	f.Add(make([]byte, 4))
	// Short
	f.Add(make([]byte, 2))

	f.Fuzz(func(t *testing.T, data []byte) {
		var ack CIFACK
		err := ack.UnmarshalCIF(data)
		if err != nil {
			return
		}

		// Roundtrip
		marshaled, err := ack.MarshalCIF()
		if err != nil {
			return
		}
		_ = marshaled
	})
}

// FuzzCIFNAK tests that CIFNAK unmarshal never panics.
func FuzzCIFNAK(f *testing.F) {
	// Single loss
	f.Add([]byte{0x00, 0x00, 0x00, 0x01})
	// Range loss
	f.Add([]byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05})
	// Empty
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var nak CIFNAK
		err := nak.UnmarshalCIF(data)
		if err != nil {
			return
		}

		marshaled, err := nak.MarshalCIF()
		if err != nil {
			return
		}
		_ = marshaled
	})
}

// FuzzCIFHandshake tests that handshake CIF unmarshal never panics.
func FuzzCIFHandshake(f *testing.F) {
	// Minimal handshake (48 bytes)
	f.Add(make([]byte, 48))

	// Handshake with extensions
	ext := make([]byte, 128)
	ext[0] = 0x00
	ext[1] = 0x00
	ext[2] = 0x00
	ext[3] = 0x05 // version 5
	ext[20] = 0xFF
	ext[21] = 0xFF
	ext[22] = 0xFF
	ext[23] = 0xFF // CONCLUSION
	f.Add(ext)

	f.Fuzz(func(t *testing.T, data []byte) {
		var hs CIFHandshake
		err := hs.UnmarshalCIF(data)
		if err != nil {
			return
		}

		marshaled, err := hs.MarshalCIF()
		if err != nil {
			return
		}
		_ = marshaled
	})
}
