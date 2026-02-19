package crypto

// RFC 3394 AES Key Wrap implementation in pure Go.
// This replaces the external github.com/benburkert/openpgp/aes/keywrap dependency.

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

// Default IV for RFC 3394.
var defaultIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

var (
	errWrapPlaintext    = errors.New("keywrap: plaintext must be a multiple of 8 bytes")
	errUnwrapCiphertext = errors.New("keywrap: ciphertext must be a multiple of 8 bytes")
	errUnwrapFailed     = errors.New("keywrap: integrity check failed")
)

// KeyWrap wraps plaintext using the RFC 3394 AES Key Wrap algorithm.
// The kek (Key Encryption Key) must be a valid AES key (16, 24, or 32 bytes).
// plaintext must be a multiple of 8 bytes.
// Returns ciphertext of len(plaintext)+8 bytes.
func KeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 || len(plaintext) == 0 {
		return nil, errWrapPlaintext
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(plaintext) / 8

	// Initialize: A = IV, R[1..n] = plaintext blocks
	var a [8]byte
	copy(a[:], defaultIV[:])

	r := make([]byte, len(plaintext))
	copy(r, plaintext)

	// 6 rounds of wrapping
	var b [aes.BlockSize]byte
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			// B = AES(K, A || R[i])
			copy(b[:8], a[:])
			copy(b[8:], r[i*8:(i+1)*8])
			block.Encrypt(b[:], b[:])

			// A = MSB(64, B) XOR t where t = n*j + i + 1
			t := uint64(n*j + i + 1)
			copy(a[:], b[:8])
			tBytes := binary.BigEndian.Uint64(a[:])
			binary.BigEndian.PutUint64(a[:], tBytes^t)

			// R[i] = LSB(64, B)
			copy(r[i*8:], b[8:])
		}
	}

	// Output: C[0] = A, C[1..n] = R[1..n]
	out := make([]byte, 8+len(plaintext))
	copy(out[:8], a[:])
	copy(out[8:], r)
	return out, nil
}

// KeyUnwrap unwraps ciphertext using the RFC 3394 AES Key Wrap algorithm.
// The kek must be a valid AES key. ciphertext must be a multiple of 8 bytes.
// Returns plaintext of len(ciphertext)-8 bytes.
func KeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%8 != 0 || len(ciphertext) < 16 {
		return nil, errUnwrapCiphertext
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := (len(ciphertext) / 8) - 1

	// Initialize: A = C[0], R[1..n] = C[1..n]
	var a [8]byte
	copy(a[:], ciphertext[:8])

	r := make([]byte, n*8)
	copy(r, ciphertext[8:])

	// 6 rounds of unwrapping (in reverse)
	var b [aes.BlockSize]byte
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			// A XOR t
			t := uint64(n*j + i + 1)
			tBytes := binary.BigEndian.Uint64(a[:])
			binary.BigEndian.PutUint64(b[:8], tBytes^t)

			// B = AES-1(K, (A XOR t) || R[i])
			copy(b[8:], r[i*8:(i+1)*8])
			block.Decrypt(b[:], b[:])

			// A = MSB(64, B)
			copy(a[:], b[:8])

			// R[i] = LSB(64, B)
			copy(r[i*8:], b[8:])
		}
	}

	// Verify IV
	if a != defaultIV {
		return nil, errUnwrapFailed
	}

	return r, nil
}
