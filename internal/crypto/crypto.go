// Package crypto implements SRT encryption and decryption.
//
// SRT supports two cipher modes:
//   - AES-CTR (default): stream cipher, no authentication
//   - AES-GCM: authenticated encryption with associated data (AEAD)
//
// Both modes use PBKDF2-derived KEKs (Key Encryption Keys) and RFC 3394
// AES Key Wrap for key exchange. Cipher blocks and AEAD instances are cached
// to avoid re-creating them per packet.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"crypto/pbkdf2"

	"github.com/zsiec/srtgo/internal/packet"
)

// CipherMode represents the SRT encryption cipher mode.
// HCRYPT_CIPHER_AES_CTR=2, HCRYPT_CIPHER_AES_GCM=4
type CipherMode uint8

const (
	CipherCTR CipherMode = 2 // AES-CTR (default, legacy)
	CipherGCM CipherMode = 4 // AES-GCM (authenticated encryption)
)

const (
	// AuthNone indicates no authentication (CTR mode).
	AuthNone uint8 = 0

	// AuthGCM indicates GCM authentication.
	AuthGCM uint8 = 1

	// GCMTagSize is the GCM authentication tag size in bytes (16).
	GCMTagSize = 16

	// GCMNonceSize is the GCM nonce/IV size in bytes (96 bits).
	GCMNonceSize = 12
)

var (
	// ErrInvalidKey is returned when the encryption flag is invalid.
	ErrInvalidKey = errors.New("crypto: invalid encryption key type")

	// ErrInvalidPassphrase is returned when the passphrase is wrong.
	ErrInvalidPassphrase = errors.New("crypto: invalid passphrase")

	// ErrAuthFailed is returned when GCM authentication fails during decryption.
	ErrAuthFailed = errors.New("crypto: GCM authentication failed")
)

// Context manages SRT encryption state. It caches AES cipher blocks (CTR)
// and AEAD instances (GCM) to avoid allocating them per-packet.
type Context struct {
	mu        sync.RWMutex
	mode      CipherMode
	keyLength int
	salt      [16]byte

	evenSEK    []byte
	oddSEK     []byte
	evenCipher cipher.Block // cached for CTR — only recreated on key rotation
	oddCipher  cipher.Block // cached for CTR
	evenAEAD   cipher.AEAD  // cached for GCM
	oddAEAD    cipher.AEAD  // cached for GCM

	// GCM 1.5.3 backward compatibility: old nonce format uses salt[4:16]
	// instead of salt[0:12]. Enabled for peers with version >= 1.5.3 && < 1.5.4.
	useGcm153 bool
}

// New creates a new crypto context with CTR mode and the given key length
// (16, 24, or 32 bytes). It generates a random salt and initial SEKs.
func New(keyLength int) (*Context, error) {
	return NewWithMode(keyLength, CipherCTR)
}

// NewWithMode creates a new crypto context with the specified cipher mode
// and key length (16, 24, or 32 bytes).
func NewWithMode(keyLength int, mode CipherMode) (*Context, error) {
	switch keyLength {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("crypto: invalid key size %d, must be 16, 24, or 32", keyLength)
	}

	ctx := &Context{keyLength: keyLength, mode: mode}

	// Generate random salt (128 bits)
	if _, err := rand.Read(ctx.salt[:]); err != nil {
		return nil, fmt.Errorf("crypto: generating salt: %w", err)
	}

	// Generate initial even and odd SEKs
	if err := ctx.generateSEK(packet.EncryptionEven); err != nil {
		return nil, err
	}
	if err := ctx.generateSEK(packet.EncryptionOdd); err != nil {
		return nil, err
	}

	return ctx, nil
}

// Mode returns the cipher mode (CTR or GCM).
func (ctx *Context) Mode() CipherMode {
	return ctx.mode
}

// SetMode changes the cipher mode. Must be called before any encrypt/decrypt
// operations if the mode was learned from a peer's KMREQ.
func (ctx *Context) SetMode(mode CipherMode) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.mode == mode {
		return
	}
	ctx.mode = mode
	// Recreate AEAD ciphers if switching to GCM
	if mode == CipherGCM {
		if ctx.evenCipher != nil {
			ctx.evenAEAD, _ = cipher.NewGCM(ctx.evenCipher)
		}
		if ctx.oddCipher != nil {
			ctx.oddAEAD, _ = cipher.NewGCM(ctx.oddCipher)
		}
	}
}

// SetGCM153 enables or disables GCM 1.5.3 backward compatibility mode.
// In this mode, the GCM nonce is built using salt[4:16] instead of salt[0:12].
// This matches the older SRT v1.5.3 nonce derivation format.
func (ctx *Context) SetGCM153(enabled bool) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.useGcm153 = enabled
}

// GenerateSEK generates a new random SEK for the given key slot.
func (ctx *Context) GenerateSEK(key packet.PacketEncryption) error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return ctx.generateSEK(key)
}

func (ctx *Context) generateSEK(key packet.PacketEncryption) error {
	sek := make([]byte, ctx.keyLength)
	if _, err := rand.Read(sek); err != nil {
		return fmt.Errorf("crypto: generating SEK: %w", err)
	}

	block, err := aes.NewCipher(sek)
	if err != nil {
		return fmt.Errorf("crypto: creating cipher: %w", err)
	}

	// Create AEAD for GCM mode
	var aead cipher.AEAD
	if ctx.mode == CipherGCM {
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return fmt.Errorf("crypto: creating GCM: %w", err)
		}
	}

	switch key {
	case packet.EncryptionEven:
		ctx.evenSEK = sek
		ctx.evenCipher = block
		ctx.evenAEAD = aead
	case packet.EncryptionOdd:
		ctx.oddSEK = sek
		ctx.oddCipher = block
		ctx.oddAEAD = aead
	default:
		return ErrInvalidKey
	}

	return nil
}

// ClearSEK zeros and removes the SEK for the given key slot.
// Called during PostSwitch to clear the deprecated key.
func (ctx *Context) ClearSEK(key packet.PacketEncryption) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	switch key {
	case packet.EncryptionEven:
		for i := range ctx.evenSEK {
			ctx.evenSEK[i] = 0
		}
		ctx.evenSEK = nil
		ctx.evenCipher = nil
		ctx.evenAEAD = nil
	case packet.EncryptionOdd:
		for i := range ctx.oddSEK {
			ctx.oddSEK[i] = 0
		}
		ctx.oddSEK = nil
		ctx.oddCipher = nil
		ctx.oddAEAD = nil
	}
}

// EncryptPayload encrypts the payload data.
// For CTR mode: data is modified in-place, header is ignored. Returns data.
// For GCM mode: returns ciphertext+tag (GCMTagSize bytes longer), uses header as AAD.
//
// The header parameter should be the 16-byte marshalled SRT data packet header
// (seqno, msgno+flags, timestamp, destSocketID) in network byte order.
func (ctx *Context) EncryptPayload(data []byte, header []byte, key packet.PacketEncryption, seqNo uint32) ([]byte, error) {
	if ctx.mode == CipherGCM {
		return ctx.encryptGCM(data, header, key, seqNo)
	}
	err := ctx.xorPayload(data, key, seqNo)
	return data, err
}

// DecryptPayload decrypts the payload data.
// For CTR mode: data is modified in-place, header is ignored. Returns data.
// For GCM mode: returns plaintext (GCMTagSize bytes shorter), uses header as AAD.
// Returns ErrAuthFailed if GCM authentication fails.
func (ctx *Context) DecryptPayload(data []byte, header []byte, key packet.PacketEncryption, seqNo uint32) ([]byte, error) {
	if ctx.mode == CipherGCM {
		return ctx.decryptGCM(data, header, key, seqNo)
	}
	err := ctx.xorPayload(data, key, seqNo)
	return data, err
}

// xorPayload performs AES-CTR XOR on data. Used for both encryption and decryption.
func (ctx *Context) xorPayload(data []byte, key packet.PacketEncryption, seqNo uint32) error {
	ctx.mu.RLock()
	block, salt := ctx.cipherAndSalt(key)
	ctx.mu.RUnlock()

	if block == nil {
		return ErrInvalidKey
	}

	// Build CTR IV per SRT spec (Section 6.1.2):
	//   IV = MSB(112, Salt) = salt[0..13] (14 bytes)
	//   CTR[0..9]   = salt[0..9]
	//   CTR[10..13] = salt[10..13] XOR packet_sequence_number
	//   CTR[14..15] = 0 (block counter, incremented by AES-CTR)
	var ctr [16]byte
	binary.BigEndian.PutUint32(ctr[10:], seqNo)
	for i := 0; i < 14; i++ {
		ctr[i] ^= salt[i]
	}

	stream := cipher.NewCTR(block, ctr[:])
	stream.XORKeyStream(data, data)

	return nil
}

// encryptGCM encrypts data using AES-GCM with the packet header as AAD.
// Returns ciphertext + 16-byte authentication tag.
// Implements GCM encryption per the SRT spec.
func (ctx *Context) encryptGCM(data []byte, header []byte, key packet.PacketEncryption, seqNo uint32) ([]byte, error) {
	ctx.mu.RLock()
	aead, salt := ctx.aeadAndSalt(key)
	useGcm153 := ctx.useGcm153
	ctx.mu.RUnlock()

	if aead == nil {
		return nil, ErrInvalidKey
	}

	nonce := ctx.buildGCMNonce(salt, seqNo, useGcm153)

	// AAD is the 16-byte SRT packet header in network byte order (first 4 uint32s).
	var aad []byte
	if len(header) >= 16 {
		aad = header[:16]
	}

	// Seal appends ciphertext+tag to dst. Pre-allocate for the result.
	result := aead.Seal(nil, nonce[:], data, aad)
	return result, nil
}

// decryptGCM decrypts data using AES-GCM with the packet header as AAD.
// Input data must include the 16-byte authentication tag at the end.
// Returns plaintext with the tag stripped, or ErrAuthFailed if verification fails.
// Implements GCM decryption per the SRT spec.
func (ctx *Context) decryptGCM(data []byte, header []byte, key packet.PacketEncryption, seqNo uint32) ([]byte, error) {
	ctx.mu.RLock()
	aead, salt := ctx.aeadAndSalt(key)
	useGcm153 := ctx.useGcm153
	ctx.mu.RUnlock()

	if aead == nil {
		return nil, ErrInvalidKey
	}

	if len(data) < GCMTagSize {
		return nil, ErrAuthFailed
	}

	nonce := ctx.buildGCMNonce(salt, seqNo, useGcm153)

	var aad []byte
	if len(header) >= 16 {
		aad = header[:16]
	}

	// Open verifies the tag and decrypts in-place.
	// data contains ciphertext+tag; plaintext is shorter (no tag), so data[:0]
	// as dst is safe — Go's GCM.Open supports this aliasing pattern.
	plaintext, err := aead.Open(data[:0], nonce[:], data, aad)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return plaintext, nil
}

// buildGCMNonce builds the 96-bit GCM nonce from the salt and sequence number.
// v1.5.4+ format: zeros[12] + pki@offset8 XOR salt[0:12]
// v1.5.3 format: zeros[16] + pki@offset10 → take bytes[4:16] → effectively XOR with salt[4:16]
func (ctx *Context) buildGCMNonce(salt [16]byte, seqNo uint32, legacy bool) [GCMNonceSize]byte {
	var nonce [GCMNonceSize]byte
	if legacy {
		// v1.5.3: build a 16-byte CTR-style IV, then take bytes [4:16]
		var iv [16]byte
		binary.BigEndian.PutUint32(iv[12:], seqNo) // pki at offset 12 (last 4 bytes)
		for i := 0; i < 16; i++ {
			iv[i] ^= salt[i]
		}
		copy(nonce[:], iv[4:16])
	} else {
		// v1.5.4+: standard format
		binary.BigEndian.PutUint32(nonce[8:], seqNo)
		for i := 0; i < GCMNonceSize; i++ {
			nonce[i] ^= salt[i]
		}
	}
	return nonce
}

func (ctx *Context) cipherAndSalt(key packet.PacketEncryption) (cipher.Block, [16]byte) {
	switch key {
	case packet.EncryptionEven:
		return ctx.evenCipher, ctx.salt
	case packet.EncryptionOdd:
		return ctx.oddCipher, ctx.salt
	default:
		return nil, ctx.salt
	}
}

func (ctx *Context) aeadAndSalt(key packet.PacketEncryption) (cipher.AEAD, [16]byte) {
	switch key {
	case packet.EncryptionEven:
		return ctx.evenAEAD, ctx.salt
	case packet.EncryptionOdd:
		return ctx.oddAEAD, ctx.salt
	default:
		return nil, ctx.salt
	}
}

// MarshalKM populates a CIFKeyMaterial with the wrapped SEK(s) for the given key slot.
func (ctx *Context) MarshalKM(km *packet.CIFKeyMaterial, passphrase string, key packet.PacketEncryption) error {
	if key == packet.EncryptionNone {
		return ErrInvalidKey
	}

	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	km.S = 0
	km.Version = 1
	km.PacketType = 2
	km.Sign = 0x2029
	km.KeyBasedEncryption = key
	km.KeyEncryptionKeyIndex = 0
	km.StreamEncapsulation = 2
	km.SLen = 16
	km.KLen = uint16(ctx.keyLength)

	// Set cipher and authentication fields based on mode.
	if ctx.mode == CipherGCM {
		km.Cipher = uint8(CipherGCM)
		km.Authentication = AuthGCM
	} else {
		km.Cipher = uint8(CipherCTR)
		km.Authentication = AuthNone
	}

	km.Salt = make([]byte, 16)
	copy(km.Salt, ctx.salt[:])

	// Prepare plaintext: one or two keys
	n := 1
	if key == packet.EncryptionBoth {
		n = 2
	}
	plaintext := make([]byte, n*ctx.keyLength)

	switch key {
	case packet.EncryptionEven:
		copy(plaintext, ctx.evenSEK)
	case packet.EncryptionOdd:
		copy(plaintext, ctx.oddSEK)
	case packet.EncryptionBoth:
		copy(plaintext[:ctx.keyLength], ctx.evenSEK)
		copy(plaintext[ctx.keyLength:], ctx.oddSEK)
	}

	kek := calculateKEK(passphrase, ctx.salt[:], ctx.keyLength)

	wrap, err := KeyWrap(kek, plaintext)
	if err != nil {
		return fmt.Errorf("crypto: wrapping key: %w", err)
	}

	km.Wrap = wrap
	return nil
}

// UnmarshalKM unwraps the SEK(s) from a CIFKeyMaterial using the passphrase.
// If the KM specifies GCM cipher mode, the context's mode is updated accordingly.
func (ctx *Context) UnmarshalKM(km *packet.CIFKeyMaterial, passphrase string) error {
	if km.KeyBasedEncryption == packet.EncryptionNone {
		return ErrInvalidKey
	}

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	if len(km.Salt) == 16 {
		copy(ctx.salt[:], km.Salt)
	}

	// Adopt cipher mode from peer's KMREQ (auto-negotiate cipher mode from KM message).
	if km.Cipher == uint8(CipherGCM) {
		ctx.mode = CipherGCM
	} else {
		ctx.mode = CipherCTR
	}

	kek := calculateKEK(passphrase, ctx.salt[:], ctx.keyLength)

	plaintext, err := KeyUnwrap(kek, km.Wrap)
	if err != nil {
		return ErrInvalidPassphrase
	}

	n := 1
	if km.KeyBasedEncryption == packet.EncryptionBoth {
		n = 2
	}
	expectedLen := n * ctx.keyLength
	if len(plaintext) != expectedLen {
		return fmt.Errorf("crypto: unwrapped key wrong length (%d, want %d)", len(plaintext), expectedLen)
	}

	// Install key(s) and cache cipher block(s) + AEAD instances
	switch km.KeyBasedEncryption {
	case packet.EncryptionEven:
		ctx.evenSEK = make([]byte, ctx.keyLength)
		copy(ctx.evenSEK, plaintext)
		ctx.evenCipher, err = aes.NewCipher(ctx.evenSEK)
		if err == nil && ctx.mode == CipherGCM {
			ctx.evenAEAD, err = cipher.NewGCM(ctx.evenCipher)
		}
	case packet.EncryptionOdd:
		ctx.oddSEK = make([]byte, ctx.keyLength)
		copy(ctx.oddSEK, plaintext)
		ctx.oddCipher, err = aes.NewCipher(ctx.oddSEK)
		if err == nil && ctx.mode == CipherGCM {
			ctx.oddAEAD, err = cipher.NewGCM(ctx.oddCipher)
		}
	case packet.EncryptionBoth:
		ctx.evenSEK = make([]byte, ctx.keyLength)
		ctx.oddSEK = make([]byte, ctx.keyLength)
		copy(ctx.evenSEK, plaintext[:ctx.keyLength])
		copy(ctx.oddSEK, plaintext[ctx.keyLength:])
		ctx.evenCipher, err = aes.NewCipher(ctx.evenSEK)
		if err == nil {
			ctx.oddCipher, err = aes.NewCipher(ctx.oddSEK)
		}
		if err == nil && ctx.mode == CipherGCM {
			ctx.evenAEAD, err = cipher.NewGCM(ctx.evenCipher)
			if err == nil {
				ctx.oddAEAD, err = cipher.NewGCM(ctx.oddCipher)
			}
		}
	}

	return err
}

// Salt returns the current salt value.
func (ctx *Context) Salt() [16]byte {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	return ctx.salt
}

// KeyLength returns the configured key length.
func (ctx *Context) KeyLength() int {
	return ctx.keyLength
}

// calculateKEK derives a Key Encryption Key from a passphrase and salt using PBKDF2.
// SRT Section 6.1.4: PBKDF2(HMAC-SHA1, passphrase, LSB(64, salt), 2048, keyLength)
func calculateKEK(passphrase string, salt []byte, keyLength int) []byte {
	// Use the last 8 bytes of the salt per the SRT spec
	saltForKDF := salt[8:]
	key, _ := pbkdf2.Key(sha1.New, passphrase, saltForKDF, 2048, keyLength)
	return key
}
