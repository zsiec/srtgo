package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/zsiec/srtgo/internal/packet"
)

// RFC 3394 Test Vectors from https://www.rfc-editor.org/rfc/rfc3394#section-4

func TestKeyWrapRFC3394_128(t *testing.T) {
	// 4.1 Wrap 128 bits of Key Data with a 128-bit KEK
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	plaintext, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	expected, _ := hex.DecodeString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

	wrapped, err := KeyWrap(kek, plaintext)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	if !bytes.Equal(wrapped, expected) {
		t.Errorf("KeyWrap:\n  got  %s\n  want %s", hex.EncodeToString(wrapped), hex.EncodeToString(expected))
	}
}

func TestKeyUnwrapRFC3394_128(t *testing.T) {
	// Unwrap the 4.1 test vector
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	ciphertext, _ := hex.DecodeString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
	expected, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")

	unwrapped, err := KeyUnwrap(kek, ciphertext)
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, expected) {
		t.Errorf("KeyUnwrap:\n  got  %s\n  want %s", hex.EncodeToString(unwrapped), hex.EncodeToString(expected))
	}
}

func TestKeyWrapRFC3394_192(t *testing.T) {
	// 4.2 Wrap 128 bits of Key Data with a 192-bit KEK
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F1011121314151617")
	plaintext, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	expected, _ := hex.DecodeString("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D")

	wrapped, err := KeyWrap(kek, plaintext)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	if !bytes.Equal(wrapped, expected) {
		t.Errorf("KeyWrap:\n  got  %s\n  want %s", hex.EncodeToString(wrapped), hex.EncodeToString(expected))
	}
}

func TestKeyWrapRFC3394_256(t *testing.T) {
	// 4.3 Wrap 128 bits of Key Data with a 256-bit KEK
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	plaintext, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	expected, _ := hex.DecodeString("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")

	wrapped, err := KeyWrap(kek, plaintext)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	if !bytes.Equal(wrapped, expected) {
		t.Errorf("KeyWrap:\n  got  %s\n  want %s", hex.EncodeToString(wrapped), hex.EncodeToString(expected))
	}
}

func TestKeyWrapRFC3394_256_256(t *testing.T) {
	// 4.6 Wrap 256 bits of Key Data with a 256-bit KEK
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	plaintext, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
	expected, _ := hex.DecodeString("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")

	wrapped, err := KeyWrap(kek, plaintext)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	if !bytes.Equal(wrapped, expected) {
		t.Errorf("KeyWrap:\n  got  %s\n  want %s", hex.EncodeToString(wrapped), hex.EncodeToString(expected))
	}
}

func TestKeyWrapUnwrapRoundtrip(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	original, _ := hex.DecodeString("DEADBEEFCAFEBABE1234567890ABCDEF")

	wrapped, err := KeyWrap(kek, original)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	unwrapped, err := KeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, original) {
		t.Errorf("roundtrip failed:\n  got  %s\n  want %s", hex.EncodeToString(unwrapped), hex.EncodeToString(original))
	}
}

func TestKeyUnwrapWrongKey(t *testing.T) {
	kek1, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	kek2, _ := hex.DecodeString("FF0102030405060708090A0B0C0D0E0F")
	plaintext, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")

	wrapped, err := KeyWrap(kek1, plaintext)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	_, err = KeyUnwrap(kek2, wrapped)
	if err == nil {
		t.Error("expected error for wrong key")
	}
}

func TestKeyWrapInvalidPlaintext(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")

	_, err := KeyWrap(kek, []byte{1, 2, 3}) // not multiple of 8
	if err == nil {
		t.Error("expected error for non-8-byte-aligned plaintext")
	}

	_, err = KeyWrap(kek, []byte{}) // empty
	if err == nil {
		t.Error("expected error for empty plaintext")
	}
}

// --- CTR Crypto Context tests ---

func TestCryptoEncryptDecryptCTR(t *testing.T) {
	ctx, err := New(16) // AES-128, CTR mode
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	original := []byte("Hello, SRT World! This is test data for encryption.")
	data := make([]byte, len(original))
	copy(data, original)

	// Encrypt with even key
	result, err := ctx.EncryptPayload(data, nil, packet.EncryptionEven, 42)
	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	// For CTR, result should be the same slice
	if &result[0] != &data[0] {
		t.Error("CTR encrypt should return same slice")
	}

	// Data should be different from original
	if bytes.Equal(data, original) {
		t.Error("encrypted data should differ from original")
	}

	// Decrypt with same key
	result, err = ctx.DecryptPayload(data, nil, packet.EncryptionEven, 42)
	if err != nil {
		t.Fatalf("DecryptPayload failed: %v", err)
	}

	if !bytes.Equal(result, original) {
		t.Errorf("decrypted data differs:\n  got  %q\n  want %q", result, original)
	}
}

func TestCryptoEncryptDecryptOddKey(t *testing.T) {
	ctx, err := New(32) // AES-256
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	original := []byte("Test with AES-256 odd key")
	data := make([]byte, len(original))
	copy(data, original)

	data, err = ctx.EncryptPayload(data, nil, packet.EncryptionOdd, 100)
	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	data, err = ctx.DecryptPayload(data, nil, packet.EncryptionOdd, 100)
	if err != nil {
		t.Fatalf("DecryptPayload failed: %v", err)
	}

	if !bytes.Equal(data, original) {
		t.Error("roundtrip failed")
	}
}

func TestCryptoWrongSequenceNumber(t *testing.T) {
	ctx, err := New(16)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	original := []byte("sequence number matters")
	data := make([]byte, len(original))
	copy(data, original)

	data, _ = ctx.EncryptPayload(data, nil, packet.EncryptionEven, 42)
	data, _ = ctx.DecryptPayload(data, nil, packet.EncryptionEven, 43) // wrong sequence number

	if bytes.Equal(data, original) {
		t.Error("decryption with wrong seqno should not recover original data")
	}
}

func TestCryptoKeyMaterialRoundtrip(t *testing.T) {
	passphrase := "my secret passphrase"

	// Sender creates crypto context and marshals KM
	sender, err := New(16)
	if err != nil {
		t.Fatalf("New sender failed: %v", err)
	}

	km := &packet.CIFKeyMaterial{}
	err = sender.MarshalKM(km, passphrase, packet.EncryptionEven)
	if err != nil {
		t.Fatalf("MarshalKM failed: %v", err)
	}

	// Receiver creates crypto context and unmarshals KM
	receiver, err := New(16)
	if err != nil {
		t.Fatalf("New receiver failed: %v", err)
	}

	err = receiver.UnmarshalKM(km, passphrase)
	if err != nil {
		t.Fatalf("UnmarshalKM failed: %v", err)
	}

	// Now both should be able to encrypt/decrypt the same data
	original := []byte("This should be decryptable by both sides!")
	encrypted := make([]byte, len(original))
	copy(encrypted, original)

	encrypted, err = sender.EncryptPayload(encrypted, nil, packet.EncryptionEven, 1)
	if err != nil {
		t.Fatalf("sender encrypt failed: %v", err)
	}

	decrypted, err := receiver.DecryptPayload(encrypted, nil, packet.EncryptionEven, 1)
	if err != nil {
		t.Fatalf("receiver decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Errorf("cross-context roundtrip failed:\n  got  %q\n  want %q", decrypted, original)
	}
}

func TestCryptoKeyMaterialWrongPassphrase(t *testing.T) {
	sender, err := New(16)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	km := &packet.CIFKeyMaterial{}
	err = sender.MarshalKM(km, "correct passphrase", packet.EncryptionEven)
	if err != nil {
		t.Fatalf("MarshalKM failed: %v", err)
	}

	receiver, err := New(16)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	err = receiver.UnmarshalKM(km, "wrong passphrase")
	if err == nil {
		t.Error("expected error for wrong passphrase")
	}
}

func TestCryptoKeyMaterialBothKeys(t *testing.T) {
	passphrase := "both keys test"

	sender, err := New(16)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	km := &packet.CIFKeyMaterial{}
	err = sender.MarshalKM(km, passphrase, packet.EncryptionBoth)
	if err != nil {
		t.Fatalf("MarshalKM failed: %v", err)
	}

	if km.KeyBasedEncryption != packet.EncryptionBoth {
		t.Errorf("expected EncryptionBoth, got %d", km.KeyBasedEncryption)
	}

	receiver, err := New(16)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	err = receiver.UnmarshalKM(km, passphrase)
	if err != nil {
		t.Fatalf("UnmarshalKM failed: %v", err)
	}

	// Test both even and odd keys work
	for _, key := range []packet.PacketEncryption{packet.EncryptionEven, packet.EncryptionOdd} {
		original := []byte("test data for both keys")
		data := make([]byte, len(original))
		copy(data, original)

		data, _ = sender.EncryptPayload(data, nil, key, 1)
		data, _ = receiver.DecryptPayload(data, nil, key, 1)

		if !bytes.Equal(data, original) {
			t.Errorf("key %d roundtrip failed", key)
		}
	}
}

func TestCryptoKeyRotation(t *testing.T) {
	ctx, err := New(16)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Encrypt with even key
	original := []byte("pre rotation data")
	data1 := make([]byte, len(original))
	copy(data1, original)
	data1, _ = ctx.EncryptPayload(data1, nil, packet.EncryptionEven, 1)

	// Rotate even key
	err = ctx.GenerateSEK(packet.EncryptionEven)
	if err != nil {
		t.Fatalf("GenerateSEK failed: %v", err)
	}

	// Can't decrypt old data with new key
	data1, _ = ctx.DecryptPayload(data1, nil, packet.EncryptionEven, 1)
	if bytes.Equal(data1, original) {
		t.Error("should not decrypt with rotated key")
	}

	// New data with new key works
	data2 := make([]byte, len(original))
	copy(data2, original)
	data2, _ = ctx.EncryptPayload(data2, nil, packet.EncryptionEven, 2)
	data2, _ = ctx.DecryptPayload(data2, nil, packet.EncryptionEven, 2)
	if !bytes.Equal(data2, original) {
		t.Error("new key roundtrip failed")
	}
}

func TestCryptoInvalidKeyLength(t *testing.T) {
	for _, kl := range []int{0, 8, 15, 17, 31, 33, 64} {
		_, err := New(kl)
		if err == nil {
			t.Errorf("expected error for key length %d", kl)
		}
	}
}

// --- GCM Crypto Context tests ---

func TestCryptoGCMEncryptDecrypt(t *testing.T) {
	ctx, err := NewWithMode(16, CipherGCM) // AES-128-GCM
	if err != nil {
		t.Fatalf("NewWithMode failed: %v", err)
	}

	original := []byte("Hello, SRT GCM World!")
	header := makeTestHeader(42, 1, 1000, 5555)

	encrypted, err := ctx.EncryptPayload(original, header, packet.EncryptionEven, 42)
	if err != nil {
		t.Fatalf("EncryptPayload GCM failed: %v", err)
	}

	// GCM output should be 16 bytes longer (auth tag)
	if len(encrypted) != len(original)+GCMTagSize {
		t.Errorf("GCM ciphertext length: got %d, want %d", len(encrypted), len(original)+GCMTagSize)
	}

	// Ciphertext should differ from plaintext
	if bytes.Equal(encrypted[:len(original)], original) {
		t.Error("GCM encrypted data should differ from original")
	}

	// Decrypt
	decrypted, err := ctx.DecryptPayload(encrypted, header, packet.EncryptionEven, 42)
	if err != nil {
		t.Fatalf("DecryptPayload GCM failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Errorf("GCM roundtrip failed:\n  got  %q\n  want %q", decrypted, original)
	}
}

func TestCryptoGCMAuthFailure(t *testing.T) {
	ctx, err := NewWithMode(16, CipherGCM)
	if err != nil {
		t.Fatalf("NewWithMode failed: %v", err)
	}

	original := []byte("tamper test data")
	header := makeTestHeader(42, 1, 1000, 5555)

	encrypted, err := ctx.EncryptPayload(original, header, packet.EncryptionEven, 42)
	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	// Tamper with the ciphertext
	encrypted[0] ^= 0xFF

	_, err = ctx.DecryptPayload(encrypted, header, packet.EncryptionEven, 42)
	if err != ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed, got %v", err)
	}
}

func TestCryptoGCMWrongHeader(t *testing.T) {
	ctx, err := NewWithMode(16, CipherGCM)
	if err != nil {
		t.Fatalf("NewWithMode failed: %v", err)
	}

	original := []byte("header mismatch test")
	header := makeTestHeader(42, 1, 1000, 5555)

	encrypted, err := ctx.EncryptPayload(original, header, packet.EncryptionEven, 42)
	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	// Decrypt with different header (wrong AAD)
	wrongHeader := makeTestHeader(42, 2, 1000, 5555) // different message number
	_, err = ctx.DecryptPayload(encrypted, wrongHeader, packet.EncryptionEven, 42)
	if err != ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed with wrong header, got %v", err)
	}
}

func TestCryptoGCMKeyMaterial(t *testing.T) {
	passphrase := "gcm key material test"

	sender, err := NewWithMode(32, CipherGCM) // AES-256-GCM
	if err != nil {
		t.Fatalf("NewWithMode sender failed: %v", err)
	}

	km := &packet.CIFKeyMaterial{}
	err = sender.MarshalKM(km, passphrase, packet.EncryptionEven)
	if err != nil {
		t.Fatalf("MarshalKM failed: %v", err)
	}

	// KM should have GCM cipher and auth fields
	if km.Cipher != uint8(CipherGCM) {
		t.Errorf("KM Cipher: got %d, want %d", km.Cipher, CipherGCM)
	}
	if km.Authentication != AuthGCM {
		t.Errorf("KM Authentication: got %d, want %d", km.Authentication, AuthGCM)
	}

	// Receiver creates CTR context, should auto-switch to GCM on UnmarshalKM
	receiver, err := New(32) // starts as CTR
	if err != nil {
		t.Fatalf("New receiver failed: %v", err)
	}

	err = receiver.UnmarshalKM(km, passphrase)
	if err != nil {
		t.Fatalf("UnmarshalKM failed: %v", err)
	}

	// Receiver should now be in GCM mode
	if receiver.Mode() != CipherGCM {
		t.Error("receiver should have switched to GCM mode")
	}

	// Cross-context encrypt/decrypt should work
	original := []byte("cross-context GCM test payload!!")
	header := makeTestHeader(1, 1, 500, 9999)

	encrypted, err := sender.EncryptPayload(original, header, packet.EncryptionEven, 1)
	if err != nil {
		t.Fatalf("sender encrypt failed: %v", err)
	}

	decrypted, err := receiver.DecryptPayload(encrypted, header, packet.EncryptionEven, 1)
	if err != nil {
		t.Fatalf("receiver decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Errorf("GCM cross-context roundtrip failed:\n  got  %q\n  want %q", decrypted, original)
	}
}

func TestCryptoGCMOddKey(t *testing.T) {
	ctx, err := NewWithMode(24, CipherGCM) // AES-192-GCM
	if err != nil {
		t.Fatalf("NewWithMode failed: %v", err)
	}

	original := []byte("odd key GCM test")
	header := makeTestHeader(100, 5, 2000, 7777)

	encrypted, err := ctx.EncryptPayload(original, header, packet.EncryptionOdd, 100)
	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	decrypted, err := ctx.DecryptPayload(encrypted, header, packet.EncryptionOdd, 100)
	if err != nil {
		t.Fatalf("DecryptPayload failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Error("GCM odd key roundtrip failed")
	}
}

func TestCryptoGCMKeyRotation(t *testing.T) {
	ctx, err := NewWithMode(16, CipherGCM)
	if err != nil {
		t.Fatalf("NewWithMode failed: %v", err)
	}

	original := []byte("pre rotation GCM data")
	header := makeTestHeader(1, 1, 100, 1111)

	enc1, _ := ctx.EncryptPayload(original, header, packet.EncryptionEven, 1)

	// Rotate key
	err = ctx.GenerateSEK(packet.EncryptionEven)
	if err != nil {
		t.Fatalf("GenerateSEK failed: %v", err)
	}

	// Old ciphertext should fail auth with new key
	_, err = ctx.DecryptPayload(enc1, header, packet.EncryptionEven, 1)
	if err != ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed with rotated key, got %v", err)
	}

	// New key should work
	enc2, err := ctx.EncryptPayload(original, header, packet.EncryptionEven, 2)
	if err != nil {
		t.Fatalf("encrypt with new key failed: %v", err)
	}
	dec2, err := ctx.DecryptPayload(enc2, header, packet.EncryptionEven, 2)
	if err != nil {
		t.Fatalf("decrypt with new key failed: %v", err)
	}
	if !bytes.Equal(dec2, original) {
		t.Error("GCM key rotation roundtrip failed")
	}
}

func TestCryptoGCMTooShort(t *testing.T) {
	ctx, err := NewWithMode(16, CipherGCM)
	if err != nil {
		t.Fatalf("NewWithMode failed: %v", err)
	}

	header := makeTestHeader(1, 1, 100, 1111)

	// Data shorter than GCM tag size
	_, err = ctx.DecryptPayload(make([]byte, 10), header, packet.EncryptionEven, 1)
	if err != ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed for short data, got %v", err)
	}
}

func TestCryptoModeSwitch(t *testing.T) {
	ctx, err := New(16) // starts as CTR
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if ctx.Mode() != CipherCTR {
		t.Error("expected CTR mode")
	}

	ctx.SetMode(CipherGCM)
	if ctx.Mode() != CipherGCM {
		t.Error("expected GCM mode after SetMode")
	}

	// Should be able to encrypt/decrypt in GCM mode after switch
	original := []byte("mode switch test")
	header := makeTestHeader(1, 1, 100, 1111)

	encrypted, err := ctx.EncryptPayload(original, header, packet.EncryptionEven, 1)
	if err != nil {
		t.Fatalf("encrypt after mode switch failed: %v", err)
	}

	decrypted, err := ctx.DecryptPayload(encrypted, header, packet.EncryptionEven, 1)
	if err != nil {
		t.Fatalf("decrypt after mode switch failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Error("mode switch roundtrip failed")
	}
}

// --- Benchmarks ---

func BenchmarkEncryptPayloadCTR(b *testing.B) {
	ctx, _ := New(16)
	data := make([]byte, 1316) // typical video packet

	b.ResetTimer()
	for b.Loop() {
		ctx.EncryptPayload(data, nil, packet.EncryptionEven, 42)
	}
}

func BenchmarkEncryptPayloadGCM(b *testing.B) {
	ctx, _ := NewWithMode(16, CipherGCM)
	data := make([]byte, 1316)
	header := makeTestHeader(42, 1, 1000, 5555)

	b.ResetTimer()
	for b.Loop() {
		ctx.EncryptPayload(data, header, packet.EncryptionEven, 42)
	}
}

func BenchmarkDecryptPayloadGCM(b *testing.B) {
	ctx, _ := NewWithMode(16, CipherGCM)
	data := make([]byte, 1316)
	header := makeTestHeader(42, 1, 1000, 5555)
	encrypted, _ := ctx.EncryptPayload(data, header, packet.EncryptionEven, 42)

	b.ResetTimer()
	for b.Loop() {
		ctx.DecryptPayload(encrypted, header, packet.EncryptionEven, 42)
	}
}

func BenchmarkEncryptPayloadCachedVsNew(b *testing.B) {
	ctx, _ := New(16)
	data := make([]byte, 1316)

	b.Run("cached", func(b *testing.B) {
		for b.Loop() {
			ctx.EncryptPayload(data, nil, packet.EncryptionEven, 42)
		}
	})
}

func BenchmarkKeyWrap128(b *testing.B) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	plaintext, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")

	for b.Loop() {
		KeyWrap(kek, plaintext)
	}
}

func BenchmarkKeyUnwrap128(b *testing.B) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	ciphertext, _ := hex.DecodeString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

	for b.Loop() {
		KeyUnwrap(kek, ciphertext)
	}
}

func BenchmarkCalculateKEK(b *testing.B) {
	salt := make([]byte, 16)
	for b.Loop() {
		calculateKEK("test passphrase", salt, 16)
	}
}

// ---- GCM 1.5.3 nonce tests ----

func TestBuildGCMNonceLegacyVsModern(t *testing.T) {
	// The legacy (v1.5.3) and modern (v1.5.4+) GCM nonce formats should
	// produce different output for the same salt and sequence number.
	ctx, err := NewWithMode(16, CipherGCM)
	if err != nil {
		t.Fatal(err)
	}

	salt := ctx.salt
	seqNo := uint32(12345)

	nonceLegacy := ctx.buildGCMNonce(salt, seqNo, true)  // v1.5.3 format
	nonceModern := ctx.buildGCMNonce(salt, seqNo, false) // v1.5.4+ format

	// They should differ (unless salt is trivially all-zero, which is extremely unlikely)
	if nonceLegacy == nonceModern {
		t.Errorf("legacy and modern nonces should differ for same salt/seqNo")
	}
}

func TestBuildGCMNonceModernFormat(t *testing.T) {
	// v1.5.4+ format: nonce[8:12] = seqNo (big-endian), XOR with salt[0:12]
	ctx := &Context{}
	// Use a known salt
	for i := range ctx.salt {
		ctx.salt[i] = byte(i + 1)
	}
	salt := ctx.salt
	seqNo := uint32(0x01020304)

	nonce := ctx.buildGCMNonce(salt, seqNo, false)

	// Compute expected: start with zeros, put seqNo at offset 8, XOR with salt[0:12]
	var expected [GCMNonceSize]byte
	expected[8] = byte(seqNo >> 24)
	expected[9] = byte(seqNo >> 16)
	expected[10] = byte(seqNo >> 8)
	expected[11] = byte(seqNo)
	for i := 0; i < GCMNonceSize; i++ {
		expected[i] ^= salt[i]
	}

	if nonce != expected {
		t.Errorf("modern nonce mismatch:\n  got  %x\n  want %x", nonce, expected)
	}
}

func TestBuildGCMNonceLegacyFormat(t *testing.T) {
	// v1.5.3 format: build 16-byte CTR IV, put seqNo at offset 12,
	// XOR with full salt[0:16], then take bytes [4:16] as the 12-byte nonce.
	ctx := &Context{}
	for i := range ctx.salt {
		ctx.salt[i] = byte(i + 1)
	}
	salt := ctx.salt
	seqNo := uint32(0x01020304)

	nonce := ctx.buildGCMNonce(salt, seqNo, true)

	// Compute expected
	var iv [16]byte
	iv[12] = byte(seqNo >> 24)
	iv[13] = byte(seqNo >> 16)
	iv[14] = byte(seqNo >> 8)
	iv[15] = byte(seqNo)
	for i := 0; i < 16; i++ {
		iv[i] ^= salt[i]
	}
	var expected [GCMNonceSize]byte
	copy(expected[:], iv[4:16])

	if nonce != expected {
		t.Errorf("legacy nonce mismatch:\n  got  %x\n  want %x", nonce, expected)
	}
}

func TestBuildGCMNonceDeterministic(t *testing.T) {
	// Same inputs should always produce the same nonce
	ctx := &Context{}
	for i := range ctx.salt {
		ctx.salt[i] = byte(0xAB)
	}
	salt := ctx.salt
	seqNo := uint32(42)

	n1 := ctx.buildGCMNonce(salt, seqNo, false)
	n2 := ctx.buildGCMNonce(salt, seqNo, false)
	if n1 != n2 {
		t.Errorf("nonce should be deterministic: %x != %x", n1, n2)
	}

	n3 := ctx.buildGCMNonce(salt, seqNo, true)
	n4 := ctx.buildGCMNonce(salt, seqNo, true)
	if n3 != n4 {
		t.Errorf("legacy nonce should be deterministic: %x != %x", n3, n4)
	}
}

func TestGCM153Toggle(t *testing.T) {
	ctx, err := NewWithMode(16, CipherGCM)
	if err != nil {
		t.Fatal(err)
	}

	// Default: useGcm153 should be false
	ctx.mu.RLock()
	if ctx.useGcm153 {
		ctx.mu.RUnlock()
		t.Error("useGcm153 should default to false")
	} else {
		ctx.mu.RUnlock()
	}

	// Toggle on
	ctx.SetGCM153(true)
	ctx.mu.RLock()
	if !ctx.useGcm153 {
		ctx.mu.RUnlock()
		t.Error("useGcm153 should be true after SetGCM153(true)")
	} else {
		ctx.mu.RUnlock()
	}

	// Toggle off
	ctx.SetGCM153(false)
	ctx.mu.RLock()
	if ctx.useGcm153 {
		ctx.mu.RUnlock()
		t.Error("useGcm153 should be false after SetGCM153(false)")
	} else {
		ctx.mu.RUnlock()
	}
}

func TestClearSEKEven(t *testing.T) {
	ctx, err := New(16) // AES-128
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Verify even key works before clearing
	original := []byte("clearSEK test data")
	data := make([]byte, len(original))
	copy(data, original)
	_, err = ctx.EncryptPayload(data, nil, packet.EncryptionEven, 1)
	if err != nil {
		t.Fatalf("EncryptPayload before ClearSEK failed: %v", err)
	}

	// Clear even SEK
	ctx.ClearSEK(packet.EncryptionEven)

	// Verify the SEK is zeroed and nilled
	ctx.mu.RLock()
	if ctx.evenSEK != nil {
		t.Error("evenSEK should be nil after ClearSEK")
	}
	if ctx.evenCipher != nil {
		t.Error("evenCipher should be nil after ClearSEK")
	}
	if ctx.evenAEAD != nil {
		t.Error("evenAEAD should be nil after ClearSEK")
	}
	ctx.mu.RUnlock()

	// Encrypting with cleared key should fail
	data2 := make([]byte, len(original))
	copy(data2, original)
	_, err = ctx.EncryptPayload(data2, nil, packet.EncryptionEven, 2)
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey after ClearSEK, got %v", err)
	}

	// Odd key should still work
	data3 := make([]byte, len(original))
	copy(data3, original)
	_, err = ctx.EncryptPayload(data3, nil, packet.EncryptionOdd, 3)
	if err != nil {
		t.Errorf("odd key should still work after clearing even: %v", err)
	}
}

func TestClearSEKOdd(t *testing.T) {
	ctx, err := New(32) // AES-256
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Clear odd SEK
	ctx.ClearSEK(packet.EncryptionOdd)

	ctx.mu.RLock()
	if ctx.oddSEK != nil {
		t.Error("oddSEK should be nil after ClearSEK")
	}
	if ctx.oddCipher != nil {
		t.Error("oddCipher should be nil after ClearSEK")
	}
	if ctx.oddAEAD != nil {
		t.Error("oddAEAD should be nil after ClearSEK")
	}
	ctx.mu.RUnlock()

	// Encrypting with cleared odd key should fail
	data := []byte("test data")
	_, err = ctx.EncryptPayload(data, nil, packet.EncryptionOdd, 1)
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey after clearing odd key, got %v", err)
	}

	// Even key should still work
	data2 := make([]byte, len(data))
	copy(data2, data)
	_, err = ctx.EncryptPayload(data2, nil, packet.EncryptionEven, 2)
	if err != nil {
		t.Errorf("even key should still work after clearing odd: %v", err)
	}
}

func TestClearSEKGCM(t *testing.T) {
	ctx, err := NewWithMode(16, CipherGCM)
	if err != nil {
		t.Fatalf("NewWithMode failed: %v", err)
	}

	// Verify AEAD is non-nil before clear
	ctx.mu.RLock()
	if ctx.evenAEAD == nil {
		ctx.mu.RUnlock()
		t.Fatal("evenAEAD should be non-nil before ClearSEK")
	}
	ctx.mu.RUnlock()

	ctx.ClearSEK(packet.EncryptionEven)

	ctx.mu.RLock()
	if ctx.evenAEAD != nil {
		ctx.mu.RUnlock()
		t.Error("evenAEAD should be nil after ClearSEK")
	} else {
		ctx.mu.RUnlock()
	}
}

func TestClearSEKZerosBytes(t *testing.T) {
	ctx, err := New(16)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Save a reference to the even SEK to check it was zeroed
	ctx.mu.RLock()
	evenCopy := make([]byte, len(ctx.evenSEK))
	copy(evenCopy, ctx.evenSEK)
	ctx.mu.RUnlock()

	// Verify the SEK is not all zeros before clearing
	allZero := true
	for _, b := range evenCopy {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("SEK should not be all zeros before ClearSEK (extremely unlikely)")
	}

	ctx.ClearSEK(packet.EncryptionEven)

	// evenSEK slice should be nil now
	ctx.mu.RLock()
	if ctx.evenSEK != nil {
		ctx.mu.RUnlock()
		t.Error("evenSEK should be nil after ClearSEK")
	} else {
		ctx.mu.RUnlock()
	}
}

func TestSalt(t *testing.T) {
	ctx, err := New(16)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	salt := ctx.Salt()

	// Salt should not be all zeros (extremely unlikely with random generation)
	allZero := true
	for _, b := range salt {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Salt should not be all zeros")
	}

	// Salt should be consistent across calls
	salt2 := ctx.Salt()
	if salt != salt2 {
		t.Error("Salt should return the same value across calls")
	}
}

func TestKeyLength(t *testing.T) {
	for _, kl := range []int{16, 24, 32} {
		ctx, err := New(kl)
		if err != nil {
			t.Fatalf("New(%d) failed: %v", kl, err)
		}

		got := ctx.KeyLength()
		if got != kl {
			t.Errorf("KeyLength for %d: got %d", kl, got)
		}
	}
}

func TestCipherAndSaltInvalidKey(t *testing.T) {
	ctx, err := New(16)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// EncryptPayload with invalid key type should return error
	data := []byte("test data")
	_, err = ctx.EncryptPayload(data, nil, packet.PacketEncryption(0), 1)
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey for invalid key type, got %v", err)
	}

	// Decrypt too
	_, err = ctx.DecryptPayload(data, nil, packet.PacketEncryption(0), 1)
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey for invalid key type on decrypt, got %v", err)
	}
}

func TestGCMInvalidKeyType(t *testing.T) {
	ctx, err := NewWithMode(16, CipherGCM)
	if err != nil {
		t.Fatalf("NewWithMode failed: %v", err)
	}

	header := makeTestHeader(1, 1, 100, 1111)
	data := []byte("test data")

	// GCM encrypt with invalid key type
	_, err = ctx.EncryptPayload(data, header, packet.PacketEncryption(0), 1)
	if err != ErrInvalidKey {
		t.Errorf("GCM encrypt: expected ErrInvalidKey for invalid key type, got %v", err)
	}

	// GCM decrypt with invalid key type
	_, err = ctx.DecryptPayload(data, header, packet.PacketEncryption(0), 1)
	if err != ErrInvalidKey {
		t.Errorf("GCM decrypt: expected ErrInvalidKey for invalid key type, got %v", err)
	}
}

func TestGCMEncryptNilHeader(t *testing.T) {
	ctx, err := NewWithMode(16, CipherGCM)
	if err != nil {
		t.Fatalf("NewWithMode failed: %v", err)
	}

	original := []byte("test with nil header")

	// Encrypt with nil header (AAD will be nil)
	encrypted, err := ctx.EncryptPayload(original, nil, packet.EncryptionEven, 1)
	if err != nil {
		t.Fatalf("GCM encrypt with nil header failed: %v", err)
	}

	// Decrypt with nil header should succeed
	decrypted, err := ctx.DecryptPayload(encrypted, nil, packet.EncryptionEven, 1)
	if err != nil {
		t.Fatalf("GCM decrypt with nil header failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Errorf("nil header roundtrip failed")
	}
}

func TestGCMEncryptShortHeader(t *testing.T) {
	ctx, err := NewWithMode(16, CipherGCM)
	if err != nil {
		t.Fatalf("NewWithMode failed: %v", err)
	}

	original := []byte("test with short header")
	shortHeader := []byte{1, 2, 3, 4} // less than 16 bytes

	// Encrypt with short header (AAD will be nil)
	encrypted, err := ctx.EncryptPayload(original, shortHeader, packet.EncryptionEven, 1)
	if err != nil {
		t.Fatalf("GCM encrypt with short header failed: %v", err)
	}

	// Decrypt with same short header should succeed
	decrypted, err := ctx.DecryptPayload(encrypted, shortHeader, packet.EncryptionEven, 1)
	if err != nil {
		t.Fatalf("GCM decrypt with short header failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Errorf("short header roundtrip failed")
	}
}

func TestGenerateSEKInvalidKey(t *testing.T) {
	ctx, err := New(16)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	err = ctx.GenerateSEK(packet.PacketEncryption(0))
	if err != ErrInvalidKey {
		t.Errorf("GenerateSEK with invalid key: expected ErrInvalidKey, got %v", err)
	}
}

func TestSetModeSameMode(t *testing.T) {
	ctx, err := New(16) // starts as CTR
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Setting same mode should be a no-op (early return)
	ctx.SetMode(CipherCTR)
	if ctx.Mode() != CipherCTR {
		t.Error("mode should remain CTR")
	}
}

func TestUnmarshalKMOddKey(t *testing.T) {
	passphrase := "odd key test"

	sender, err := New(16)
	if err != nil {
		t.Fatalf("New sender failed: %v", err)
	}

	km := &packet.CIFKeyMaterial{}
	err = sender.MarshalKM(km, passphrase, packet.EncryptionOdd)
	if err != nil {
		t.Fatalf("MarshalKM odd failed: %v", err)
	}

	receiver, err := New(16)
	if err != nil {
		t.Fatalf("New receiver failed: %v", err)
	}

	err = receiver.UnmarshalKM(km, passphrase)
	if err != nil {
		t.Fatalf("UnmarshalKM odd failed: %v", err)
	}

	// Cross-context encrypt/decrypt with odd key
	original := []byte("odd key cross-context test!")
	data := make([]byte, len(original))
	copy(data, original)

	data, err = sender.EncryptPayload(data, nil, packet.EncryptionOdd, 1)
	if err != nil {
		t.Fatalf("sender encrypt odd failed: %v", err)
	}

	data, err = receiver.DecryptPayload(data, nil, packet.EncryptionOdd, 1)
	if err != nil {
		t.Fatalf("receiver decrypt odd failed: %v", err)
	}

	if !bytes.Equal(data, original) {
		t.Error("odd key cross-context roundtrip failed")
	}
}

func TestUnmarshalKMNoneKey(t *testing.T) {
	ctx, err := New(16)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	km := &packet.CIFKeyMaterial{
		KeyBasedEncryption: packet.EncryptionNone,
	}
	err = ctx.UnmarshalKM(km, "passphrase")
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey for EncryptionNone, got %v", err)
	}
}

func TestMarshalKMNoneKey(t *testing.T) {
	ctx, err := New(16)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	km := &packet.CIFKeyMaterial{}
	err = ctx.MarshalKM(km, "passphrase", packet.EncryptionNone)
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey for EncryptionNone, got %v", err)
	}
}

// helper to create a 16-byte header for AAD testing
func makeTestHeader(seqNo, msgNo, ts, socketID uint32) []byte {
	var buf [16]byte
	buf[0] = byte(seqNo >> 24)
	buf[1] = byte(seqNo >> 16)
	buf[2] = byte(seqNo >> 8)
	buf[3] = byte(seqNo)
	buf[4] = byte(msgNo >> 24)
	buf[5] = byte(msgNo >> 16)
	buf[6] = byte(msgNo >> 8)
	buf[7] = byte(msgNo)
	buf[8] = byte(ts >> 24)
	buf[9] = byte(ts >> 16)
	buf[10] = byte(ts >> 8)
	buf[11] = byte(ts)
	buf[12] = byte(socketID >> 24)
	buf[13] = byte(socketID >> 16)
	buf[14] = byte(socketID >> 8)
	buf[15] = byte(socketID)
	return buf[:]
}
