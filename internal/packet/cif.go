package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// HandshakeType represents the type of handshake message (Table 4).
type HandshakeType uint32

const (
	HandshakeTypeDone       HandshakeType = 0xFFFFFFFD
	HandshakeTypeAgreement  HandshakeType = 0xFFFFFFFE
	HandshakeTypeConclusion HandshakeType = 0xFFFFFFFF
	HandshakeTypeWavehand   HandshakeType = 0x00000000
	HandshakeTypeInduction  HandshakeType = 0x00000001
)

func (h HandshakeType) String() string {
	switch h {
	case HandshakeTypeDone:
		return "DONE"
	case HandshakeTypeAgreement:
		return "AGREEMENT"
	case HandshakeTypeConclusion:
		return "CONCLUSION"
	case HandshakeTypeWavehand:
		return "WAVEHAND"
	case HandshakeTypeInduction:
		return "INDUCTION"
	default:
		return fmt.Sprintf("REJECT(%d)", h)
	}
}

// IsHandshake returns true if this is a valid handshake type (not a rejection).
func (h HandshakeType) IsHandshake() bool {
	switch h {
	case HandshakeTypeDone, HandshakeTypeAgreement, HandshakeTypeConclusion,
		HandshakeTypeWavehand, HandshakeTypeInduction:
		return true
	}
	return false
}

// IsRejection returns true if this handshake type indicates a rejection.
func (h HandshakeType) IsRejection() bool {
	return !h.IsHandshake()
}

// Handshake Extension Message Flags (Table 6).
const (
	FlagTSBPDSend    uint32 = 1 << 0
	FlagTSBPDRecv    uint32 = 1 << 1
	FlagCrypt        uint32 = 1 << 2
	FlagTLPktDrop    uint32 = 1 << 3
	FlagPeriodicNAK  uint32 = 1 << 4
	FlagRexmit       uint32 = 1 << 5
	FlagStream       uint32 = 1 << 6
	FlagPacketFilter uint32 = 1 << 7
)

// CIFHandshake is the Control Information Field for handshake packets.
type CIFHandshake struct {
	Version         uint32
	EncryptionField uint16 // cipher family: 0=none, 2=AES-128, 3=AES-192, 4=AES-256
	ExtensionField  uint16

	InitialPacketSequenceNumber uint32
	MaxTransmissionUnitSize     uint32
	MaxFlowWindowSize           uint32
	HandshakeType               HandshakeType
	SRTSocketID                 uint32
	SynCookie                   uint32
	PeerIP                      net.IP // 16 bytes (IPv4 in first 4, rest zero)

	// Extension fields (SRT v5, CONCLUSION only)
	IsRequest bool // true=request (HSREQ/KMREQ), false=response (HSRSP/KMRSP)

	HasHS bool
	SRTHS *CIFHandshakeExtension

	HasKM bool
	SRTKM *CIFKeyMaterial

	HasSID   bool
	StreamID string

	HasCongestion  bool
	CongestionType string // "live" or "file"

	HasFilter    bool
	FilterConfig string // e.g., "fec,cols:10,rows:5,layout:staircase,arq:onreq"

	// Group extension (ExtTypeGroup) — for connection bonding
	HasGroup    bool
	GroupID     uint32 // peer's group ID
	GroupType   uint8  // 1=broadcast, 2=backup
	GroupFlags  uint8  // reserved
	GroupWeight uint16 // member weight (0 = default)
}

func (c *CIFHandshake) MarshalCIF() ([]byte, error) {
	if c.StreamID == "" {
		c.HasSID = false
	}

	// Compute extension field for v5
	if c.Version == 5 && c.HandshakeType == HandshakeTypeConclusion {
		c.ExtensionField = 0
		if c.HasHS {
			c.ExtensionField |= 1
		}
		if c.HasKM {
			c.ExtensionField |= 2
		}
		if c.HasSID || c.HasCongestion || c.HasFilter || c.HasGroup {
			c.ExtensionField |= 4 // HS_EXT_CONFIG: SID, congestion, filter, or group
		}
	} else if c.Version == 4 {
		c.EncryptionField = 0
		c.ExtensionField = 2
	}

	// Base handshake is 48 bytes
	buf := make([]byte, 48, 256)

	binary.BigEndian.PutUint32(buf[0:], c.Version)
	binary.BigEndian.PutUint16(buf[4:], c.EncryptionField)
	binary.BigEndian.PutUint16(buf[6:], c.ExtensionField)
	binary.BigEndian.PutUint32(buf[8:], c.InitialPacketSequenceNumber&0x7FFFFFFF)
	binary.BigEndian.PutUint32(buf[12:], c.MaxTransmissionUnitSize)
	binary.BigEndian.PutUint32(buf[16:], c.MaxFlowWindowSize)
	binary.BigEndian.PutUint32(buf[20:], uint32(c.HandshakeType))
	binary.BigEndian.PutUint32(buf[24:], c.SRTSocketID)
	binary.BigEndian.PutUint32(buf[28:], c.SynCookie)

	// PeerIP: 16 bytes (IPv4 in first 4, rest zero)
	marshalIP(buf[32:48], c.PeerIP)

	// Extension data
	if c.HasHS {
		hsData, err := c.SRTHS.MarshalCIF()
		if err != nil {
			return nil, fmt.Errorf("handshake extension: %w", err)
		}
		extType := ExtTypeHSReq
		if !c.IsRequest {
			extType = ExtTypeHSRsp
		}
		buf = appendExtension(buf, extType, hsData)
	}

	if c.HasSID {
		sidData := marshalStreamID(c.StreamID)
		buf = appendExtension(buf, ExtTypeSID, sidData)
	}

	if c.HasCongestion {
		ccData := marshalStreamID(c.CongestionType)
		buf = appendExtension(buf, ExtTypeCongestion, ccData)
	}

	if c.HasFilter && c.FilterConfig != "" {
		filterData := marshalStreamID(c.FilterConfig)
		buf = appendExtension(buf, ExtTypeFilter, filterData)
	}

	if c.HasGroup && c.GroupID != 0 {
		// Group extension: 2 uint32s (8 bytes)
		// Word 0: GroupID
		// Word 1: GroupType<<24 | GroupFlags<<16 | GroupWeight
		grpData := make([]byte, 8)
		binary.BigEndian.PutUint32(grpData[0:], c.GroupID)
		dataword := uint32(c.GroupType)<<24 | uint32(c.GroupFlags)<<16 | uint32(c.GroupWeight)
		binary.BigEndian.PutUint32(grpData[4:], dataword)
		buf = appendExtension(buf, ExtTypeGroup, grpData)
	}

	// KMREQ/KMRSP must be last per SRT extension ordering
	if c.HasKM {
		kmData, err := c.SRTKM.MarshalCIF()
		if err != nil {
			return nil, fmt.Errorf("key material extension: %w", err)
		}
		extType := ExtTypeKMReq
		if !c.IsRequest {
			extType = ExtTypeKMRsp
		}
		buf = appendExtension(buf, extType, kmData)
	}

	return buf, nil
}

func (c *CIFHandshake) UnmarshalCIF(data []byte) error {
	if len(data) < 48 {
		return fmt.Errorf("packet: handshake CIF too short (%d bytes)", len(data))
	}

	c.Version = binary.BigEndian.Uint32(data[0:])
	c.EncryptionField = binary.BigEndian.Uint16(data[4:])
	c.ExtensionField = binary.BigEndian.Uint16(data[6:])
	c.InitialPacketSequenceNumber = binary.BigEndian.Uint32(data[8:]) & 0x7FFFFFFF
	c.MaxTransmissionUnitSize = binary.BigEndian.Uint32(data[12:])
	c.MaxFlowWindowSize = binary.BigEndian.Uint32(data[16:])
	c.HandshakeType = HandshakeType(binary.BigEndian.Uint32(data[20:]))
	c.SRTSocketID = binary.BigEndian.Uint32(data[24:])
	c.SynCookie = binary.BigEndian.Uint32(data[28:])
	c.PeerIP = unmarshalIP(data[32:48])

	if c.HandshakeType == HandshakeTypeInduction {
		return nil
	}

	if c.HandshakeType != HandshakeTypeConclusion {
		return nil
	}

	if c.ExtensionField == 0 || len(data) <= 48 {
		return nil
	}

	// Validate encryption field
	switch c.EncryptionField {
	case 0, 2, 3, 4:
	default:
		return fmt.Errorf("packet: invalid encryption field (%d)", c.EncryptionField)
	}

	// Parse extensions. Track seen types to detect duplicates.
	pivot := data[48:]
	var seenExt uint32 // bitmask of seen extension types
	for len(pivot) >= 4 {
		extType := SubType(binary.BigEndian.Uint16(pivot[0:]))
		extLen := int(binary.BigEndian.Uint16(pivot[2:])) * 4
		pivot = pivot[4:]

		if len(pivot) < extLen {
			return fmt.Errorf("packet: extension %s truncated (%d < %d)", extType, len(pivot), extLen)
		}

		// Reject duplicate extension blocks.
		extBit := uint32(1) << (uint(extType) & 31)
		if seenExt&extBit != 0 {
			return fmt.Errorf("packet: duplicate extension type %d", extType)
		}
		seenExt |= extBit

		extData := pivot[:extLen]

		switch extType {
		case ExtTypeHSReq, ExtTypeHSRsp:
			if extLen != 12 {
				return fmt.Errorf("packet: HS extension wrong length (%d)", extLen)
			}
			c.HasHS = true
			c.IsRequest = (extType == ExtTypeHSReq)
			c.SRTHS = &CIFHandshakeExtension{}
			if err := c.SRTHS.UnmarshalCIF(extData); err != nil {
				return fmt.Errorf("packet: HS extension: %w", err)
			}

		case ExtTypeKMReq, ExtTypeKMRsp:
			c.HasKM = true
			c.IsRequest = (extType == ExtTypeKMReq)
			c.SRTKM = &CIFKeyMaterial{}
			if err := c.SRTKM.UnmarshalCIF(extData); err != nil {
				return fmt.Errorf("packet: KM extension: %w", err)
			}

		case ExtTypeSID:
			if extLen > 512 {
				return fmt.Errorf("packet: stream ID too long (%d)", extLen)
			}
			c.HasSID = true
			c.StreamID = unmarshalStreamID(extData)

		case ExtTypeCongestion:
			c.HasCongestion = true
			c.CongestionType = unmarshalStreamID(extData)

		case ExtTypeFilter:
			c.HasFilter = true
			c.FilterConfig = unmarshalStreamID(extData)

		case ExtTypeGroup:
			if extLen >= 8 {
				c.HasGroup = true
				c.GroupID = binary.BigEndian.Uint32(extData[0:])
				dataword := binary.BigEndian.Uint32(extData[4:])
				c.GroupType = uint8(dataword >> 24)
				c.GroupFlags = uint8(dataword >> 16)
				c.GroupWeight = uint16(dataword)
			}

		default:
			// Unknown or unimplemented extension — skip for forward compatibility
		}

		if len(pivot) > extLen {
			pivot = pivot[extLen:]
		} else {
			break
		}
	}

	return nil
}

// CIFHandshakeExtension is the SRT Handshake Extension (HSREQ/HSRSP).
type CIFHandshakeExtension struct {
	SRTVersion     uint32
	SRTFlags       uint32
	RecvTSBPDDelay uint16 // milliseconds
	SendTSBPDDelay uint16 // milliseconds
}

func (c *CIFHandshakeExtension) MarshalCIF() ([]byte, error) {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:], c.SRTVersion)
	binary.BigEndian.PutUint32(buf[4:], c.SRTFlags)
	binary.BigEndian.PutUint16(buf[8:], c.RecvTSBPDDelay)
	binary.BigEndian.PutUint16(buf[10:], c.SendTSBPDDelay)
	return buf, nil
}

func (c *CIFHandshakeExtension) UnmarshalCIF(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("hs extension too short (%d bytes)", len(data))
	}
	c.SRTVersion = binary.BigEndian.Uint32(data[0:])
	c.SRTFlags = binary.BigEndian.Uint32(data[4:])
	c.RecvTSBPDDelay = binary.BigEndian.Uint16(data[8:])
	c.SendTSBPDDelay = binary.BigEndian.Uint16(data[10:])
	return nil
}

// CIFKeyMaterial is the Key Material Extension (KMREQ/KMRSP).
type CIFKeyMaterial struct {
	Error                 uint32
	S                     uint8
	Version               uint8
	PacketType            uint8
	Sign                  uint16
	KeyBasedEncryption    PacketEncryption
	KeyEncryptionKeyIndex uint32
	Cipher                uint8
	Authentication        uint8
	StreamEncapsulation   uint8
	SLen                  uint16 // salt length in bytes
	KLen                  uint16 // key length in bytes
	Salt                  []byte
	Wrap                  []byte
}

func (c *CIFKeyMaterial) MarshalCIF() ([]byte, error) {
	// Handle error response
	if c.Error != 0 {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, c.Error)
		return buf, nil
	}

	size := 16 + int(c.SLen) + len(c.Wrap)
	buf := make([]byte, size)

	b := byte(0)
	b |= (c.S << 7) & 0x80
	b |= (c.Version << 4) & 0x70
	b |= c.PacketType & 0x0F
	buf[0] = b

	binary.BigEndian.PutUint16(buf[1:], c.Sign)

	b = 0
	b |= uint8(c.KeyBasedEncryption) & 0x03
	buf[3] = b

	binary.BigEndian.PutUint32(buf[4:], c.KeyEncryptionKeyIndex)
	buf[8] = c.Cipher
	buf[9] = c.Authentication
	buf[10] = c.StreamEncapsulation
	buf[11] = 0                             // Resv2
	binary.BigEndian.PutUint16(buf[12:], 0) // Resv3
	buf[14] = byte(c.SLen / 4)
	buf[15] = byte(c.KLen / 4)

	offset := 16
	if c.SLen > 0 {
		copy(buf[offset:], c.Salt)
		offset += int(c.SLen)
	}
	copy(buf[offset:], c.Wrap)

	return buf, nil
}

func (c *CIFKeyMaterial) UnmarshalCIF(data []byte) error {
	if len(data) == 4 {
		// Error response
		c.Error = binary.BigEndian.Uint32(data[0:])
		return nil
	}

	if len(data) < 16 {
		return fmt.Errorf("km extension too short (%d bytes)", len(data))
	}

	c.S = (data[0] >> 7) & 0x01
	c.Version = (data[0] >> 4) & 0x07
	c.PacketType = data[0] & 0x0F

	if c.Version != 1 {
		return fmt.Errorf("km: invalid version (%d)", c.Version)
	}
	if c.PacketType != 2 {
		return fmt.Errorf("km: invalid packet type (%d)", c.PacketType)
	}

	c.Sign = binary.BigEndian.Uint16(data[1:])
	if c.Sign != 0x2029 {
		return fmt.Errorf("km: invalid signature (0x%04X)", c.Sign)
	}

	c.KeyBasedEncryption = PacketEncryption(data[3] & 0x03)

	// Key flags must be non-zero (at least one SEK indicated).
	if c.KeyBasedEncryption == EncryptionNone {
		return fmt.Errorf("km: no key indicated (KF=0)")
	}

	c.KeyEncryptionKeyIndex = binary.BigEndian.Uint32(data[4:])
	c.Cipher = data[8]
	c.Authentication = data[9]
	c.StreamEncapsulation = data[10]

	// Cipher must be AES-CTR(2) or AES-GCM(4).
	switch c.Cipher {
	case 2, 4: // AES-CTR, AES-GCM
	default:
		return fmt.Errorf("km: unsupported cipher (%d)", c.Cipher)
	}

	// Auth/cipher consistency check:
	// GCM cipher requires GCM auth (1); CTR cipher requires no auth (0)
	if c.Cipher == 4 && c.Authentication != 1 {
		return fmt.Errorf("km: GCM cipher requires GCM auth, got auth=%d", c.Authentication)
	}
	if c.Cipher == 2 && c.Authentication != 0 {
		return fmt.Errorf("km: CTR cipher requires no auth, got auth=%d", c.Authentication)
	}

	// SE must be HCRYPT_SE_TSSRT (2).
	if c.StreamEncapsulation != 2 {
		return fmt.Errorf("km: invalid stream encapsulation (%d)", c.StreamEncapsulation)
	}

	c.SLen = uint16(data[14]) * 4
	c.KLen = uint16(data[15]) * 4

	switch c.KLen {
	case 16, 24, 32:
	default:
		return fmt.Errorf("km: invalid key length (%d)", c.KLen)
	}

	offset := 16

	if c.SLen > 0 {
		if c.SLen != 16 {
			return fmt.Errorf("km: invalid salt length (%d)", c.SLen)
		}
		if len(data[offset:]) < int(c.SLen) {
			return fmt.Errorf("km: data too short for salt")
		}
		c.Salt = make([]byte, c.SLen)
		copy(c.Salt, data[offset:])
		offset += int(c.SLen)
	}

	// Wrap: 8 + n*KLen bytes, where n = number of keys
	n := 1
	if c.KeyBasedEncryption == EncryptionBoth {
		n = 2
	}
	wrapLen := n*int(c.KLen) + 8
	if len(data[offset:]) < wrapLen {
		return fmt.Errorf("km: data too short for wrapped key(s)")
	}

	// Total length consistency check.
	// Expected: 16 (header) + SLen + n*KLen + 8 (wrap signature)
	expectedLen := 16 + int(c.SLen) + wrapLen
	if len(data) != expectedLen {
		return fmt.Errorf("km: length inconsistent (got %d, expected %d)", len(data), expectedLen)
	}

	c.Wrap = make([]byte, wrapLen)
	copy(c.Wrap, data[offset:])

	return nil
}

// ---- Helpers ----

func appendExtension(buf []byte, extType SubType, data []byte) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:], uint16(extType))
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(data)/4))
	buf = append(buf, hdr[:]...)
	buf = append(buf, data...)
	return buf
}

// marshalIP writes an IP address into the 16-byte SRT handshake format.
func marshalIP(buf []byte, ip net.IP) {
	_ = buf[15]
	for i := range buf[:16] {
		buf[i] = 0
	}
	if ip == nil {
		return
	}
	ip4 := ip.To4()
	if ip4 != nil {
		copy(buf[0:4], ip4)
	} else {
		copy(buf[0:16], ip.To16())
	}
}

// unmarshalIP reads an IP from the 16-byte SRT handshake format.
func unmarshalIP(data []byte) net.IP {
	_ = data[15]
	// Check if it's IPv4 (bytes 4-15 are zero)
	allZero := true
	for _, b := range data[4:16] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return net.IP(append([]byte{}, data[0:4]...))
	}
	return net.IP(append([]byte{}, data[0:16]...))
}

// marshalStreamID encodes a stream ID with the SRT 4-byte word reversal.
func marshalStreamID(sid string) []byte {
	data := []byte(sid)
	// Pad to multiple of 4
	if rem := len(data) % 4; rem != 0 {
		data = append(data, make([]byte, 4-rem)...)
	}
	// Reverse bytes within each 4-byte word
	for i := 0; i < len(data); i += 4 {
		data[i+0], data[i+3] = data[i+3], data[i+0]
		data[i+1], data[i+2] = data[i+2], data[i+1]
	}
	return data
}

// unmarshalStreamID decodes a stream ID from SRT 4-byte word reversal.
func unmarshalStreamID(data []byte) string {
	var b strings.Builder
	b.Grow(len(data))
	for i := 0; i+3 < len(data); i += 4 {
		b.WriteByte(data[i+3])
		b.WriteByte(data[i+2])
		b.WriteByte(data[i+1])
		b.WriteByte(data[i+0])
	}
	return strings.TrimRight(b.String(), "\x00")
}
