package packet

import (
	"encoding/binary"
	"fmt"
	"net"
)

// HeaderSize is the fixed size of an SRT packet header in bytes.
const HeaderSize = 16

// CtrlType represents SRT control packet types (Table 1 in the SRT RFC).
type CtrlType uint16

const (
	CtrlTypeHandshake CtrlType = 0x0000
	CtrlTypeKeepalive CtrlType = 0x0001
	CtrlTypeACK       CtrlType = 0x0002
	CtrlTypeNAK       CtrlType = 0x0003
	CtrlTypeWarn      CtrlType = 0x0004 // unused
	CtrlTypeShutdown  CtrlType = 0x0005
	CtrlTypeACKACK    CtrlType = 0x0006
	CtrlTypeDropReq   CtrlType = 0x0007 // unused
	CtrlTypePeerError CtrlType = 0x0008 // unused
	CtrlTypeUser      CtrlType = 0x7FFF
)

func (c CtrlType) String() string {
	switch c {
	case CtrlTypeHandshake:
		return "HANDSHAKE"
	case CtrlTypeKeepalive:
		return "KEEPALIVE"
	case CtrlTypeACK:
		return "ACK"
	case CtrlTypeNAK:
		return "NAK"
	case CtrlTypeShutdown:
		return "SHUTDOWN"
	case CtrlTypeACKACK:
		return "ACKACK"
	case CtrlTypeDropReq:
		return "DROPREQ"
	case CtrlTypeUser:
		return "USER"
	default:
		return fmt.Sprintf("CTRL(%d)", c)
	}
}

// SubType represents extension types for handshake packets (Table 5).
type SubType uint16

const (
	SubTypeNone       SubType = 0
	ExtTypeHSReq      SubType = 1
	ExtTypeHSRsp      SubType = 2
	ExtTypeKMReq      SubType = 3
	ExtTypeKMRsp      SubType = 4
	ExtTypeSID        SubType = 5
	ExtTypeCongestion SubType = 6
	ExtTypeFilter     SubType = 7
	ExtTypeGroup      SubType = 8
)

func (s SubType) String() string {
	switch s {
	case SubTypeNone:
		return "NONE"
	case ExtTypeHSReq:
		return "HSREQ"
	case ExtTypeHSRsp:
		return "HSRSP"
	case ExtTypeKMReq:
		return "KMREQ"
	case ExtTypeKMRsp:
		return "KMRSP"
	case ExtTypeSID:
		return "SID"
	case ExtTypeCongestion:
		return "CONGESTION"
	case ExtTypeFilter:
		return "FILTER"
	case ExtTypeGroup:
		return "GROUP"
	default:
		return fmt.Sprintf("EXT(%d)", s)
	}
}

// PacketPosition indicates the position of a data packet within a message.
type PacketPosition uint8

const (
	PositionMiddle PacketPosition = 0b00
	PositionLast   PacketPosition = 0b01
	PositionFirst  PacketPosition = 0b10
	PositionSingle PacketPosition = 0b11
)

// PacketEncryption indicates the encryption status of a data packet.
type PacketEncryption uint8

const (
	EncryptionNone PacketEncryption = 0b00
	EncryptionEven PacketEncryption = 0b01
	EncryptionOdd  PacketEncryption = 0b10
	EncryptionBoth PacketEncryption = 0b11 // only in control packets
)

// Header is the 16-byte SRT packet header.
//
// SRT packets are either control or data packets, distinguished by the
// highest bit of the first 32-bit word.
type Header struct {
	Addr net.Addr

	IsControl bool

	// Control packet fields (valid when IsControl == true)
	ControlType  CtrlType
	SubType      SubType
	TypeSpecific uint32

	// Data packet fields (valid when IsControl == false)
	SequenceNumber uint32         // 31-bit sequence number
	PacketPosition PacketPosition // position within message
	Order          bool           // in-order delivery flag
	Encryption     PacketEncryption
	Retransmitted  bool
	MessageNumber  uint32 // 26-bit message number

	// Common fields
	Timestamp           uint32
	DestinationSocketID uint32
}

// Marshal writes the 16-byte header to buf. buf must be at least 16 bytes.
func (h *Header) Marshal(buf []byte) {
	_ = buf[15] // bounds check hint

	if h.IsControl {
		binary.BigEndian.PutUint16(buf[0:], uint16(h.ControlType)|0x8000)
		binary.BigEndian.PutUint16(buf[2:], uint16(h.SubType))
		binary.BigEndian.PutUint32(buf[4:], h.TypeSpecific)
	} else {
		binary.BigEndian.PutUint32(buf[0:], h.SequenceNumber&0x7FFFFFFF)

		var field uint32
		field |= uint32(h.PacketPosition&0b11) << 30
		if h.Order {
			field |= 1 << 29
		}
		field |= uint32(h.Encryption&0b11) << 27
		if h.Retransmitted {
			field |= 1 << 26
		}
		field |= h.MessageNumber & 0x03FFFFFF
		binary.BigEndian.PutUint32(buf[4:], field)
	}

	binary.BigEndian.PutUint32(buf[8:], h.Timestamp)
	binary.BigEndian.PutUint32(buf[12:], h.DestinationSocketID)
}

// Unmarshal parses a 16-byte header from buf. buf must be at least 16 bytes.
func (h *Header) Unmarshal(buf []byte) error {
	if len(buf) < HeaderSize {
		return fmt.Errorf("packet: header too short (%d bytes)", len(buf))
	}

	h.IsControl = (buf[0] & 0x80) != 0

	if h.IsControl {
		h.ControlType = CtrlType(binary.BigEndian.Uint16(buf[0:]) & 0x7FFF)
		h.SubType = SubType(binary.BigEndian.Uint16(buf[2:]))
		h.TypeSpecific = binary.BigEndian.Uint32(buf[4:])
	} else {
		h.SequenceNumber = binary.BigEndian.Uint32(buf[0:]) & 0x7FFFFFFF
		field := binary.BigEndian.Uint32(buf[4:])
		h.PacketPosition = PacketPosition((field >> 30) & 0b11)
		h.Order = (field>>29)&1 != 0
		h.Encryption = PacketEncryption((field >> 27) & 0b11)
		h.Retransmitted = (field>>26)&1 != 0
		h.MessageNumber = field & 0x03FFFFFF
	}

	h.Timestamp = binary.BigEndian.Uint32(buf[8:])
	h.DestinationSocketID = binary.BigEndian.Uint32(buf[12:])

	return nil
}
