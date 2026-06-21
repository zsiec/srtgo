// Package packet implements SRT packet parsing, serialization, and pooling.
//
// Packets are concrete structs (not interfaces) for zero-vtable-overhead
// on the hot path. Packet buffers are managed via sync.Pool to minimize
// GC pressure.
package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// WireHeaderSize is the combined IP + UDP + SRT header overhead per packet (20 + 8 + 16).
const WireHeaderSize = 44

// MaxPayloadSize is the default maximum payload size (MTU 1500 - WireHeaderSize).
const MaxPayloadSize = 1456

// bufferPool is a pool of byte slices for packet payloads.
var bufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, MaxPayloadSize+HeaderSize)
		return &buf
	},
}

// getBuffer retrieves a buffer from the pool.
func getBuffer() []byte {
	bp := bufferPool.Get().(*[]byte)
	return (*bp)[:0]
}

// putBuffer returns a buffer to the pool.
func putBuffer(buf []byte) {
	if cap(buf) < MaxPayloadSize {
		return // don't pool undersized buffers
	}
	buf = buf[:0]
	bufferPool.Put(&buf)
}

// Packet is an SRT packet consisting of a header and payload data.
// Use New or Parse to create packets; call Release when done.
type Packet struct {
	Header Header

	// Data is the packet payload. For data packets this is the media content.
	// For control packets this is the Control Information Field (CIF).
	Data []byte

	// pooled is the underlying pooled buffer backing Data.
	// If nil, Data is not pooled (e.g. user-provided buffer).
	pooled []byte
}

// New creates a new empty packet addressed to addr.
func New(addr net.Addr) Packet {
	buf := getBuffer()
	return Packet{
		Header: Header{Addr: addr},
		Data:   buf,
		pooled: buf,
	}
}

// NewControl creates a new control packet of the given type.
func NewControl(addr net.Addr, ctrlType CtrlType, destSocketID uint32, timestamp uint32) Packet {
	p := New(addr)
	p.Header.IsControl = true
	p.Header.ControlType = ctrlType
	p.Header.DestinationSocketID = destSocketID
	p.Header.Timestamp = timestamp
	return p
}

// NewData creates a new data packet with the given sequence number and payload.
func NewData(addr net.Addr, seqNo uint32, timestamp uint32, destSocketID uint32, payload []byte) Packet {
	buf := getBuffer()
	buf = append(buf, payload...)
	return Packet{
		Header: Header{
			Addr:                addr,
			SequenceNumber:      seqNo,
			Timestamp:           timestamp,
			DestinationSocketID: destSocketID,
			PacketPosition:      PositionSingle,
			MessageNumber:       1,
		},
		Data:   buf,
		pooled: buf,
	}
}

// Parse parses an SRT packet from raw bytes received from addr.
// The data is copied into a pooled buffer.
func Parse(rawdata []byte, addr net.Addr) (Packet, error) {
	if len(rawdata) < HeaderSize {
		return Packet{}, fmt.Errorf("packet: data too short (%d bytes)", len(rawdata))
	}

	var p Packet
	p.Header.Addr = addr

	if err := p.Header.Unmarshal(rawdata[:HeaderSize]); err != nil {
		return Packet{}, err
	}

	payload := rawdata[HeaderSize:]
	if len(payload) > 0 {
		buf := getBuffer()
		buf = append(buf, payload...)
		p.Data = buf
		p.pooled = buf
	}

	return p, nil
}

// Marshal serializes the packet into buf and returns the number of bytes written.
// buf must be at least HeaderSize + len(Data) bytes.
func (p *Packet) Marshal(buf []byte) (int, error) {
	needed := HeaderSize + len(p.Data)
	if len(buf) < needed {
		return 0, fmt.Errorf("packet: buffer too small (%d < %d)", len(buf), needed)
	}

	p.Header.Marshal(buf[:HeaderSize])
	copy(buf[HeaderSize:], p.Data)

	return needed, nil
}

// MarshalTo serializes the packet, allocating a new buffer.
func (p *Packet) MarshalTo() ([]byte, error) {
	buf := make([]byte, HeaderSize+len(p.Data))
	_, err := p.Marshal(buf)
	return buf, err
}

// Release returns the packet's pooled buffer (if any) to the pool.
// The packet must not be used after calling Release.
func (p *Packet) Release() {
	if p.pooled != nil {
		putBuffer(p.pooled)
		p.pooled = nil
		p.Data = nil
	}
}

// Clone creates a deep copy of the packet with its own pooled buffer.
func (p *Packet) Clone() Packet {
	buf := getBuffer()
	buf = append(buf, p.Data...)
	return Packet{
		Header: p.Header,
		Data:   buf,
		pooled: buf,
	}
}

// SetData replaces the packet payload with the given data.
func (p *Packet) SetData(data []byte) {
	if p.pooled != nil {
		p.pooled = p.pooled[:0]
		p.pooled = append(p.pooled, data...)
		p.Data = p.pooled
	} else {
		buf := getBuffer()
		buf = append(buf, data...)
		p.Data = buf
		p.pooled = buf
	}
}

// Len returns the length of the packet payload.
func (p *Packet) Len() int {
	return len(p.Data)
}

// MarshalCIF serializes a CIF into the packet's payload.
func (p *Packet) MarshalCIF(c CIF) error {
	data, err := c.MarshalCIF()
	if err != nil {
		return err
	}
	p.SetData(data)
	return nil
}

// UnmarshalCIF parses the packet's payload into a CIF.
func (p *Packet) UnmarshalCIF(c CIF) error {
	return c.UnmarshalCIF(p.Data)
}

// CIF is the interface for Control Information Fields.
type CIF interface {
	MarshalCIF() ([]byte, error)
	UnmarshalCIF(data []byte) error
}

// ---- ACK CIF ----

// CIFACK represents an ACK Control Information Field (Section 3.2.3).
type CIFACK struct {
	LastACKPacketSequenceNumber uint32
	RTT                         uint32 // microseconds
	RTTVariance                 uint32 // microseconds
	AvailableBufferSize         uint32 // packets
	PacketsReceivingRate        uint32 // packets/sec
	EstimatedLinkCapacity       uint32 // packets/sec
	ReceivingRate               uint32 // bytes/sec
}

func (c *CIFACK) MarshalCIF() ([]byte, error) {
	buf := make([]byte, 28)
	binary.BigEndian.PutUint32(buf[0:], c.LastACKPacketSequenceNumber)
	binary.BigEndian.PutUint32(buf[4:], c.RTT)
	binary.BigEndian.PutUint32(buf[8:], c.RTTVariance)
	binary.BigEndian.PutUint32(buf[12:], c.AvailableBufferSize)
	binary.BigEndian.PutUint32(buf[16:], c.PacketsReceivingRate)
	binary.BigEndian.PutUint32(buf[20:], c.EstimatedLinkCapacity)
	binary.BigEndian.PutUint32(buf[24:], c.ReceivingRate)
	return buf, nil
}

// MarshalSmallCIF marshals only the first 4 fields (16 bytes) for a Small ACK.
// seq, RTT, RTTVar, AvailableBufferSize. Extended fields (speed, BW, rate)
// are only included in Full ACK (sent every 10ms).
func (c *CIFACK) MarshalSmallCIF() ([]byte, error) {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint32(buf[0:], c.LastACKPacketSequenceNumber)
	binary.BigEndian.PutUint32(buf[4:], c.RTT)
	binary.BigEndian.PutUint32(buf[8:], c.RTTVariance)
	binary.BigEndian.PutUint32(buf[12:], c.AvailableBufferSize)
	return buf, nil
}

// MarshalUDTBaseCIF marshals the first 6 fields (24 bytes) for pre-v1.0.3 peers.
func (c *CIFACK) MarshalUDTBaseCIF() ([]byte, error) {
	buf := make([]byte, 24)
	binary.BigEndian.PutUint32(buf[0:], c.LastACKPacketSequenceNumber)
	binary.BigEndian.PutUint32(buf[4:], c.RTT)
	binary.BigEndian.PutUint32(buf[8:], c.RTTVariance)
	binary.BigEndian.PutUint32(buf[12:], c.AvailableBufferSize)
	binary.BigEndian.PutUint32(buf[16:], c.PacketsReceivingRate)
	binary.BigEndian.PutUint32(buf[20:], c.EstimatedLinkCapacity)
	return buf, nil
}

// MarshalV102CIF marshals all 8 fields (32 bytes) for v1.0.2 peers.
// Includes the extra XMRATE field.
// The 8th field is ReceivingRate (same as 7th in current layout) followed by XMRATE.
// XMRATE = bandwidth * payloadSize (transmission rate), stored at offset 28.
func (c *CIFACK) MarshalV102CIF(xmRate uint32) ([]byte, error) {
	buf := make([]byte, 32)
	binary.BigEndian.PutUint32(buf[0:], c.LastACKPacketSequenceNumber)
	binary.BigEndian.PutUint32(buf[4:], c.RTT)
	binary.BigEndian.PutUint32(buf[8:], c.RTTVariance)
	binary.BigEndian.PutUint32(buf[12:], c.AvailableBufferSize)
	binary.BigEndian.PutUint32(buf[16:], c.PacketsReceivingRate)
	binary.BigEndian.PutUint32(buf[20:], c.EstimatedLinkCapacity)
	binary.BigEndian.PutUint32(buf[24:], c.ReceivingRate)
	binary.BigEndian.PutUint32(buf[28:], xmRate)
	return buf, nil
}

func (c *CIFACK) UnmarshalCIF(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("packet: ACK CIF too short (%d bytes)", len(data))
	}

	c.LastACKPacketSequenceNumber = binary.BigEndian.Uint32(data[0:])

	// Fields after the first are optional:
	// 4 bytes = Lite ACK (seq only)
	// 16 bytes = Small ACK (seq + RTT + RTTVar + BufferLeft)
	// 28 bytes = Full ACK (Small + speed + BW + rate)
	if len(data) >= 16 {
		c.RTT = binary.BigEndian.Uint32(data[4:])
		c.RTTVariance = binary.BigEndian.Uint32(data[8:])
		c.AvailableBufferSize = binary.BigEndian.Uint32(data[12:])
	}
	if len(data) >= 28 {
		c.PacketsReceivingRate = binary.BigEndian.Uint32(data[16:])
		c.EstimatedLinkCapacity = binary.BigEndian.Uint32(data[20:])
		c.ReceivingRate = binary.BigEndian.Uint32(data[24:])
	}

	return nil
}

// ---- NAK CIF ----

// CIFNAK represents a NAK Control Information Field (Section 3.2.4).
// It contains a list of lost packet sequence numbers encoded as
// individual numbers or ranges.
type CIFNAK struct {
	LossList []uint32 // sequence numbers of lost packets (expanded from ranges)
}

func (c *CIFNAK) MarshalCIF() ([]byte, error) {
	// Compress the loss list into ranges where possible
	if len(c.LossList) == 0 {
		return nil, nil
	}

	// Simple encoding: encode ranges (pre-allocate for worst case: all singles)
	encoded := make([]uint32, 0, len(c.LossList))
	i := 0
	for i < len(c.LossList) {
		start := c.LossList[i]
		end := start

		// Find contiguous range
		for i+1 < len(c.LossList) && c.LossList[i+1] == end+1 {
			i++
			end = c.LossList[i]
		}

		if start == end {
			// Single sequence number
			encoded = append(encoded, start&0x7FFFFFFF)
		} else {
			// Range [start, end]
			encoded = append(encoded, start|0x80000000, end&0x7FFFFFFF)
		}
		i++
	}

	buf := make([]byte, len(encoded)*4)
	for j, v := range encoded {
		binary.BigEndian.PutUint32(buf[j*4:], v)
	}
	return buf, nil
}

func (c *CIFNAK) UnmarshalCIF(data []byte) error {
	c.LossList = c.LossList[:0] // reset but keep capacity

	for i := 0; i+3 < len(data); {
		val := binary.BigEndian.Uint32(data[i:])
		if val&0x80000000 != 0 {
			// Range
			if i+7 >= len(data) {
				return fmt.Errorf("packet: NAK range incomplete at offset %d", i)
			}
			start := val & 0x7FFFFFFF
			end := binary.BigEndian.Uint32(data[i+4:]) & 0x7FFFFFFF
			for seq := start; seq != (end+1)&0x7FFFFFFF; seq = (seq + 1) & 0x7FFFFFFF {
				c.LossList = append(c.LossList, seq)
				// Safety limit: losses can't exceed the flow control window
				// (default 8192). Cap at 8192 to bound memory from malicious peers.
				if len(c.LossList) > 8192 {
					return fmt.Errorf("packet: NAK loss list too large (%d entries)", len(c.LossList))
				}
			}
			i += 8
		} else {
			// Single sequence number
			c.LossList = append(c.LossList, val)
			i += 4
		}
	}

	return nil
}

// ---- Shutdown CIF ----

// CIFShutdown is an empty CIF for shutdown control packets.
type CIFShutdown struct{}

func (c *CIFShutdown) MarshalCIF() ([]byte, error) { return nil, nil }
func (c *CIFShutdown) UnmarshalCIF([]byte) error   { return nil }

// ---- Drop Request CIF ----

// CIFDropReq represents a Drop Request Control Information Field: the inclusive
// sequence range [FirstSeqNo, LastSeqNo] the sender has abandoned. The CIF body
// is exactly two 32-bit words, matching libsrt's UMSG_DROPREQ wire layout
// (pack(UMSG_DROPREQ, &msgno, seqpair, 8) — an 8-byte [first, last] body). The
// dropped message number is NOT in the CIF; it travels in the control header's
// type-specific word (see Conn.emitDropReq), so a 12-byte body with msgno first
// — as an earlier version of this codec produced — corrupts the range against a
// real libsrt peer (it would read msgno as firstSeq).
type CIFDropReq struct {
	FirstSeqNo uint32
	LastSeqNo  uint32
}

func (c *CIFDropReq) MarshalCIF() ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:], c.FirstSeqNo)
	binary.BigEndian.PutUint32(buf[4:], c.LastSeqNo)
	return buf, nil
}

func (c *CIFDropReq) UnmarshalCIF(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("packet: DropReq CIF too short (%d bytes)", len(data))
	}
	c.FirstSeqNo = binary.BigEndian.Uint32(data[0:])
	c.LastSeqNo = binary.BigEndian.Uint32(data[4:])
	return nil
}
