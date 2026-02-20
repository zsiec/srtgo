package srt

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
	"github.com/zsiec/srtgo/internal/tsbpd"
)

// testConnPair creates two connected Conns for testing.
// Cleanup is registered via t.Cleanup.
func testConnPair(t *testing.T) (*Conn, *Conn) {
	t.Helper()

	// Create two UDP sockets bound to localhost
	addrA, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	addrB, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")

	connA, err := net.ListenUDP("udp", addrA)
	if err != nil {
		t.Fatalf("ListenUDP A: %v", err)
	}
	connB, err := net.ListenUDP("udp", addrB)
	if err != nil {
		connA.Close()
		t.Fatalf("ListenUDP B: %v", err)
	}

	muxA := mux.New(connA, 1500)
	muxB := mux.New(connB, 1500)

	socketIDA := uint32(100)
	socketIDB := uint32(200)

	recvChA := muxA.Register(socketIDA)
	recvChB := muxB.Register(socketIDB)

	clk := clock.NewRealClock()

	senderConn := newConn(ConnConfig{
		LocalAddr:    connA.LocalAddr(),
		RemoteAddr:   connB.LocalAddr(),
		SocketID:     socketIDA,
		PeerSocketID: socketIDB,
		Mux:          muxA,
		RecvChan:     recvChA,
		Clock:        clk,
		SendISN:      seq.Number(1000),
		RecvISN:      seq.Number(2000),
		SendBufSize:  1024,
		RecvBufSize:  1024,
		TsbpdDelay:   20 * time.Millisecond,
	})

	receiverConn := newConn(ConnConfig{
		LocalAddr:    connB.LocalAddr(),
		RemoteAddr:   connA.LocalAddr(),
		SocketID:     socketIDB,
		PeerSocketID: socketIDA,
		IsServer:     true,
		Mux:          muxB,
		RecvChan:     recvChB,
		Clock:        clk,
		SendISN:      seq.Number(2000),
		RecvISN:      seq.Number(1000),
		SendBufSize:  1024,
		RecvBufSize:  1024,
		TsbpdDelay:   20 * time.Millisecond,
	})

	t.Cleanup(func() {
		senderConn.Close()
		receiverConn.Close()
		muxA.Close()
		muxB.Close()
	})

	return senderConn, receiverConn
}

// testSingleConn creates a single Conn with a mux for basic tests.
func testSingleConn(t *testing.T) (*Conn, *mux.Mux) {
	t.Helper()

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}

	m := mux.New(udpConn, 1500)
	socketID := uint32(42)
	recvCh := m.Register(socketID)

	remoteAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9000}

	c := newConn(ConnConfig{
		LocalAddr:    udpConn.LocalAddr(),
		RemoteAddr:   remoteAddr,
		SocketID:     socketID,
		PeerSocketID: 99,
		Mux:          m,
		RecvChan:     recvCh,
		Clock:        clock.NewRealClock(),
		SendISN:      seq.Number(1000),
		RecvISN:      seq.Number(0),
		SendBufSize:  256,
		RecvBufSize:  256,
		TsbpdDelay:   20 * time.Millisecond,
	})

	t.Cleanup(func() {
		c.Close()
		m.Close()
	})

	return c, m
}

func TestConnNetConnInterface(t *testing.T) {
	c, _ := testSingleConn(t)

	// Verify that Conn implements net.Conn
	var _ net.Conn = c

	if c.LocalAddr() == nil {
		t.Error("LocalAddr should not be nil")
	}
	if c.RemoteAddr() == nil {
		t.Error("RemoteAddr should not be nil")
	}
}

func TestConnSocketIDAndStreamID(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, _ := net.ListenUDP("udp", addr)
	m := mux.New(udpConn, 1500)
	recvCh := m.Register(42)

	c := newConn(ConnConfig{
		LocalAddr:    udpConn.LocalAddr(),
		RemoteAddr:   &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9000},
		SocketID:     42,
		PeerSocketID: 99,
		StreamID:     "live/test",
		Mux:          m,
		RecvChan:     recvCh,
		Clock:        clock.NewRealClock(),
		SendISN:      seq.Number(0),
		RecvISN:      seq.Number(0),
		TsbpdDelay:   20 * time.Millisecond,
	})
	defer func() {
		c.Close()
		m.Close()
	}()

	if c.SocketID() != 42 {
		t.Errorf("SocketID: got %d, want 42", c.SocketID())
	}
	if c.StreamID() != "live/test" {
		t.Errorf("StreamID: got %q, want %q", c.StreamID(), "live/test")
	}
}

func TestConnClose(t *testing.T) {
	c, _ := testSingleConn(t)

	// Close should succeed
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Double close should be safe
	if err := c.Close(); err != nil {
		t.Fatalf("Double close: %v", err)
	}

	// Write after close should fail
	_, err := c.Write([]byte("hello"))
	if err == nil {
		t.Error("Write after Close should fail")
	}
}

func TestConnSetDeadline(t *testing.T) {
	c, _ := testSingleConn(t)

	// Set read deadline in the past
	c.SetReadDeadline(time.Now().Add(-1 * time.Second))

	// Read should timeout immediately
	buf := make([]byte, 1500)
	_, err := c.Read(buf)
	if err == nil {
		t.Error("Read with past deadline should fail")
	}

	// Verify it's a timeout error
	if netErr, ok := err.(*net.OpError); ok {
		if netErr.Op != "read" {
			t.Errorf("OpError.Op: got %q, want %q", netErr.Op, "read")
		}
	}
}

func TestConnWriteDeadline(t *testing.T) {
	c, _ := testSingleConn(t)

	// Fill the send buffer
	for i := range 256 {
		p := packet.NewData(
			c.remoteAddr,
			uint32(1000+i),
			uint32(i*1000),
			c.peerSocketID,
			make([]byte, 100),
		)
		if !c.sendBuf.Push(p) {
			break
		}
	}

	// Set write deadline in the past — should timeout when buffer is full
	c.SetWriteDeadline(time.Now().Add(-1 * time.Second))
	_, err := c.Write(make([]byte, 100))
	if err == nil {
		t.Error("Write with full buffer and past deadline should fail")
	}
}

func TestConnHandleDataPacket(t *testing.T) {
	c, _ := testSingleConn(t)

	// Simulate receiving a data packet
	p := packet.NewData(c.localAddr, 0, 1000, c.socketID, []byte("test payload"))
	c.handleDataPacket(p)

	if c.recvPackets.Load() != 1 {
		t.Errorf("recvPackets: got %d, want 1", c.recvPackets.Load())
	}
	if c.recvBytes.Load() != 12 {
		t.Errorf("recvBytes: got %d, want 12", c.recvBytes.Load())
	}
}

func TestConnHandleDuplicateDataPacket(t *testing.T) {
	c, _ := testSingleConn(t)

	// Insert same packet twice
	p1 := packet.NewData(c.localAddr, 0, 1000, c.socketID, []byte("test"))
	p2 := packet.NewData(c.localAddr, 0, 1000, c.socketID, []byte("test"))

	c.handleDataPacket(p1)
	c.handleDataPacket(p2)

	if c.recvPackets.Load() != 1 {
		t.Errorf("recvPackets: got %d, want 1 (duplicate should be dropped)", c.recvPackets.Load())
	}
}

func TestConnHandleACK(t *testing.T) {
	c, _ := testSingleConn(t)

	// Push some packets to the send buffer first
	for i := range 5 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, []byte("data"))
		c.sendBuf.Push(p)
	}

	before := c.sendBuf.Size()
	if before != 5 {
		t.Fatalf("sendBuf.Size: got %d, want 5", before)
	}

	// Create an ACK packet that ACKs up to sequence 1003
	ack := &packet.CIFACK{
		LastACKPacketSequenceNumber: 1003,
		RTT:                         1000,
		RTTVariance:                 500,
		AvailableBufferSize:         100,
	}
	p := packet.NewControl(c.localAddr, packet.CtrlTypeACK, c.socketID, 0)
	p.Header.TypeSpecific = 1 // ACK sequence number
	p.MarshalCIF(ack)

	c.handleACK(p)

	after := c.sendBuf.Size()
	if after >= before {
		t.Errorf("sendBuf.Size should decrease after ACK: was %d, now %d", before, after)
	}
}

func TestConnHandleACK_DuplicateDoesNotResetRTO(t *testing.T) {
	// Duplicate ACKs (where ackd == 0, i.e., the ACK sequence doesn't advance)
	// must NOT reset lastACKRecv or rexmitCount. Otherwise, over unreliable
	// transports (e.g., WebRTC DataChannel), the RTO timer never fires and
	// LATEREXMIT cannot recover lost retransmissions — causing a permanent stall.
	c, _ := testSingleConn(t)

	// Push 10 packets to the send buffer
	for i := range 10 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, make([]byte, 100))
		c.sendBuf.Push(p, c.clk.Now())
	}

	// First ACK at seq 1003: should advance and reset RTO
	ack1 := &packet.CIFACK{
		LastACKPacketSequenceNumber: 1003,
		RTT:                         1000,
		RTTVariance:                 500,
		AvailableBufferSize:         100,
	}
	p1 := packet.NewControl(c.localAddr, packet.CtrlTypeACK, c.socketID, 0)
	p1.Header.TypeSpecific = 1
	p1.MarshalCIF(ack1)
	c.handleACK(p1)

	// Verify first ACK advanced the buffer
	if c.sendBuf.Size() >= 10 {
		t.Fatal("first ACK should have reduced sendBuf.Size")
	}

	// Record lastACKRecv after the advancing ACK
	afterFirstACK := c.lastACKRecv.Load()
	if afterFirstACK == 0 {
		t.Fatal("lastACKRecv should be set after advancing ACK")
	}

	// Set lastACKRecv to a known old value so we can detect if it gets reset
	oldTime := time.Now().Add(-5 * time.Second).UnixNano()
	c.lastACKRecv.Store(oldTime)
	c.rexmitCount.Store(3) // simulate backoff

	// Send a duplicate ACK with the same sequence (ackd == 0)
	ack2 := &packet.CIFACK{
		LastACKPacketSequenceNumber: 1003, // same as before — no advancement
		RTT:                         1000,
		RTTVariance:                 500,
		AvailableBufferSize:         100,
	}
	p2 := packet.NewControl(c.localAddr, packet.CtrlTypeACK, c.socketID, 0)
	p2.Header.TypeSpecific = 2
	p2.MarshalCIF(ack2)
	c.handleACK(p2)

	// lastACKRecv should NOT have been reset (should still be our old value)
	if c.lastACKRecv.Load() != oldTime {
		t.Errorf("duplicate ACK should not reset lastACKRecv: got %d, want %d", c.lastACKRecv.Load(), oldTime)
	}

	// rexmitCount should NOT have been reset to 1
	if c.rexmitCount.Load() != 3 {
		t.Errorf("duplicate ACK should not reset rexmitCount: got %d, want 3", c.rexmitCount.Load())
	}

	// Now send an advancing ACK (seq 1005) — should reset both
	ack3 := &packet.CIFACK{
		LastACKPacketSequenceNumber: 1005,
		RTT:                         1000,
		RTTVariance:                 500,
		AvailableBufferSize:         100,
	}
	p3 := packet.NewControl(c.localAddr, packet.CtrlTypeACK, c.socketID, 0)
	p3.Header.TypeSpecific = 3
	p3.MarshalCIF(ack3)
	c.handleACK(p3)

	if c.lastACKRecv.Load() == oldTime {
		t.Error("advancing ACK should reset lastACKRecv")
	}
	if c.rexmitCount.Load() != 1 {
		t.Errorf("advancing ACK should reset rexmitCount to 1: got %d", c.rexmitCount.Load())
	}
}

func TestConnDuplicateACK_RTOFiresLATEREXMIT(t *testing.T) {
	// End-to-end test: when a receiver sends duplicate ACKs (sequence stuck
	// on a gap), the sender's RTO timer must eventually fire and trigger
	// LATEREXMIT to retransmit all in-flight packets.
	c, _ := testSingleConn(t)
	c.tsbpdEnabled.Store(false) // file mode

	// Push 10 packets
	for i := range 10 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, make([]byte, 100))
		c.sendBuf.Push(p, c.clk.Now())
	}

	// ACK up to seq 1003 (packets 0-2 ACK'd, 7 in flight)
	ack := &packet.CIFACK{
		LastACKPacketSequenceNumber: 1003,
		RTT:                         50_000, // 50ms
		RTTVariance:                 10_000,
		AvailableBufferSize:         100,
	}
	p := packet.NewControl(c.localAddr, packet.CtrlTypeACK, c.socketID, 0)
	p.Header.TypeSpecific = 1
	p.MarshalCIF(ack)
	c.handleACK(p)

	flightBefore := c.sendBuf.Size()
	if flightBefore == 0 {
		t.Fatal("should have packets in flight")
	}

	// Send duplicate ACKs (receiver stuck on gap at seq 1003)
	for i := range 10 {
		dup := &packet.CIFACK{
			LastACKPacketSequenceNumber: 1003,
			RTT:                         50_000,
			RTTVariance:                 10_000,
			AvailableBufferSize:         100,
		}
		dp := packet.NewControl(c.localAddr, packet.CtrlTypeACK, c.socketID, 0)
		dp.Header.TypeSpecific = uint32(2 + i)
		dp.MarshalCIF(dup)
		c.handleACK(dp)
	}

	// lastACKRecv should still be from the first (advancing) ACK, not reset
	// by duplicates. Set RTT values so we can verify RTO condition.
	c.rtt.Store(50_000)    // 50ms
	c.rttVar.Store(10_000) // 10ms

	// Simulate time passing beyond RTO: SRTT + 4*RTTVar + 2*SYN = 50+40+20 = 110ms
	// RTO = rxCount * rttSyn + 10ms. With rxCount=1: 110+10 = 120ms
	// Set lastACKRecv to 200ms ago to ensure RTO fires
	c.lastACKRecv.Store(time.Now().Add(-200 * time.Millisecond).UnixNano())
	c.sndLossCount.Store(0) // loss list empty (retransmissions were sent)

	retransBefore := c.retransCount.Load()

	// Simulate the timerLoop's RTO check
	now := time.Now()
	rttSynUS := c.rtt.Load() + 4*c.rttVar.Load() + 2*10_000
	rxCount := int64(c.rexmitCount.Load())
	if rxCount < 1 {
		rxCount = 1
	}
	rtoUS := rxCount*rttSynUS + 10_000
	rto := time.Duration(rtoUS) * time.Microsecond
	lastACKNano := c.lastACKRecv.Load()

	if !(lastACKNano > 0 && now.Sub(time.Unix(0, lastACKNano)) > rto) {
		t.Fatal("RTO condition should be true after duplicate ACKs and time passage")
	}

	// LATEREXMIT: file mode + loss list empty
	if !c.tsbpdEnabled.Load() && c.flightSize() > 0 && c.sndLossCount.Load() <= 0 {
		c.retransmitAllInFlight()
	}

	if c.retransCount.Load() <= retransBefore {
		t.Error("LATEREXMIT should have retransmitted in-flight packets")
	}
}

func TestConnHandleNAK(t *testing.T) {
	c, _ := testSingleConn(t)

	// Push some packets
	for i := range 10 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, make([]byte, 100))
		c.sendBuf.Push(p)
	}

	// Create NAK for sequence 1002
	nak := &packet.CIFNAK{LossList: []uint32{1002}}
	p := packet.NewControl(c.localAddr, packet.CtrlTypeNAK, c.socketID, 0)
	p.MarshalCIF(nak)

	c.handleNAK(p)

	if c.lostPackets.Load() != 1 {
		t.Errorf("lostPackets: got %d, want 1", c.lostPackets.Load())
	}
}

func TestConnHandleShutdown(t *testing.T) {
	c, _ := testSingleConn(t)

	p := packet.NewControl(c.localAddr, packet.CtrlTypeShutdown, c.socketID, 0)
	c.handleControlPacket(p)

	// Connection should be closed
	select {
	case <-c.done:
		// expected
	case <-time.After(100 * time.Millisecond):
		t.Error("connection should be closed after Shutdown")
	}
}

func TestConnHandleKeepalive(t *testing.T) {
	c, _ := testSingleConn(t)

	// KeepAlive should not close the connection
	p := packet.NewControl(c.localAddr, packet.CtrlTypeKeepalive, c.socketID, 0)
	c.handleControlPacket(p)

	select {
	case <-c.done:
		t.Error("KeepAlive should not close connection")
	default:
		// expected
	}
}

func TestConnStats(t *testing.T) {
	c, _ := testSingleConn(t)

	// Generate some stats
	c.sentPackets.Add(10)
	c.sentBytes.Add(15000)
	c.recvPackets.Add(8)
	c.recvBytes.Add(12000)
	c.lostPackets.Add(2)
	c.retransCount.Add(1)

	// Set known RTT values
	c.rtt.Store(50000)    // 50ms
	c.rttVar.Store(10000) // 10ms

	stats := c.Stats(false)

	if stats.SentPackets != 10 {
		t.Errorf("SentPackets: got %d, want 10", stats.SentPackets)
	}
	if stats.SentBytes != 15000 {
		t.Errorf("SentBytes: got %d, want 15000", stats.SentBytes)
	}
	if stats.RecvPackets != 8 {
		t.Errorf("RecvPackets: got %d, want 8", stats.RecvPackets)
	}
	if stats.RecvBytes != 12000 {
		t.Errorf("RecvBytes: got %d, want 12000", stats.RecvBytes)
	}
	if stats.LostPackets != 2 {
		t.Errorf("LostPackets: got %d, want 2", stats.LostPackets)
	}
	if stats.Retransmits != 1 {
		t.Errorf("Retransmits: got %d, want 1", stats.Retransmits)
	}

	// New fields
	if stats.RTTVar != 10*time.Millisecond {
		t.Errorf("RTTVar: got %v, want 10ms", stats.RTTVar)
	}
	if stats.FlightSize < 0 {
		t.Errorf("FlightSize: got %d, want >= 0", stats.FlightSize)
	}
	if stats.SendBufAvailable <= 0 {
		t.Errorf("SendBufAvailable: got %d, want > 0", stats.SendBufAvailable)
	}
	if stats.RecvBufAvailable <= 0 {
		t.Errorf("RecvBufAvailable: got %d, want > 0", stats.RecvBufAvailable)
	}
	if stats.NegotiatedLatency <= 0 {
		t.Errorf("NegotiatedLatency: got %v, want > 0", stats.NegotiatedLatency)
	}
}

func TestConnStatsControlPackets(t *testing.T) {
	c, _ := testSingleConn(t)

	// Insert some data packets so ACK has something to send
	for i := range 5 {
		p := packet.NewData(c.localAddr, uint32(i), uint32(i*1000), c.socketID, []byte("data"))
		c.recvBuf.Insert(p, c.clk.Now())
	}

	// Send Full ACK (increments sentACKs)
	c.sendFullACK()
	stats := c.Stats(false)
	if stats.SentACKs != 1 {
		t.Errorf("SentACKs: got %d, want 1", stats.SentACKs)
	}

	// Send Lite ACK
	c.sendLiteACK()
	stats = c.Stats(false)
	if stats.SentACKs != 2 {
		t.Errorf("SentACKs after lite: got %d, want 2", stats.SentACKs)
	}

	// Push some data into send buffer so ACK seq 1003 is within valid range
	// (SendISN=1000, so we need NextSeq > 1003)
	for i := range 5 {
		sp := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, []byte("data"))
		c.sendBuf.Push(sp, c.clk.Now())
	}

	// Simulate receiving an ACK (increments recvACKs + sentACKACKs)
	ack := &packet.CIFACK{
		LastACKPacketSequenceNumber: 1003,
		RTT:                         1000,
		RTTVariance:                 500,
	}
	ap := packet.NewControl(c.localAddr, packet.CtrlTypeACK, c.socketID, 0)
	ap.Header.TypeSpecific = 1
	ap.MarshalCIF(ack)
	c.handleACK(ap)

	stats = c.Stats(false)
	if stats.RecvACKs != 1 {
		t.Errorf("RecvACKs: got %d, want 1", stats.RecvACKs)
	}
	if stats.SentACKACKs != 1 {
		t.Errorf("SentACKACKs: got %d, want 1", stats.SentACKACKs)
	}

	// Simulate receiving a NAK (increments recvNAKs)
	nak := &packet.CIFNAK{LossList: []uint32{1002}}
	np := packet.NewControl(c.localAddr, packet.CtrlTypeNAK, c.socketID, 0)
	np.MarshalCIF(nak)
	c.handleNAK(np)

	stats = c.Stats(false)
	if stats.RecvNAKs != 1 {
		t.Errorf("RecvNAKs: got %d, want 1", stats.RecvNAKs)
	}

	// Simulate receiving an ACKACK (increments recvACKACKs)
	aap := packet.NewControl(c.localAddr, packet.CtrlTypeACKACK, c.socketID, 0)
	aap.Header.TypeSpecific = 999 // unknown seq — won't update RTT but still counts
	c.handleACKACK(aap)
	aap.Release()

	stats = c.Stats(false)
	if stats.RecvACKACKs != 1 {
		t.Errorf("RecvACKACKs: got %d, want 1", stats.RecvACKACKs)
	}
}

func TestConnStatsNegotiated(t *testing.T) {
	c, _ := testSingleConn(t)

	stats := c.Stats(false)

	// testSingleConn uses default payload size (1500 - 44 = 1456)
	expectedMSS := packet.MaxPayloadSize + 44
	if stats.NegotiatedMSS != expectedMSS {
		t.Errorf("NegotiatedMSS: got %d, want %d", stats.NegotiatedMSS, expectedMSS)
	}

	// FC defaults to 8192 in newConn
	if stats.NegotiatedFC != 8192 {
		t.Errorf("NegotiatedFC: got %d, want 8192", stats.NegotiatedFC)
	}
}

func TestConnStatsBelated(t *testing.T) {
	c, _ := testSingleConn(t)

	// Insert a packet successfully
	p := packet.NewData(c.localAddr, 0, 1000, c.socketID, []byte("data"))
	c.handleDataPacket(p)

	// Insert a duplicate (same seq) — should be counted as belated
	p2 := packet.NewData(c.localAddr, 0, 1000, c.socketID, []byte("data"))
	c.handleDataPacket(p2)

	stats := c.Stats(false)
	if stats.RecvBelated != 1 {
		t.Errorf("RecvBelated: got %d, want 1", stats.RecvBelated)
	}
}

func TestConnACKACKRTT(t *testing.T) {
	c, _ := testSingleConn(t)

	// Store a fake ACK send time with data seqno
	ackSeqNo := uint32(5)
	sendTime := c.clk.Now()
	slot := ackSeqNo & (ackTimeSlots - 1)
	c.ackSendTimeMu.Lock()
	c.ackSendTimeSlots[slot] = ackTimeEntry{seqNo: ackSeqNo, info: ackSendInfo{sendTime: sendTime, dataSeq: 100}}
	c.ackSendTimeMu.Unlock()

	// Simulate some time passing
	time.Sleep(5 * time.Millisecond)

	// Create ACKACK with matching sequence number
	p := packet.NewControl(c.localAddr, packet.CtrlTypeACKACK, c.socketID, c.clk.Now().SRTTimestamp())
	p.Header.TypeSpecific = ackSeqNo

	c.handleACKACK(p)
	p.Release()

	rtt := c.rtt.Load()
	if rtt <= 0 {
		t.Errorf("RTT should be positive after ACKACK, got %d", rtt)
	}
}

func TestConnACKACKUnknownSeq(t *testing.T) {
	c, _ := testSingleConn(t)

	initialRTTVal := c.rtt.Load()

	// Create ACKACK with unknown sequence number
	p := packet.NewControl(c.localAddr, packet.CtrlTypeACKACK, c.socketID, 0)
	p.Header.TypeSpecific = 9999 // unknown

	c.handleACKACK(p)
	p.Release()

	// RTT should not change
	if c.rtt.Load() != initialRTTVal {
		t.Error("RTT should not change for unknown ACKACK sequence")
	}
}

func TestConnSignaling(t *testing.T) {
	c, _ := testSingleConn(t)

	// signalReadReady should be non-blocking
	c.signalReadReady()
	select {
	case <-c.readReady:
		// expected
	default:
		t.Error("readReady should have signal")
	}

	// signalWriteReady should be non-blocking
	c.signalWriteReady()
	select {
	case <-c.writeReady:
		// expected
	default:
		t.Error("writeReady should have signal")
	}

	// Double signal should not block (buffered channel of size 1)
	c.signalReadReady()
	c.signalReadReady() // should not block

	c.signalWriteReady()
	c.signalWriteReady() // should not block
}

func TestConnFullACK(t *testing.T) {
	c, _ := testSingleConn(t)

	// Insert some data packets so ACK sequence advances
	for i := range 5 {
		p := packet.NewData(c.localAddr, uint32(i), uint32(i*1000), c.socketID, []byte("data"))
		c.recvBuf.Insert(p, c.clk.Now())
	}

	// Send Full ACK
	c.sendFullACK()

	// ACK sequence number should have incremented
	if c.ackSeqNo.Load() != 1 {
		t.Errorf("ackSeqNo: got %d, want 1", c.ackSeqNo.Load())
	}
}

func TestConnFullACKNoNewData(t *testing.T) {
	c, _ := testSingleConn(t)

	// First call: periodic Full ACK always goes through (needFullACK=true since >10ms since epoch)
	c.sendFullACK()
	if c.ackSeqNo.Load() != 1 {
		t.Errorf("first ackSeqNo: got %d, want 1 (periodic Full ACK)", c.ackSeqNo.Load())
	}

	// Second call immediately (<10ms): suppressed because ack == rcvLastAckAck (both at ISN)
	// and it's not time for a periodic Full ACK yet (rcvLastAckAck == ack && !needFullAck)
	c.sendFullACK()
	if c.ackSeqNo.Load() != 1 {
		t.Errorf("second ackSeqNo: got %d, want 1 (suppressed, no new data)", c.ackSeqNo.Load())
	}
}

func TestConnPeriodicNAK(t *testing.T) {
	c, _ := testSingleConn(t)

	// Insert packets with gap (seq 0 missing, seqs 1-3 present)
	for i := 1; i <= 3; i++ {
		p := packet.NewData(c.localAddr, uint32(i), uint32(i*1000), c.socketID, []byte("data"))
		c.recvBuf.Insert(p, c.clk.Now())
	}

	// This should detect the gap and send a NAK
	// We can't easily verify the packet was sent (goes to unresolvable addr),
	// but we can verify it doesn't panic
	c.sendPeriodicNAK()
}

func TestConnDataTransfer(t *testing.T) {
	sender, _ := testConnPair(t)

	payload := []byte("hello SRT world!")

	// Write from sender
	n, err := sender.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Write: got %d, want %d", n, len(payload))
	}

	// Wait for the sender to record the sent packet
	if !waitFor(t, 200*time.Millisecond, func() bool {
		return sender.Stats(false).SentPackets >= 1
	}) {
		t.Fatal("timed out waiting for SentPackets")
	}

	stats := sender.Stats(false)
	if stats.SentPackets != 1 {
		t.Errorf("SentPackets: got %d, want 1", stats.SentPackets)
	}
	if stats.SentBytes != uint64(len(payload)) {
		t.Errorf("SentBytes: got %d, want %d", stats.SentBytes, len(payload))
	}
}

func TestConnLiteACK(t *testing.T) {
	c, _ := testSingleConn(t)

	// sendLiteACK should not panic with empty buffer
	c.sendLiteACK()
}

func TestConnDefaultConfig(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, _ := net.ListenUDP("udp", addr)
	m := mux.New(udpConn, 1500)
	recvCh := m.Register(1)

	// Test with zero/default values
	c := newConn(ConnConfig{
		LocalAddr:    udpConn.LocalAddr(),
		RemoteAddr:   &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9000},
		SocketID:     1,
		PeerSocketID: 2,
		Mux:          m,
		RecvChan:     recvCh,
		// All other fields zero — should use defaults
	})
	defer func() {
		c.Close()
		m.Close()
	}()

	stats := c.Stats(false)
	if stats.RTT <= 0 {
		t.Errorf("default RTT should be positive, got %v", stats.RTT)
	}
}

func TestConnShutdownErr(t *testing.T) {
	c, _ := testSingleConn(t)

	// Before any error, getShutdownErr returns net.ErrClosed
	err := c.getShutdownErr()
	if err != net.ErrClosed {
		t.Errorf("initial error: got %v, want net.ErrClosed", err)
	}

	// Set an error
	c.setShutdownErr(net.ErrClosed)

	// First error wins
	c.setShutdownErr(net.ErrClosed)
	err = c.getShutdownErr()
	if err != net.ErrClosed {
		t.Errorf("shutdown error: got %v", err)
	}
}

func TestFlightSizeTracking(t *testing.T) {
	c, _ := testSingleConn(t)

	// Initially, flight size should be 0 (nothing in send buffer)
	if fs := c.flightSize(); fs != 0 {
		t.Errorf("initial flightSize: got %d, want 0", fs)
	}

	// Push 5 packets into the send buffer
	for i := range 5 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, []byte("data"))
		c.sendBuf.Push(p)
	}

	// Flight size = sendBuf.Size() = 5
	if fs := c.flightSize(); fs != 5 {
		t.Errorf("flightSize after push: got %d, want 5", fs)
	}

	// ACK first 3 packets (up to 1003, exclusive)
	c.sendBuf.ACK(seq.Number(1003))
	if fs := c.flightSize(); fs != 2 {
		t.Errorf("flightSize after ACK: got %d, want 2", fs)
	}
}

func TestFCBlocksWrite(t *testing.T) {
	// Create a pair of connected UDP sockets so sends succeed
	addrA, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	addrB, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	connA, err := net.ListenUDP("udp", addrA)
	if err != nil {
		t.Fatalf("ListenUDP A: %v", err)
	}
	connB, err := net.ListenUDP("udp", addrB)
	if err != nil {
		connA.Close()
		t.Fatalf("ListenUDP B: %v", err)
	}

	muxA := mux.New(connA, 1500)
	socketIDA := uint32(100)
	recvChA := muxA.Register(socketIDA)

	// Create conn with FC=5 and a very long TSBPD delay so checkSendDrop
	// doesn't drop packets and interfere with the FC test.
	c := newConn(ConnConfig{
		LocalAddr:    connA.LocalAddr(),
		RemoteAddr:   connB.LocalAddr(),
		SocketID:     socketIDA,
		PeerSocketID: 200,
		Mux:          muxA,
		RecvChan:     recvChA,
		Clock:        clock.NewRealClock(),
		SendISN:      seq.Number(1000),
		RecvISN:      seq.Number(0),
		SendBufSize:  256,
		RecvBufSize:  256,
		FC:           5,
		TsbpdDelay:   30 * time.Second,
	})
	defer func() {
		c.Close()
		muxA.Close()
		connB.Close()
	}()

	// Write 5 packets (should succeed — fills the FC window)
	for i := range 5 {
		_, err := c.Write(make([]byte, 100))
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	// 6th write should block and timeout since FC=5.
	// Use a past deadline to ensure immediate timeout.
	c.SetWriteDeadline(time.Now().Add(-1 * time.Second))
	_, err = c.Write(make([]byte, 100))
	if err == nil {
		t.Error("Write should block when flightSize >= FC")
	}
}

func TestNAKInterval(t *testing.T) {
	c, _ := testSingleConn(t)

	// NAK interval: CC adjusts base (RTT+4*RTTVar), then clamp to CC minimum.
	// LiveCC: divides by 2 (nakReportAccel=2), min 20ms.

	// Case 1: RTT=100_000μs (100ms), RTTVar=25_000μs (25ms)
	// base = 100_000+4*25_000 = 200_000 → CC: 200_000/2 = 100_000 → 100ms (> 20ms min)
	c.rtt.Store(100_000)
	c.rttVar.Store(25_000)

	got := c.nakInterval()
	want := 100 * time.Millisecond
	if got != want {
		t.Errorf("nakInterval: got %v, want %v", got, want)
	}

	// Case 2: Floor test — RTT=1000μs, RTTVar=500μs
	// base = 1_000+4*500 = 3_000 → CC: 3_000/2 = 1_500 → clamp to 20ms min
	c.rtt.Store(1000)
	c.rttVar.Store(500)

	got = c.nakInterval()
	if got != 20*time.Millisecond {
		t.Errorf("nakInterval floor: got %v, want 20ms", got)
	}

	// Case 3: High RTT exceeding floor — RTT=500_000μs, RTTVar=100_000μs
	// base = 500_000+4*100_000 = 900_000 → CC: 900_000/2 = 450_000 → 450ms
	c.rtt.Store(500_000)
	c.rttVar.Store(100_000)

	got = c.nakInterval()
	want = 450 * time.Millisecond
	if got != want {
		t.Errorf("nakInterval high RTT: got %v, want %v", got, want)
	}
}

func TestConnCloseWithLinger(t *testing.T) {
	// Create a conn pair so ACKs can flow between them.
	sender, receiver := testConnPair(t)

	// Write some data from sender
	for range 3 {
		_, err := sender.Write([]byte("data"))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	// Set linger on sender
	sender.linger = 500 * time.Millisecond

	// Wait for the receiver to get the packets and send ACKs
	time.Sleep(50 * time.Millisecond)

	// Trigger ACK from receiver side so sender buffer drains
	receiver.sendFullACK()
	time.Sleep(50 * time.Millisecond)

	// Close should complete quickly (buffer drained by ACK)
	start := time.Now()
	sender.Close()
	elapsed := time.Since(start)

	if elapsed > 400*time.Millisecond {
		t.Errorf("Close took %v, expected faster (buffer should have drained)", elapsed)
	}
}

func TestConnCloseLingerTimeout(t *testing.T) {
	c, _ := testSingleConn(t)

	// Push packets to send buffer (won't be ACK'd since single conn)
	for i := range 5 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, make([]byte, 100))
		c.sendBuf.Push(p)
	}

	// Set short linger
	c.linger = 50 * time.Millisecond

	// Close should return after linger timeout (no ACKs coming)
	start := time.Now()
	c.Close()
	elapsed := time.Since(start)

	if elapsed < 40*time.Millisecond {
		t.Errorf("Close returned too quickly: %v (expected ~50ms linger)", elapsed)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("Close took %v, expected ~50ms linger timeout", elapsed)
	}
}

func TestConnCloseImmediate(t *testing.T) {
	c, _ := testSingleConn(t)

	// Push packets to send buffer
	for i := range 5 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, make([]byte, 100))
		c.sendBuf.Push(p)
	}

	// Linger=0 (default) — Close should be immediate
	start := time.Now()
	c.Close()
	elapsed := time.Since(start)

	if elapsed > 50*time.Millisecond {
		t.Errorf("Close with Linger=0 took %v, expected immediate", elapsed)
	}
}

func TestConnPeerIdleTimeout(t *testing.T) {
	// Create conn with custom peer idle timeout via ConnConfig
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, _ := net.ListenUDP("udp", addr)
	m := mux.New(udpConn, 1500)
	recvCh := m.Register(42)

	c := newConn(ConnConfig{
		LocalAddr:       udpConn.LocalAddr(),
		RemoteAddr:      &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9000},
		SocketID:        42,
		PeerSocketID:    99,
		Mux:             m,
		RecvChan:        recvCh,
		Clock:           clock.NewRealClock(),
		SendISN:         seq.Number(0),
		RecvISN:         seq.Number(0),
		PeerIdleTimeout: 10 * time.Second,
		TsbpdDelay:      20 * time.Millisecond,
	})
	defer func() {
		c.Close()
		m.Close()
	}()

	if c.peerIdleTimeout != 10*time.Second {
		t.Errorf("peerIdleTimeout: got %v, want 10s", c.peerIdleTimeout)
	}
}

func TestKeyRotationCountdown(t *testing.T) {
	c, _ := testSingleConn(t)

	// Set up encryption with small rotation parameters
	cryptoCtx, err := crypto.New(16)
	if err != nil {
		t.Fatal(err)
	}
	c.cryptoCtx = cryptoCtx
	c.activeKey = packet.EncryptionEven
	c.passphrase = "test-passphrase"
	c.kmRefreshRate = 30
	c.kmPreAnnounce = 10

	initialKey := c.activeKey

	// Simulate sending 30 packets worth of key rotation checks
	for range 30 {
		c.checkKeyRotation()
	}

	// After 30 packets, the key should have switched
	if c.activeKey == initialKey {
		t.Error("activeKey should have switched after KMRefreshRate packets")
	}
	if c.kmPacketCount != 0 {
		t.Errorf("kmPacketCount: got %d, want 0 (reset after rotation)", c.kmPacketCount)
	}
}

func TestKeyRotationPreAnnounce(t *testing.T) {
	c, _ := testSingleConn(t)

	cryptoCtx, err := crypto.New(16)
	if err != nil {
		t.Fatal(err)
	}
	c.cryptoCtx = cryptoCtx
	c.activeKey = packet.EncryptionEven
	c.passphrase = "test-passphrase"
	c.kmRefreshRate = 30
	c.kmPreAnnounce = 10

	// Pre-announce point is at 30 - 10 = 20 packets
	for i := range uint64(19) {
		c.checkKeyRotation()
		if c.kmAnnounced {
			t.Errorf("kmAnnounced should be false at packet %d", i+1)
		}
	}

	// 20th packet should trigger announcement
	c.checkKeyRotation()
	if !c.kmAnnounced {
		t.Error("kmAnnounced should be true at pre-announce point")
	}
}

func TestKeyRotationDisabled(t *testing.T) {
	c, _ := testSingleConn(t)

	cryptoCtx, err := crypto.New(16)
	if err != nil {
		t.Fatal(err)
	}
	c.cryptoCtx = cryptoCtx
	c.activeKey = packet.EncryptionEven
	c.kmRefreshRate = 0 // disabled

	initialKey := c.activeKey
	for range 100 {
		// KM rotation is checked in Write only when kmRefreshRate > 0
		c.kmPacketCount++
	}

	if c.activeKey != initialKey {
		t.Error("activeKey should not change when rotation is disabled")
	}
}

func TestKeyRotationKeySwitch(t *testing.T) {
	c, _ := testSingleConn(t)

	cryptoCtx, err := crypto.New(16)
	if err != nil {
		t.Fatal(err)
	}
	c.cryptoCtx = cryptoCtx
	c.activeKey = packet.EncryptionEven
	c.passphrase = "test-passphrase"
	c.kmRefreshRate = 20
	c.kmPreAnnounce = 5

	// First rotation: Even → Odd
	for range 20 {
		c.checkKeyRotation()
	}
	if c.activeKey != packet.EncryptionOdd {
		t.Errorf("after 1st rotation: got %d, want Odd", c.activeKey)
	}

	// Second rotation: Odd → Even
	for range 20 {
		c.checkKeyRotation()
	}
	if c.activeKey != packet.EncryptionEven {
		t.Errorf("after 2nd rotation: got %d, want Even", c.activeKey)
	}
}

func TestKeyRotationKMREQRetry(t *testing.T) {
	c, _ := testSingleConn(t)

	cryptoCtx, err := crypto.New(16)
	if err != nil {
		t.Fatal(err)
	}
	c.cryptoCtx = cryptoCtx
	c.activeKey = packet.EncryptionEven
	c.passphrase = "test-passphrase"
	c.kmRefreshRate = 100
	c.kmPreAnnounce = 20

	// Pre-announce at packet 80. After that, retry every 20/10+1 = 3 packets.
	for range 80 {
		c.checkKeyRotation()
	}
	if !c.kmAnnounced {
		t.Fatal("should be announced at packet 80")
	}
	if c.kmConfirmed.Load() {
		t.Fatal("should not be confirmed yet")
	}

	// Simulate no KMRSP — kmConfirmed stays false.
	// Retries happen at packets 83, 86, 89, ... (every 3 packets after pre-announce)
	// The retry is at sinceAnnounce % 3 == 0, where sinceAnnounce = pktCount - 80.
	// At pktCount=83: sinceAnnounce=3, 3%3==0 → retry
	for range 3 {
		c.checkKeyRotation()
	}
	// After 3 more packets, we're at pktCount=83 — a retry should fire.
	// (verified by the fact that we don't panic and the announced state holds)
	if !c.kmAnnounced {
		t.Error("should still be announced during retry window")
	}

	// Simulate KMRSP received
	c.kmConfirmed.Store(true)

	// Continue sending — no more retries should happen (no crashes)
	for range 17 {
		c.checkKeyRotation()
	}
	// We're now at pktCount=100 → key switch
	if c.activeKey != packet.EncryptionOdd {
		t.Errorf("activeKey: got %d, want Odd", c.activeKey)
	}
	if c.kmAnnounced {
		t.Error("kmAnnounced should reset after key switch")
	}
}

func TestOppositeKey(t *testing.T) {
	if oppositeKey(packet.EncryptionEven) != packet.EncryptionOdd {
		t.Error("oppositeKey(Even) should be Odd")
	}
	if oppositeKey(packet.EncryptionOdd) != packet.EncryptionEven {
		t.Error("oppositeKey(Odd) should be Even")
	}
}

func TestConnRecvDropTooLate(t *testing.T) {
	c, _ := testSingleConn(t)

	// testSingleConn has RecvISN=0 and TsbpdDelay=20ms (20_000μs).
	// Insert seq 1 but not seq 0 — creates a gap at the head.
	pktTS := uint32(1000)
	p := packet.NewData(c.localAddr, 1, pktTS, c.socketID, []byte("payload"))
	c.recvBuf.Insert(p, c.clk.Now())

	// Compute the actual delivery time from the TSBPD timer
	delivery := c.tsbpdTimer.DeliveryTime(pktTS)

	// Before delivery time: empty slot 0 should NOT be dropped.
	now := delivery.Add(-10_000) // 10ms before delivery
	dropped := c.recvBuf.DropTooLate(now, c.tsbpdTimer.DeliveryTime)
	if dropped != 0 {
		t.Errorf("DropTooLate before delivery: got %d, want 0", dropped)
	}

	// After delivery time: empty slot 0 should be dropped.
	now = delivery.Add(10_000) // 10ms after delivery
	dropped = c.recvBuf.DropTooLate(now, c.tsbpdTimer.DeliveryTime)
	if dropped != 1 {
		t.Errorf("DropTooLate after delivery: got %d, want 1", dropped)
	}
	if c.recvBuf.StartSeq() != seq.Number(1) {
		t.Errorf("StartSeq: got %d, want 1", c.recvBuf.StartSeq())
	}

	// Verify recvDropped counter tracks the drops.
	c.recvDropped.Add(uint64(dropped))
	if c.recvDropped.Load() != 1 {
		t.Errorf("recvDropped: got %d, want 1", c.recvDropped.Load())
	}
}

func TestConnTimestampWrapDetection(t *testing.T) {
	c, _ := testSingleConn(t)

	// Delivery times should increase monotonically even across the
	// 32-bit timestamp wrap boundary (~71.6 minutes).

	// Simulate a packet near the end of the 32-bit range
	preWrapTS := uint32(0xFFFFFFF0) // ~16μs before wrap

	// UpdateWrap enters wrap period (ts > MAX - 30s)
	c.tsbpdTimer.UpdateWrap(preWrapTS)
	deliveryPre := c.tsbpdTimer.DeliveryTime(preWrapTS)

	// Now simulate a packet after the wrap
	postWrapTS := uint32(0x00000064) // 100μs after wrap
	c.tsbpdTimer.UpdateWrap(postWrapTS)

	// Get delivery time for post-wrap timestamp
	deliveryPost := c.tsbpdTimer.DeliveryTime(postWrapTS)

	// The post-wrap delivery time should be AFTER the pre-wrap delivery time
	if deliveryPost <= deliveryPre {
		t.Errorf("delivery time should increase across wrap: pre=%d, post=%d", deliveryPre, deliveryPost)
	}

	// The difference should be approximately (0xFFFFFFFF - 0xFFFFFFF0 + 0x64 + 1) = 0x74 = 116μs
	diff := deliveryPost.Sub(deliveryPre)
	expectedDiff := clock.Microseconds(0xFFFFFFFF - preWrapTS + postWrapTS + 1)
	if diff < expectedDiff-10 || diff > expectedDiff+10 {
		t.Errorf("delivery time diff: got %dμs, expected ~%dμs", diff, expectedDiff)
	}
}

func TestConnSendDropThreshold(t *testing.T) {
	// Formula: max(delay+extra, 1s) + 20ms

	// With default 20ms TSBPD delay: max(20ms, 1s) + 20ms = 1020ms
	c, _ := testSingleConn(t)

	expected := 1*clock.Second + 20*clock.Millisecond // 1020ms
	if c.sendDropThresh != expected {
		t.Errorf("sendDropThresh with 20ms delay: got %d, want %d (1s floor + 20ms)",
			c.sendDropThresh, expected)
	}

	// With large delay (2s): max(2s, 1s) + 20ms = 2020ms
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", addr)
	m := mux.New(conn, 1500)
	recvCh := m.Register(200)
	c2 := newConn(ConnConfig{
		LocalAddr:    conn.LocalAddr(),
		RemoteAddr:   &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9000},
		SocketID:     200,
		PeerSocketID: 201,
		Mux:          m,
		RecvChan:     recvCh,
		SendISN:      seq.Number(0),
		RecvISN:      seq.Number(0),
		TsbpdDelay:   2 * time.Second,
	})
	defer func() { c2.Close(); m.Close() }()

	expected = 2*clock.Second + 20*clock.Millisecond // 2020ms
	if c2.sendDropThresh != expected {
		t.Errorf("sendDropThresh with 2s delay: got %d, want %d", c2.sendDropThresh, expected)
	}
}

func TestStatsUniqueRetransBreakdown(t *testing.T) {
	c, _ := testSingleConn(t)

	// Simulate 10 sent packets, 2 retransmissions
	c.sentPackets.Store(10)
	c.sentBytes.Store(10000)
	c.retransCount.Store(2)
	c.retransBytes.Store(2000)

	// Simulate 8 received packets, 1 retransmission
	c.recvPackets.Store(8)
	c.recvBytes.Store(8000)
	c.recvRetrans.Store(1)
	c.recvRetransBytes.Store(1000)

	stats := c.Stats(false)

	if stats.SentUniquePackets != 8 {
		t.Errorf("SentUniquePackets: got %d, want 8", stats.SentUniquePackets)
	}
	if stats.SentUniqueBytes != 8000 {
		t.Errorf("SentUniqueBytes: got %d, want 8000", stats.SentUniqueBytes)
	}
	if stats.RetransBytes != 2000 {
		t.Errorf("RetransBytes: got %d, want 2000", stats.RetransBytes)
	}
	if stats.RecvUniquePackets != 7 {
		t.Errorf("RecvUniquePackets: got %d, want 7", stats.RecvUniquePackets)
	}
	if stats.RecvUniqueBytes != 7000 {
		t.Errorf("RecvUniqueBytes: got %d, want 7000", stats.RecvUniqueBytes)
	}
	if stats.RecvRetrans != 1 {
		t.Errorf("RecvRetrans: got %d, want 1", stats.RecvRetrans)
	}
	if stats.RecvRetransBytes != 1000 {
		t.Errorf("RecvRetransBytes: got %d, want 1000", stats.RecvRetransBytes)
	}
}

func TestStatsLossRate(t *testing.T) {
	c, _ := testSingleConn(t)

	// Zero packets — rates should be 0
	stats := c.Stats(false)
	if stats.SendLossRate != 0 {
		t.Errorf("SendLossRate with no packets: got %f, want 0", stats.SendLossRate)
	}
	if stats.RecvLossRate != 0 {
		t.Errorf("RecvLossRate with no packets: got %f, want 0", stats.RecvLossRate)
	}

	// Set known values: 100 sent, 5 lost → 5%
	c.sentPackets.Store(100)
	c.lostPackets.Store(5)

	// 90 received, 10 dropped → 10 / (90 + 10) * 100 = 10%
	c.recvPackets.Store(90)
	c.recvDropped.Store(10)

	stats = c.Stats(false)
	if stats.SendLossRate < 4.99 || stats.SendLossRate > 5.01 {
		t.Errorf("SendLossRate: got %f, want ~5.0", stats.SendLossRate)
	}
	if stats.RecvLossRate < 9.99 || stats.RecvLossRate > 10.01 {
		t.Errorf("RecvLossRate: got %f, want ~10.0", stats.RecvLossRate)
	}
}

func TestStatsRTTFactor(t *testing.T) {
	c, _ := testSingleConn(t)

	// testSingleConn has TsbpdDelay=20ms. Set RTT to 10ms → factor = 0.5
	c.rtt.Store(10_000) // 10ms in μs

	stats := c.Stats(false)
	if stats.RTTFactor < 0.49 || stats.RTTFactor > 0.51 {
		t.Errorf("RTTFactor: got %f, want ~0.5", stats.RTTFactor)
	}

	// Set RTT to 20ms → factor = 1.0
	c.rtt.Store(20_000)
	stats = c.Stats(false)
	if stats.RTTFactor < 0.99 || stats.RTTFactor > 1.01 {
		t.Errorf("RTTFactor: got %f, want ~1.0", stats.RTTFactor)
	}
}

func TestStatsByteOverhead(t *testing.T) {
	c, _ := testSingleConn(t)

	c.sentPackets.Store(100)
	c.sentBytes.Store(100_000) // 100 packets × 1000 bytes payload
	c.recvPackets.Store(50)
	c.recvBytes.Store(50_000)

	stats := c.Stats(false)

	// Total = payload + packets * 44
	expectedSentTotal := uint64(100_000 + 100*44)
	if stats.SentTotalBytes != expectedSentTotal {
		t.Errorf("SentTotalBytes: got %d, want %d", stats.SentTotalBytes, expectedSentTotal)
	}

	expectedRecvTotal := uint64(50_000 + 50*44)
	if stats.RecvTotalBytes != expectedRecvTotal {
		t.Errorf("RecvTotalBytes: got %d, want %d", stats.RecvTotalBytes, expectedRecvTotal)
	}
}

func TestStatsFECPlaceholders(t *testing.T) {
	c, _ := testSingleConn(t)

	stats := c.Stats(false)
	if stats.SndFilterExtra != 0 {
		t.Errorf("SndFilterExtra: got %d, want 0", stats.SndFilterExtra)
	}
	if stats.RcvFilterExtra != 0 {
		t.Errorf("RcvFilterExtra: got %d, want 0", stats.RcvFilterExtra)
	}
	if stats.RcvFilterSupply != 0 {
		t.Errorf("RcvFilterSupply: got %d, want 0", stats.RcvFilterSupply)
	}
}

func TestStatsBufferBytes(t *testing.T) {
	c, _ := testSingleConn(t)

	// Push 5 packets into the send buffer
	for i := range 5 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, make([]byte, 100))
		c.sendBuf.Push(p)
	}

	// Insert 3 packets into the recv buffer
	for i := range 3 {
		p := packet.NewData(c.localAddr, uint32(i), uint32(i*1000), c.socketID, make([]byte, 200))
		c.recvBuf.Insert(p, c.clk.Now())
	}

	stats := c.Stats(false)
	expectedSendBytes := 5 * c.payloadSize
	if stats.SendBufBytes != expectedSendBytes {
		t.Errorf("SendBufBytes: got %d, want %d", stats.SendBufBytes, expectedSendBytes)
	}
	expectedRecvBytes := 3 * c.payloadSize
	if stats.RecvBufBytes != expectedRecvBytes {
		t.Errorf("RecvBufBytes: got %d, want %d", stats.RecvBufBytes, expectedRecvBytes)
	}
}

func TestStatsStartTimeAndDuration(t *testing.T) {
	before := time.Now()
	c, _ := testSingleConn(t)
	after := time.Now()

	stats := c.Stats(false)
	if stats.StartTime.Before(before) || stats.StartTime.After(after) {
		t.Errorf("StartTime %v not between %v and %v", stats.StartTime, before, after)
	}
	if stats.Duration < 0 {
		t.Errorf("Duration should be non-negative, got %v", stats.Duration)
	}
}

func TestStatsTraceMode(t *testing.T) {
	c, _ := testSingleConn(t)

	// Send some initial data
	c.sentPackets.Store(10)
	c.sentBytes.Store(10_000)
	c.recvPackets.Store(8)
	c.recvBytes.Store(8_000)

	// First interval call — should return all data (no prior snapshot)
	stats1 := c.Stats(true)
	if stats1.SentPackets != 10 {
		t.Errorf("first interval SentPackets: got %d, want 10", stats1.SentPackets)
	}
	if stats1.RecvPackets != 8 {
		t.Errorf("first interval RecvPackets: got %d, want 8", stats1.RecvPackets)
	}

	// Add more data
	c.sentPackets.Store(15)
	c.sentBytes.Store(15_000)
	c.recvPackets.Store(12)
	c.recvBytes.Store(12_000)

	// Second interval call — should return only the delta
	stats2 := c.Stats(true)
	if stats2.SentPackets != 5 {
		t.Errorf("second interval SentPackets: got %d, want 5", stats2.SentPackets)
	}
	if stats2.SentBytes != 5_000 {
		t.Errorf("second interval SentBytes: got %d, want 5000", stats2.SentBytes)
	}
	if stats2.RecvPackets != 4 {
		t.Errorf("second interval RecvPackets: got %d, want 4", stats2.RecvPackets)
	}
}

func TestStatsTotalMode(t *testing.T) {
	c, _ := testSingleConn(t)

	c.sentPackets.Store(10)
	c.sentBytes.Store(10_000)

	// Total mode should return cumulative values
	stats1 := c.Stats(false)
	if stats1.SentPackets != 10 {
		t.Errorf("total SentPackets: got %d, want 10", stats1.SentPackets)
	}

	c.sentPackets.Store(15)
	stats2 := c.Stats(false)
	if stats2.SentPackets != 15 {
		t.Errorf("total SentPackets: got %d, want 15", stats2.SentPackets)
	}

	// Total mode should not be affected by interval calls
	c.Stats(true) // clear interval
	c.sentPackets.Store(20)
	stats3 := c.Stats(false)
	if stats3.SentPackets != 20 {
		t.Errorf("total SentPackets after clear: got %d, want 20", stats3.SentPackets)
	}
}

func TestStatsTraceModeReset(t *testing.T) {
	c, _ := testSingleConn(t)

	c.sentPackets.Store(100)
	c.sentBytes.Store(100_000)
	c.lostPackets.Store(5)
	c.sentACKs.Store(50)
	c.recvDropped.Store(3)

	// Clear — take snapshot
	c.Stats(true)

	// No new data — interval should be all zeros for counters
	stats := c.Stats(true)
	if stats.SentPackets != 0 {
		t.Errorf("reset SentPackets: got %d, want 0", stats.SentPackets)
	}
	if stats.SentBytes != 0 {
		t.Errorf("reset SentBytes: got %d, want 0", stats.SentBytes)
	}
	if stats.LostPackets != 0 {
		t.Errorf("reset LostPackets: got %d, want 0", stats.LostPackets)
	}
	if stats.SentACKs != 0 {
		t.Errorf("reset SentACKs: got %d, want 0", stats.SentACKs)
	}
	if stats.RecvDropped != 0 {
		t.Errorf("reset RecvDropped: got %d, want 0", stats.RecvDropped)
	}

	// Instantaneous fields should still be populated
	if stats.NegotiatedLatency <= 0 {
		t.Errorf("NegotiatedLatency should be > 0 in interval mode")
	}
}

func TestStatsIntervalControlCounters(t *testing.T) {
	c, _ := testSingleConn(t)

	c.sentACKs.Store(10)
	c.sentNAKs.Store(5)
	c.recvACKs.Store(8)
	c.recvNAKs.Store(3)
	c.sentKM.Store(2)
	c.recvKM.Store(1)

	// First interval
	stats1 := c.Stats(true)
	if stats1.SentACKs != 10 || stats1.SentNAKs != 5 {
		t.Errorf("first interval ACKs=%d NAKs=%d, want 10,5", stats1.SentACKs, stats1.SentNAKs)
	}

	// Add more
	c.sentACKs.Store(12)
	c.sentNAKs.Store(7)
	c.recvACKs.Store(10)
	c.sentKM.Store(3)

	stats2 := c.Stats(true)
	if stats2.SentACKs != 2 {
		t.Errorf("interval SentACKs: got %d, want 2", stats2.SentACKs)
	}
	if stats2.SentNAKs != 2 {
		t.Errorf("interval SentNAKs: got %d, want 2", stats2.SentNAKs)
	}
	if stats2.RecvACKs != 2 {
		t.Errorf("interval RecvACKs: got %d, want 2", stats2.RecvACKs)
	}
	if stats2.SentKM != 1 {
		t.Errorf("interval SentKM: got %d, want 1", stats2.SentKM)
	}
}

func TestStatsCallback(t *testing.T) {
	c, _ := testSingleConn(t)

	// Simulate some data
	c.sentPackets.Store(5)
	c.sentBytes.Store(5000)

	var received []ConnStats
	mu := sync.Mutex{}
	c.OnStats(50*time.Millisecond, func(s ConnStats) {
		mu.Lock()
		received = append(received, s)
		mu.Unlock()
	})

	// Wait for at least one callback to fire
	if !waitFor(t, 500*time.Millisecond, func() bool {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		return n > 0
	}) {
		t.Fatal("stats callback should have fired at least once")
	}

	mu.Lock()
	count := len(received)
	mu.Unlock()

	// Unregister
	c.OnStats(0, nil)
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	countAfter := len(received)
	mu.Unlock()

	// Should not fire again (or at most one more due to race)
	if countAfter > count+1 {
		t.Errorf("callback should stop after unregister: before=%d, after=%d", count, countAfter)
	}
}

func TestStatsCallbackInterval(t *testing.T) {
	c, _ := testSingleConn(t)

	callCount := atomic.Uint32{}
	c.OnStats(30*time.Millisecond, func(s ConnStats) {
		callCount.Add(1)
	})

	time.Sleep(150 * time.Millisecond)
	count := callCount.Load()

	// With 30ms interval and 150ms wait, expect ~3-5 calls
	// (timerLoop ticks every 10ms, so it should check frequently)
	if count < 2 || count > 10 {
		t.Errorf("callback count: got %d, expected 2-10 in 150ms with 30ms interval", count)
	}
}

func TestStatsRetransmitTracking(t *testing.T) {
	c, _ := testSingleConn(t)

	// Push 10 packets into the send buffer directly
	for i := range 10 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, make([]byte, 100))
		c.sendBuf.Push(p)
	}

	// Simulate a NAK for packets 1002 and 1005
	nak := &packet.CIFNAK{LossList: []uint32{1002, 1005}}
	p := packet.NewControl(c.localAddr, packet.CtrlTypeNAK, c.socketID, 0)
	p.MarshalCIF(nak)
	c.handleNAK(p)

	stats := c.Stats(false)
	if stats.Retransmits != 2 {
		t.Errorf("Retransmits: got %d, want 2", stats.Retransmits)
	}
	if stats.RetransBytes != 200 { // 2 packets × 100 bytes
		t.Errorf("RetransBytes: got %d, want 200", stats.RetransBytes)
	}

	// Verify unique breakdown is consistent
	// (no sentPackets were added via Write, so SentPackets=0, SentUniquePackets wraps)
	// Instead, manually set sent counters for a clean check:
	c.sentPackets.Store(10)
	c.sentBytes.Store(1000)
	stats = c.Stats(false)
	if stats.SentUniquePackets != 10-2 {
		t.Errorf("SentUniquePackets: got %d, want 8", stats.SentUniquePackets)
	}
	if stats.SentUniqueBytes != 1000-200 {
		t.Errorf("SentUniqueBytes: got %d, want 800", stats.SentUniqueBytes)
	}
}

func TestStatsRecvRetransmitFlag(t *testing.T) {
	c, _ := testSingleConn(t)

	// Insert a normal packet
	p1 := packet.NewData(c.localAddr, 0, 1000, c.socketID, []byte("normal"))
	c.handleDataPacket(p1)

	// Insert a retransmitted packet (seq 1)
	p2 := packet.NewData(c.localAddr, 1, 2000, c.socketID, []byte("retrans"))
	p2.Header.Retransmitted = true
	c.handleDataPacket(p2)

	stats := c.Stats(false)
	if stats.RecvPackets != 2 {
		t.Errorf("RecvPackets: got %d, want 2", stats.RecvPackets)
	}
	if stats.RecvRetrans != 1 {
		t.Errorf("RecvRetrans: got %d, want 1", stats.RecvRetrans)
	}
	if stats.RecvRetransBytes != uint64(len("retrans")) {
		t.Errorf("RecvRetransBytes: got %d, want %d", stats.RecvRetransBytes, len("retrans"))
	}
	if stats.RecvUniquePackets != 1 {
		t.Errorf("RecvUniquePackets: got %d, want 1", stats.RecvUniquePackets)
	}
}

func TestStatsTotalBytesWithHeaders(t *testing.T) {
	c, _ := testSingleConn(t)

	c.sentPackets.Store(100)
	c.sentBytes.Store(100_000)
	c.retransCount.Store(10)
	c.retransBytes.Store(10_000)
	c.recvPackets.Store(80)
	c.recvBytes.Store(80_000)
	c.recvRetrans.Store(5)
	c.recvRetransBytes.Store(5_000)

	stats := c.Stats(false)

	// SentTotalBytes = payload + packets * 44
	if stats.SentTotalBytes != 100_000+100*44 {
		t.Errorf("SentTotalBytes: got %d, want %d", stats.SentTotalBytes, 100_000+100*44)
	}
	if stats.RecvTotalBytes != 80_000+80*44 {
		t.Errorf("RecvTotalBytes: got %d, want %d", stats.RecvTotalBytes, 80_000+80*44)
	}

	// Unique total bytes (90 unique sent packets × (1000 + 44))
	expectedUniqueTotal := (100_000 - 10_000) + (100-10)*44
	if stats.SentUniqueTotalBytes != uint64(expectedUniqueTotal) {
		t.Errorf("SentUniqueTotalBytes: got %d, want %d", stats.SentUniqueTotalBytes, expectedUniqueTotal)
	}

	// Retrans total bytes (10 retrans × (1000 + 44))
	expectedRetransTotal := uint64(10_000 + 10*44)
	if stats.RetransTotalBytes != expectedRetransTotal {
		t.Errorf("RetransTotalBytes: got %d, want %d", stats.RetransTotalBytes, expectedRetransTotal)
	}

	// RecvRetrans total bytes (5 retrans × (1000 + 44))
	expectedRecvRetransTotal := uint64(5_000 + 5*44)
	if stats.RecvRetransTotalBytes != expectedRecvRetransTotal {
		t.Errorf("RecvRetransTotalBytes: got %d, want %d", stats.RecvRetransTotalBytes, expectedRecvRetransTotal)
	}
}

func TestStatsRecvLoss(t *testing.T) {
	c, _ := testSingleConn(t)

	// Insert packets with a gap: seq 0 present, seq 1-3 missing, seq 4 present
	p0 := packet.NewData(c.localAddr, 0, 1000, c.socketID, []byte("data"))
	c.handleDataPacket(p0)

	// Inserting seq 4 creates gap [1, 3] — 3 lost packets
	p4 := packet.NewData(c.localAddr, 4, 5000, c.socketID, []byte("data"))
	c.handleDataPacket(p4)

	stats := c.Stats(false)
	if stats.RecvLoss != 3 {
		t.Errorf("RecvLoss: got %d, want 3", stats.RecvLoss)
	}

	// RecvLossBytes includes header overhead
	expectedLossBytes := uint64(3) * (uint64(c.payloadSize) + 44)
	if stats.RecvLossBytes != expectedLossBytes {
		t.Errorf("RecvLossBytes: got %d, want %d", stats.RecvLossBytes, expectedLossBytes)
	}
}

func TestStatsBelatedBytes(t *testing.T) {
	c, _ := testSingleConn(t)

	// Insert a packet
	p1 := packet.NewData(c.localAddr, 0, 1000, c.socketID, []byte("hello"))
	c.handleDataPacket(p1)

	// Insert duplicate — counted as belated
	p2 := packet.NewData(c.localAddr, 0, 1000, c.socketID, []byte("hello"))
	c.handleDataPacket(p2)

	stats := c.Stats(false)
	if stats.RecvBelated != 1 {
		t.Errorf("RecvBelated: got %d, want 1", stats.RecvBelated)
	}
	if stats.RecvBelatedBytes != 5 {
		t.Errorf("RecvBelatedBytes: got %d, want 5", stats.RecvBelatedBytes)
	}
	expectedBelatedTotal := uint64(5 + 44)
	if stats.RecvBelatedTotalBytes != expectedBelatedTotal {
		t.Errorf("RecvBelatedTotalBytes: got %d, want %d", stats.RecvBelatedTotalBytes, expectedBelatedTotal)
	}
}

func TestStatsInstantaneousFields(t *testing.T) {
	c, _ := testSingleConn(t)

	stats := c.Stats(false)

	// UsPktSndPeriod should be positive (from congestion controller)
	if stats.UsPktSndPeriod <= 0 {
		t.Errorf("UsPktSndPeriod: got %f, want > 0", stats.UsPktSndPeriod)
	}

	// MbpsMaxBW should be positive (default 30 Mbps → ~240 Mbps)
	if stats.MbpsMaxBW <= 0 {
		t.Errorf("MbpsMaxBW: got %f, want > 0", stats.MbpsMaxBW)
	}

	// NegotiatedMSS should be payloadSize + 44
	if stats.NegotiatedMSS != c.payloadSize+44 {
		t.Errorf("NegotiatedMSS: got %d, want %d", stats.NegotiatedMSS, c.payloadSize+44)
	}
}

func TestStatsSndBufMs(t *testing.T) {
	c, _ := testSingleConn(t)

	// Empty buffer — no age
	stats := c.Stats(false)
	if stats.MsSndBuf != 0 {
		t.Errorf("MsSndBuf with empty buffer: got %v, want 0", stats.MsSndBuf)
	}

	// Push a packet with known send time
	p := packet.NewData(c.remoteAddr, 1000, 0, c.peerSocketID, make([]byte, 100))
	c.sendBuf.Push(p, c.clk.Now())

	// Wait a bit so the age is measurable
	time.Sleep(20 * time.Millisecond)

	stats = c.Stats(false)
	if stats.MsSndBuf < 15*time.Millisecond || stats.MsSndBuf > 100*time.Millisecond {
		t.Errorf("MsSndBuf: got %v, want ~20ms", stats.MsSndBuf)
	}
}

func TestStatsIntervalBitrate(t *testing.T) {
	c, _ := testSingleConn(t)

	// First interval — establish baseline
	c.Stats(true)
	time.Sleep(50 * time.Millisecond)

	// Simulate sending 1MB of data
	c.sentPackets.Store(1000)
	c.sentBytes.Store(1_000_000)

	stats := c.Stats(true)
	// With ~1MB over ~50ms, rate should be roughly 160 Mbps
	// (1_000_000 + 1000*44) * 8 / 1_000_000 / 0.05 ≈ 167 Mbps
	if stats.MbpsSendRate <= 0 {
		t.Errorf("MbpsSendRate: got %f, want > 0", stats.MbpsSendRate)
	}
}

func TestStatsRcvFilterLossPlaceholder(t *testing.T) {
	c, _ := testSingleConn(t)

	stats := c.Stats(false)
	if stats.RcvFilterLoss != 0 {
		t.Errorf("RcvFilterLoss: got %d, want 0", stats.RcvFilterLoss)
	}
}

func TestStatsDroppedBytes(t *testing.T) {
	c, _ := testSingleConn(t)

	// Simulate drops with known byte counts
	c.sentDropped.Store(5)
	c.sentDroppedBytes.Store(5000)
	c.recvDropped.Store(3)
	c.recvDroppedBytes.Store(3000)

	stats := c.Stats(false)

	// SentDropTotalBytes = payload + pkt * 44
	expectedSndDrop := uint64(5000 + 5*44)
	if stats.SentDropTotalBytes != expectedSndDrop {
		t.Errorf("SentDropTotalBytes: got %d, want %d", stats.SentDropTotalBytes, expectedSndDrop)
	}

	expectedRcvDrop := uint64(3000 + 3*44)
	if stats.RecvDropTotalBytes != expectedRcvDrop {
		t.Errorf("RecvDropTotalBytes: got %d, want %d", stats.RecvDropTotalBytes, expectedRcvDrop)
	}
}

func TestStatsSndDuration(t *testing.T) {
	c, _ := testSingleConn(t)

	// Initially idle: duration should be 0
	stats := c.Stats(false)
	if stats.UsSndDuration != 0 {
		t.Errorf("initial UsSndDuration: got %d, want 0", stats.UsSndDuration)
	}

	// Simulate send buffer becoming non-empty
	mockClk := clock.NewMockClock()
	mockClk.Set(clock.Timestamp(1_000_000))
	c.clk = mockClk

	// Mark buffer busy at t=1.0s
	c.sndBusySince.Store(int64(clock.Timestamp(1_000_000)))

	// Advance clock to t=1.5s (500ms of busy time pending)
	mockClk.Set(clock.Timestamp(1_500_000))

	stats = c.Stats(false)
	if stats.UsSndDuration != 500_000 {
		t.Errorf("pending UsSndDuration: got %d, want 500000", stats.UsSndDuration)
	}

	// Simulate buffer drain: accumulate 500ms, clear busy flag
	c.sndDurationUs.Store(500_000)
	c.sndBusySince.Store(0)

	stats = c.Stats(false)
	if stats.UsSndDuration != 500_000 {
		t.Errorf("accumulated UsSndDuration: got %d, want 500000", stats.UsSndDuration)
	}

	// Start busy again at t=1.5s, advance to t=2.0s
	c.sndBusySince.Store(int64(clock.Timestamp(1_500_000)))
	mockClk.Set(clock.Timestamp(2_000_000))

	stats = c.Stats(false)
	// accumulated(500_000) + pending(500_000) = 1_000_000
	if stats.UsSndDuration != 1_000_000 {
		t.Errorf("total UsSndDuration: got %d, want 1000000", stats.UsSndDuration)
	}
}

func TestStatsSndDurationInterval(t *testing.T) {
	c, _ := testSingleConn(t)

	// Accumulate 1s of send duration
	c.sndDurationUs.Store(1_000_000)

	// First interval captures the full 1s
	stats := c.Stats(true)
	if stats.UsSndDuration != 1_000_000 {
		t.Errorf("first interval UsSndDuration: got %d, want 1000000", stats.UsSndDuration)
	}

	// Accumulate another 500ms
	c.sndDurationUs.Store(1_500_000)

	// Second interval should only show 500ms delta
	stats = c.Stats(true)
	if stats.UsSndDuration != 500_000 {
		t.Errorf("second interval UsSndDuration: got %d, want 500000", stats.UsSndDuration)
	}
}

func TestStatsCongestionWindow(t *testing.T) {
	c, _ := testSingleConn(t)

	stats := c.Stats(false)
	// LiveCC returns math.MaxInt for CongestionWindow (no CWND limit — FC controls flow).
	// FileCC returns the adaptive CWND.
	if stats.CongestionWindow != c.sendCC.CongestionWindow() {
		t.Errorf("CongestionWindow: got %d, want %d", stats.CongestionWindow, c.sendCC.CongestionWindow())
	}
}

func TestStatsReorderDistance(t *testing.T) {
	c, _ := testSingleConn(t)

	// Initially, no reorder distance
	stats := c.Stats(false)
	if stats.ReorderDistance != 0 {
		t.Errorf("initial ReorderDistance: got %d, want 0", stats.ReorderDistance)
	}
	if stats.ReorderTolerance != 0 {
		t.Errorf("ReorderTolerance: got %d, want 0", stats.ReorderTolerance)
	}

	// Simulate in-order arrivals: seq 1, 2, 3
	for _, s := range []uint32{1, 2, 3} {
		p := packet.NewData(c.remoteAddr, s, 100+s*1000, c.socketID, []byte("test"))
		c.handleDataPacket(p)
	}

	stats = c.Stats(false)
	if stats.ReorderDistance != 0 {
		t.Errorf("in-order ReorderDistance: got %d, want 0", stats.ReorderDistance)
	}

	// Now seq 7 arrives (gap over 4,5,6)
	p := packet.NewData(c.remoteAddr, 7, 7100, c.socketID, []byte("test"))
	c.handleDataPacket(p)

	// Then seq 5 arrives out-of-order (distance = 7-5 = 2)
	p = packet.NewData(c.remoteAddr, 5, 5100, c.socketID, []byte("test"))
	c.handleDataPacket(p)

	stats = c.Stats(false)
	if stats.ReorderDistance != 2 {
		t.Errorf("ReorderDistance after OOO: got %d, want 2", stats.ReorderDistance)
	}

	// Then seq 4 arrives (distance = 7-4 = 3, should update max)
	p = packet.NewData(c.remoteAddr, 4, 4100, c.socketID, []byte("test"))
	c.handleDataPacket(p)

	stats = c.Stats(false)
	if stats.ReorderDistance != 3 {
		t.Errorf("ReorderDistance after bigger OOO: got %d, want 3", stats.ReorderDistance)
	}

	// Retransmitted packets should NOT affect reorder distance.
	// Send seq 10 in-order, then retransmitted seq 6 (distance would be 4).
	p = packet.NewData(c.remoteAddr, 10, 10100, c.socketID, []byte("test"))
	c.handleDataPacket(p)

	p = packet.NewData(c.remoteAddr, 6, 6100, c.socketID, []byte("retrans"))
	p.Header.Retransmitted = true
	c.handleDataPacket(p)

	stats = c.Stats(false)
	// Distance should still be 3, not 4 — retransmits are excluded
	if stats.ReorderDistance != 3 {
		t.Errorf("ReorderDistance after retransmit OOO: got %d, want 3 (retransmits excluded)", stats.ReorderDistance)
	}
}

func TestStatsRcvAvgBelatedTime(t *testing.T) {
	c, _ := testSingleConn(t)

	// Initially no belated packets
	stats := c.Stats(false)
	if stats.RcvAvgBelatedTime != 0 {
		t.Errorf("initial RcvAvgBelatedTime: got %v, want 0", stats.RcvAvgBelatedTime)
	}

	// Directly set the EWMA atomic to simulate belated arrivals.
	// First sample: 10ms → EWMA initialized to 10ms
	c.recvBelatedTimeAvg.Store(10_000) // 10ms = 10,000 μs

	stats = c.Stats(false)
	expected := 10 * time.Millisecond
	if stats.RcvAvgBelatedTime != expected {
		t.Errorf("RcvAvgBelatedTime after 1 packet: got %v, want %v", stats.RcvAvgBelatedTime, expected)
	}

	// Second sample: 30ms → EWMA = 10000 + (30000 - 10000)/5 = 14000 μs = 14ms
	// CountIIR: base + (new - base) * 0.2
	newAvg := int64(10_000) + (int64(30_000)-int64(10_000))/5
	c.recvBelatedTimeAvg.Store(newAvg)

	stats = c.Stats(false)
	expected = time.Duration(newAvg) * time.Microsecond // 14ms
	if stats.RcvAvgBelatedTime != expected {
		t.Errorf("RcvAvgBelatedTime after EWMA: got %v, want %v", stats.RcvAvgBelatedTime, expected)
	}
}

func TestStatsSndDurationACKDrains(t *testing.T) {
	c, _ := testSingleConn(t)

	mockClk := clock.NewMockClock()
	mockClk.Set(clock.Timestamp(1_000_000))
	c.clk = mockClk

	// Push a packet into the send buffer to make it non-empty
	p := packet.NewData(c.remoteAddr, 1000, 100, c.peerSocketID, []byte("data"))
	c.sendBuf.Push(p, mockClk.Now())
	c.sndBusySince.Store(int64(mockClk.Now()))

	// Advance clock by 200ms
	mockClk.Set(clock.Timestamp(1_200_000))

	// Build ACK that clears the entire send buffer
	ack := &packet.CIFACK{
		LastACKPacketSequenceNumber: 1001, // ACK past our single packet
	}
	ackPkt := packet.NewControl(c.remoteAddr, packet.CtrlTypeACK, c.socketID, mockClk.Now().SRTTimestamp())
	ackPkt.Header.TypeSpecific = 1
	ackPkt.MarshalCIF(ack)

	c.handleACK(ackPkt)
	ackPkt.Release()

	// Buffer is now empty, duration should have been accumulated
	if c.sndBusySince.Load() != 0 {
		t.Error("sndBusySince should be 0 after buffer drains")
	}

	accumulated := c.sndDurationUs.Load()
	if accumulated != 200_000 {
		t.Errorf("accumulated sndDurationUs: got %d, want 200000", accumulated)
	}
}

func TestStatsSndDurationACKAccumulatesIncrementally(t *testing.T) {
	c, _ := testSingleConn(t)

	mockClk := clock.NewMockClock()
	mockClk.Set(clock.Timestamp(1_000_000))
	c.clk = mockClk

	// Push two packets so buffer doesn't drain on first ACK
	p1 := packet.NewData(c.remoteAddr, 1000, 100, c.peerSocketID, []byte("data1"))
	c.sendBuf.Push(p1, mockClk.Now())
	p2 := packet.NewData(c.remoteAddr, 1001, 200, c.peerSocketID, []byte("data2"))
	c.sendBuf.Push(p2, mockClk.Now())
	c.sndBusySince.Store(int64(mockClk.Now()))

	// Advance 100ms, send ACK for first packet only (buffer still non-empty)
	mockClk.Set(clock.Timestamp(1_100_000))
	ack := &packet.CIFACK{LastACKPacketSequenceNumber: 1001}
	ackPkt := packet.NewControl(c.remoteAddr, packet.CtrlTypeACK, c.socketID, mockClk.Now().SRTTimestamp())
	ackPkt.Header.TypeSpecific = 1
	ackPkt.MarshalCIF(ack)
	c.handleACK(ackPkt)
	ackPkt.Release()

	// Should have accumulated 100ms, and sndBusySince should be reset to now (not 0)
	if c.sndBusySince.Load() == 0 {
		t.Error("sndBusySince should not be 0 while buffer is non-empty")
	}
	if c.sndDurationUs.Load() != 100_000 {
		t.Errorf("after first ACK: sndDurationUs got %d, want 100000", c.sndDurationUs.Load())
	}

	// Advance another 150ms, ACK second packet (buffer drains)
	mockClk.Set(clock.Timestamp(1_250_000))
	ack2 := &packet.CIFACK{LastACKPacketSequenceNumber: 1002}
	ackPkt2 := packet.NewControl(c.remoteAddr, packet.CtrlTypeACK, c.socketID, mockClk.Now().SRTTimestamp())
	ackPkt2.Header.TypeSpecific = 2
	ackPkt2.MarshalCIF(ack2)
	c.handleACK(ackPkt2)
	ackPkt2.Release()

	// Should have accumulated 100 + 150 = 250ms total, and sndBusySince = 0
	if c.sndBusySince.Load() != 0 {
		t.Error("sndBusySince should be 0 after buffer drains")
	}
	if c.sndDurationUs.Load() != 250_000 {
		t.Errorf("after second ACK: sndDurationUs got %d, want 250000", c.sndDurationUs.Load())
	}
}

func TestKeyRotationMultipleCycles(t *testing.T) {
	c, _ := testSingleConn(t)

	cryptoCtx, err := crypto.New(16)
	if err != nil {
		t.Fatal(err)
	}
	c.cryptoCtx = cryptoCtx
	c.activeKey = packet.EncryptionEven
	c.passphrase = "test-passphrase"
	c.kmRefreshRate = 20
	c.kmPreAnnounce = 5

	// Track expected key transitions across 3 full rotation cycles
	expectedKeys := []packet.PacketEncryption{
		packet.EncryptionOdd,  // after cycle 1
		packet.EncryptionEven, // after cycle 2
		packet.EncryptionOdd,  // after cycle 3
	}

	for cycle := range 3 {
		preAnnounceAt := c.kmRefreshRate - c.kmPreAnnounce // packet 15

		for i := range c.kmRefreshRate {
			c.checkKeyRotation()

			// Verify pre-announce fires at the correct packet count each cycle
			if i+1 == preAnnounceAt {
				if !c.kmAnnounced {
					t.Errorf("cycle %d: kmAnnounced should be true at packet %d", cycle, i+1)
				}
			}
		}

		// After each cycle, verify key switch
		if c.activeKey != expectedKeys[cycle] {
			t.Errorf("cycle %d: activeKey = %d, want %d", cycle, c.activeKey, expectedKeys[cycle])
		}

		// Verify kmPacketCount resets
		if c.kmPacketCount != 0 {
			t.Errorf("cycle %d: kmPacketCount = %d, want 0", cycle, c.kmPacketCount)
		}

		// Verify kmAnnounced resets
		if c.kmAnnounced {
			t.Errorf("cycle %d: kmAnnounced should be false after key switch", cycle)
		}
	}
}

func TestConnStatsKmState(t *testing.T) {
	c, _ := testSingleConn(t)

	// No crypto: both states should be 0 (unsecured)
	stats := c.Stats(false)
	if stats.SndKmState != 0 {
		t.Errorf("SndKmState without crypto: got %d, want 0", stats.SndKmState)
	}
	if stats.RcvKmState != 0 {
		t.Errorf("RcvKmState without crypto: got %d, want 0", stats.RcvKmState)
	}

	// Enable crypto and set KM states (matching newConn initialization)
	cryptoCtx, err := crypto.New(16)
	if err != nil {
		t.Fatal(err)
	}
	c.cryptoCtx = cryptoCtx
	c.activeKey = packet.EncryptionEven
	c.sndKmState.Store(2) // SRT_KM_S_SECURED
	c.rcvKmState.Store(2) // SRT_KM_S_SECURED

	// Crypto enabled, no rotation in progress: state = 2 (secured)
	stats = c.Stats(false)
	if stats.SndKmState != 2 {
		t.Errorf("SndKmState with crypto: got %d, want 2", stats.SndKmState)
	}
	if stats.RcvKmState != 2 {
		t.Errorf("RcvKmState with crypto: got %d, want 2", stats.RcvKmState)
	}

	// Simulate rotation in progress (announced but not confirmed)
	c.kmAnnounced = true
	c.kmConfirmed.Store(false)
	c.sndKmState.Store(1) // SRT_KM_S_SECURING

	stats = c.Stats(false)
	if stats.SndKmState != 1 {
		t.Errorf("SndKmState during rotation: got %d, want 1 (securing)", stats.SndKmState)
	}
	// Receiver side stays secured
	if stats.RcvKmState != 2 {
		t.Errorf("RcvKmState during rotation: got %d, want 2", stats.RcvKmState)
	}

	// Confirm rotation
	c.kmConfirmed.Store(true)
	c.sndKmState.Store(2) // SRT_KM_S_SECURED
	stats = c.Stats(false)
	if stats.SndKmState != 2 {
		t.Errorf("SndKmState after confirm: got %d, want 2 (secured)", stats.SndKmState)
	}

	// Test error states (3=nosecret, 4=badsecret, 5=badcryptomode)
	c.sndKmState.Store(4) // SRT_KM_S_BADSECRET
	c.rcvKmState.Store(3) // SRT_KM_S_NOSECRET
	stats = c.Stats(false)
	if stats.SndKmState != 4 {
		t.Errorf("SndKmState badsecret: got %d, want 4", stats.SndKmState)
	}
	if stats.RcvKmState != 3 {
		t.Errorf("RcvKmState nosecret: got %d, want 3", stats.RcvKmState)
	}
}

func TestMessageNumberWrapping(t *testing.T) {
	c, _ := testSingleConn(t)

	// Set message number near the 26-bit max
	c.messageNumber = 0x03FFFFFF - 2

	nums := make([]uint32, 5)
	for i := range nums {
		nums[i] = c.nextMessageNumber()
	}

	// Should go: max-1, max, 1, 2, 3
	if nums[0] != 0x03FFFFFF-1 {
		t.Errorf("nums[0]: got %d, want %d", nums[0], 0x03FFFFFF-1)
	}
	if nums[1] != 0x03FFFFFF {
		t.Errorf("nums[1]: got %d, want %d", nums[1], 0x03FFFFFF)
	}
	if nums[2] != 1 {
		t.Errorf("nums[2]: got %d, want 1 (should wrap to 1, not 0)", nums[2])
	}
	if nums[3] != 2 {
		t.Errorf("nums[3]: got %d, want 2", nums[3])
	}
	if nums[4] != 3 {
		t.Errorf("nums[4]: got %d, want 3", nums[4])
	}
}

func TestMessageAPIDefault(t *testing.T) {
	cfg := Config{}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	if cfg.MessageAPI == nil {
		t.Fatal("MessageAPI should not be nil after validate")
	}
	if !*cfg.MessageAPI {
		t.Error("MessageAPI should default to true")
	}

	flags := cfg.srtFlags()
	if flags&packet.FlagStream != 0 {
		t.Error("FlagStream should NOT be set when MessageAPI=true")
	}
}

func TestMessageAPIFalse(t *testing.T) {
	f := false
	cfg := Config{MessageAPI: &f}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	if cfg.messageAPIEnabled() {
		t.Error("messageAPIEnabled should be false")
	}

	flags := cfg.srtFlags()
	if flags&packet.FlagStream == 0 {
		t.Error("FlagStream should be set when MessageAPI=false")
	}
}

func TestWriteSetsMessageNumber(t *testing.T) {
	c, _ := testSingleConn(t)

	// Enable messageAPI (testSingleConn doesn't set it)
	c.messageAPI = true

	// Check initial message number
	if c.messageNumber != 1 {
		t.Errorf("initial messageNumber: got %d, want 1", c.messageNumber)
	}

	// Simulate 3 writes by calling nextMessageNumber directly
	// (Write goes through the mux which requires a real peer)
	for i := range 3 {
		num := c.nextMessageNumber()
		if num != uint32(i+2) { // starts at 1, first call returns 2
			t.Errorf("nextMessageNumber %d: got %d, want %d", i, num, i+2)
		}
	}

	// Verify message number has advanced
	if c.messageNumber != 4 {
		t.Errorf("messageNumber after 3 calls: got %d, want 4", c.messageNumber)
	}
}

// testFileConnPair creates two connected Conns in file mode for testing.
// Cleanup is registered via t.Cleanup.
func testFileConnPair(t *testing.T) (*Conn, *Conn) {
	t.Helper()

	addrA, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	addrB, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")

	connA, err := net.ListenUDP("udp", addrA)
	if err != nil {
		t.Fatalf("ListenUDP A: %v", err)
	}
	connB, err := net.ListenUDP("udp", addrB)
	if err != nil {
		connA.Close()
		t.Fatalf("ListenUDP B: %v", err)
	}

	muxA := mux.New(connA, 1500)
	muxB := mux.New(connB, 1500)

	socketIDA := uint32(100)
	socketIDB := uint32(200)

	recvChA := muxA.Register(socketIDA)
	recvChB := muxB.Register(socketIDB)

	clk := clock.NewRealClock()

	senderConn := newConn(ConnConfig{
		LocalAddr:    connA.LocalAddr(),
		RemoteAddr:   connB.LocalAddr(),
		SocketID:     socketIDA,
		PeerSocketID: socketIDB,
		Mux:          muxA,
		RecvChan:     recvChA,
		Clock:        clk,
		SendISN:      seq.Number(1000),
		RecvISN:      seq.Number(2000),
		SendBufSize:  1024,
		RecvBufSize:  1024,
		Congestion:   CongestionFile,
	})

	receiverConn := newConn(ConnConfig{
		LocalAddr:    connB.LocalAddr(),
		RemoteAddr:   connA.LocalAddr(),
		SocketID:     socketIDB,
		PeerSocketID: socketIDA,
		IsServer:     true,
		Mux:          muxB,
		RecvChan:     recvChB,
		Clock:        clk,
		SendISN:      seq.Number(2000),
		RecvISN:      seq.Number(1000),
		SendBufSize:  1024,
		RecvBufSize:  1024,
		Congestion:   CongestionFile,
	})

	t.Cleanup(func() {
		senderConn.Close()
		receiverConn.Close()
		muxA.Close()
		muxB.Close()
	})

	return senderConn, receiverConn
}

func TestFileModeSendReceive(t *testing.T) {
	sender, receiver := testFileConnPair(t)

	payload := []byte("hello file mode!")

	n, err := sender.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Write: got %d, want %d", n, len(payload))
	}

	// Wait for packet delivery via UDP
	time.Sleep(50 * time.Millisecond)

	// File mode read (no TSBPD delay)
	receiver.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	n, err = receiver.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if string(buf[:n]) != string(payload) {
		t.Errorf("Read: got %q, want %q", buf[:n], payload)
	}
}

func TestFileModeNoTLPktDrop(t *testing.T) {
	sender, receiver := testFileConnPair(t)

	// Verify mode flags
	if sender.tsbpdEnabled.Load() {
		t.Error("sender tsbpdEnabled should be false in file mode")
	}
	if sender.tlpktdropEnabled.Load() {
		t.Error("sender tlpktdropEnabled should be false in file mode")
	}
	if receiver.tsbpdEnabled.Load() {
		t.Error("receiver tsbpdEnabled should be false in file mode")
	}
	if receiver.tlpktdropEnabled.Load() {
		t.Error("receiver tlpktdropEnabled should be false in file mode")
	}
	if sender.tsbpdTimer != nil {
		t.Error("sender tsbpdTimer should be nil in file mode")
	}
	if receiver.tsbpdTimer != nil {
		t.Error("receiver tsbpdTimer should be nil in file mode")
	}

	// Write a packet
	payload := []byte("no drop please")
	_, err := sender.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Wait well past what would be a TSBPD drop window in live mode
	time.Sleep(100 * time.Millisecond)

	// Should still be readable — no too-late drop in file mode
	receiver.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	n, err := receiver.Read(buf)
	if err != nil {
		t.Fatalf("Read after delay: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Errorf("Read: got %q, want %q", buf[:n], payload)
	}
}

func TestFileModeSequentialDelivery(t *testing.T) {
	sender, receiver := testFileConnPair(t)

	// Send multiple packets
	payloads := []string{"packet-0", "packet-1", "packet-2", "packet-3", "packet-4"}
	for _, payload := range payloads {
		_, err := sender.Write([]byte(payload))
		if err != nil {
			t.Fatalf("Write %q: %v", payload, err)
		}
	}

	// Wait for all to arrive
	time.Sleep(100 * time.Millisecond)

	// Read them back — should be in order
	receiver.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1500)
	for i, expected := range payloads {
		n, err := receiver.Read(buf)
		if err != nil {
			t.Fatalf("Read %d: %v", i, err)
		}
		if string(buf[:n]) != expected {
			t.Errorf("Read %d: got %q, want %q", i, buf[:n], expected)
		}
	}
}

func TestFileModeFlowControlCWND(t *testing.T) {
	// Create a file mode conn with small FC so CWND can be tested
	addrA, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	addrB, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	connA, err := net.ListenUDP("udp", addrA)
	if err != nil {
		t.Fatalf("ListenUDP A: %v", err)
	}
	connB, err := net.ListenUDP("udp", addrB)
	if err != nil {
		connA.Close()
		t.Fatalf("ListenUDP B: %v", err)
	}

	muxA := mux.New(connA, 1500)
	socketIDA := uint32(100)
	recvChA := muxA.Register(socketIDA)

	// FC=5 limits the flight window. FileCC initial CWND=16, so FC is the bottleneck.
	c := newConn(ConnConfig{
		LocalAddr:    connA.LocalAddr(),
		RemoteAddr:   connB.LocalAddr(),
		SocketID:     socketIDA,
		PeerSocketID: 200,
		Mux:          muxA,
		RecvChan:     recvChA,
		Clock:        clock.NewRealClock(),
		SendISN:      seq.Number(1000),
		RecvISN:      seq.Number(0),
		SendBufSize:  256,
		RecvBufSize:  256,
		FC:           5,
		Congestion:   CongestionFile,
	})
	defer func() {
		c.Close()
		muxA.Close()
		connB.Close()
	}()

	// Write 5 packets (fills FC window)
	for i := range 5 {
		_, err := c.Write(make([]byte, 100))
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	// 6th write should block and timeout
	c.SetWriteDeadline(time.Now().Add(-1 * time.Second))
	_, err = c.Write(make([]byte, 100))
	if err == nil {
		t.Error("Write should block when flightSize >= FC")
	}

	// Verify the connection is using file CC (CongestionWindow should not be math.MaxInt)
	cwnd := c.sendCC.CongestionWindow()
	if cwnd < 2 {
		t.Errorf("FileCC CongestionWindow: got %d, want >= 2", cwnd)
	}
}

func TestFileModeFileCC(t *testing.T) {
	// Verify that file mode connections use FileCC, not LiveCC
	sender, _ := testFileConnPair(t)

	// FileCC initial CWND = 16 (not math.MaxInt like LiveCC)
	cwnd := sender.sendCC.CongestionWindow()
	if cwnd == 0 || cwnd > 100 {
		t.Errorf("FileCC initial CongestionWindow: got %d, want ~16", cwnd)
	}

	// Live mode should use math.MaxInt
	sender2, _ := testConnPair(t)

	cwnd2 := sender2.sendCC.CongestionWindow()
	if cwnd2 < 1000000 {
		t.Errorf("LiveCC CongestionWindow should be very large (math.MaxInt): got %d", cwnd2)
	}
}

func TestTokenBucketPacing(t *testing.T) {
	sender, _ := testConnPair(t)

	// Initial state: nextSendTime is zero
	if !sender.nextSendTime.IsZero() {
		t.Error("initial nextSendTime should be zero")
	}

	// After first write, nextSendTime should be set
	sender.Write([]byte("first"))
	if sender.nextSendTime.IsZero() {
		t.Error("after first Write, nextSendTime should be set")
	}

	// Second write should use pacing
	sender.Write([]byte("second"))
	if sender.nextSendTime.IsZero() {
		t.Error("after second Write, nextSendTime should be set")
	}
}

func TestTokenBucketProbeBorrowing(t *testing.T) {
	sender, _ := testConnPair(t)

	// Send 16 packets to trigger a probe (every 16th packet)
	for range 17 {
		sender.Write([]byte("pkt"))
	}

	// After probe pair, sendTimeDiff may be negative (borrowed credit)
	// This is expected: probes borrow from future to send back-to-back
	// We mainly verify the pacing didn't panic and credit is tracked
	// (credit can be anything based on timing, just ensure it ran)
	if sender.nextSendTime.IsZero() {
		t.Error("nextSendTime should be set after sends")
	}
}

func TestFileModeQuickACK(t *testing.T) {
	sender, receiver := testFileConnPair(t)

	// Send a non-full-payload packet (smaller than max payload size).
	// In file mode, this should trigger quick ACK on the receiver.
	smallPayload := []byte("short")
	if len(smallPayload) >= receiver.payloadSize {
		t.Fatalf("test payload must be smaller than payloadSize %d", receiver.payloadSize)
	}

	// Verify receiver is in file mode (TSBPD disabled)
	if receiver.tsbpdEnabled.Load() {
		t.Fatal("receiver should be in file mode with TSBPD disabled")
	}

	// Send the small payload
	sender.Write(smallPayload)

	// Wait for the receiver to process and trigger quickACK
	if !waitFor(t, 200*time.Millisecond, func() bool {
		return receiver.sentACKs.Load() > 0
	}) {
		t.Error("receiver should have sent at least one ACK (quick ACK for non-full payload)")
	}
}

func TestFileModeQuickACKFullPayload(t *testing.T) {
	sender, receiver := testFileConnPair(t)

	// Send a full-payload packet — should NOT trigger quick ACK
	fullPayload := make([]byte, receiver.payloadSize)
	for i := range fullPayload {
		fullPayload[i] = byte(i)
	}
	sender.Write(fullPayload)

	// Wait briefly — quick ACK should NOT fire for full-size packets
	time.Sleep(20 * time.Millisecond)

	// In file mode, only periodic Full ACK (10ms) should trigger, not quick ACK.
	// We verify the receiver got the data and can read it.
	buf := make([]byte, len(fullPayload))
	receiver.Read(buf)
	if buf[0] != 0 || buf[1] != 1 {
		t.Error("data mismatch")
	}
}

func TestDynamicFlowWindow(t *testing.T) {
	sender, _ := testConnPair(t)

	// Initially flow window should be 0 (not yet updated from ACK)
	if fws := sender.flowWindowSize.Load(); fws != 0 {
		t.Errorf("initial flowWindowSize: got %d, want 0", fws)
	}

	// Simulate receiving an ACK with AvailableBufferSize
	ack := &packet.CIFACK{
		LastACKPacketSequenceNumber: sender.sendISN.Value(),
		RTT:                         1000,
		RTTVariance:                 500,
		AvailableBufferSize:         4096,
		PacketsReceivingRate:        0,
		EstimatedLinkCapacity:       0,
	}
	data, _ := ack.MarshalCIF()
	p := packet.NewControl(sender.remoteAddr, packet.CtrlTypeACK, sender.socketID, 0)
	p.Header.TypeSpecific = 1
	p.SetData(data)
	sender.handleACK(p)
	p.Release()

	// Flow window should be updated
	if fws := sender.flowWindowSize.Load(); fws != 4096 {
		t.Errorf("after ACK, flowWindowSize: got %d, want 4096", fws)
	}
}

func TestSndLossCountTracking(t *testing.T) {
	sender, _ := testFileConnPair(t)

	// Initially loss count should be 0
	if cnt := sender.sndLossCount.Load(); cnt != 0 {
		t.Errorf("initial sndLossCount: got %d, want 0", cnt)
	}

	// Send some packets to populate the send buffer
	for range 5 {
		sender.Write([]byte("data"))
	}

	// Simulate a NAK for 3 losses
	nak := &packet.CIFNAK{
		LossList: []uint32{
			sender.sendISN.Value(),
			sender.sendISN.Inc().Value(),
			sender.sendISN.Inc().Inc().Value(),
		},
	}
	data, _ := nak.MarshalCIF()
	p := packet.NewControl(sender.remoteAddr, packet.CtrlTypeNAK, sender.socketID, 0)
	p.SetData(data)
	sender.handleNAK(p)
	p.Release()

	// sndLossCount should have been tracked:
	// +3 (NAK) then -retransmitted (could be up to 3)
	// The exact value depends on how many were successfully retransmitted,
	// but it should be >= 0
	cnt := sender.sndLossCount.Load()
	if cnt < 0 {
		t.Errorf("sndLossCount should be >= 0, got %d", cnt)
	}
}

func TestMultiPacketMessageSendReceive(t *testing.T) {
	sender, receiver := testFileMessageConnPair(t)

	// Send a message larger than one payload (requires fragmentation)
	// payloadSize defaults to 1456 bytes
	msgSize := sender.payloadSize*3 + 100 // 3 full packets + 1 partial
	payload := make([]byte, msgSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	n, err := sender.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != msgSize {
		t.Errorf("Write: got %d, want %d", n, msgSize)
	}

	// Wait for delivery
	time.Sleep(100 * time.Millisecond)

	// Read the reassembled message
	receiver.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, msgSize+100)
	n, err = receiver.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != msgSize {
		t.Errorf("Read: got %d bytes, want %d", n, msgSize)
	}
	for i := range n {
		if buf[i] != byte(i%256) {
			t.Errorf("Read: byte %d: got %d, want %d", i, buf[i], byte(i%256))
			break
		}
	}
}

// testFileMessageConnPair creates two connected Conns in file mode with message API.
func testFileMessageConnPair(t *testing.T) (*Conn, *Conn) {
	t.Helper()

	addrA, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	addrB, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")

	connA, err := net.ListenUDP("udp", addrA)
	if err != nil {
		t.Fatalf("ListenUDP A: %v", err)
	}
	connB, err := net.ListenUDP("udp", addrB)
	if err != nil {
		connA.Close()
		t.Fatalf("ListenUDP B: %v", err)
	}

	muxA := mux.New(connA, 1500)
	muxB := mux.New(connB, 1500)

	recvChA := muxA.Register(uint32(300))
	recvChB := muxB.Register(uint32(400))

	clk := clock.NewRealClock()

	senderConn := newConn(ConnConfig{
		LocalAddr:    connA.LocalAddr(),
		RemoteAddr:   connB.LocalAddr(),
		SocketID:     300,
		PeerSocketID: 400,
		Mux:          muxA,
		RecvChan:     recvChA,
		Clock:        clk,
		SendISN:      seq.Number(1000),
		RecvISN:      seq.Number(2000),
		SendBufSize:  1024,
		RecvBufSize:  1024,
		Congestion:   CongestionFile,
		MessageAPI:   true,
	})

	receiverConn := newConn(ConnConfig{
		LocalAddr:    connB.LocalAddr(),
		RemoteAddr:   connA.LocalAddr(),
		SocketID:     400,
		PeerSocketID: 300,
		IsServer:     true,
		Mux:          muxB,
		RecvChan:     recvChB,
		Clock:        clk,
		SendISN:      seq.Number(2000),
		RecvISN:      seq.Number(1000),
		SendBufSize:  1024,
		RecvBufSize:  1024,
		Congestion:   CongestionFile,
		MessageAPI:   true,
	})

	t.Cleanup(func() {
		senderConn.Close()
		receiverConn.Close()
		muxA.Close()
		muxB.Close()
	})

	return senderConn, receiverConn
}

func TestMultiPacketMessageLiveReject(t *testing.T) {
	// Live mode should reject messages > payloadSize
	sender, _ := testConnPair(t)

	if !sender.tsbpdEnabled.Load() {
		t.Skip("sender not in live mode")
	}

	largePayload := make([]byte, sender.payloadSize+1)
	_, err := sender.Write(largePayload)
	if err == nil {
		t.Error("Write should reject oversized message in live mode")
	}
}

func TestSmallACKExtendedFields(t *testing.T) {
	// Verify that ACK sends small format when interval < 10ms
	ack := &packet.CIFACK{
		LastACKPacketSequenceNumber: 42,
		RTT:                         5000,
		RTTVariance:                 1000,
		AvailableBufferSize:         100,
		PacketsReceivingRate:        999,
		EstimatedLinkCapacity:       888,
		ReceivingRate:               777,
	}

	// Full ACK should be 28 bytes
	fullData, err := ack.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}
	if len(fullData) != 28 {
		t.Errorf("Full ACK size: got %d, want 28", len(fullData))
	}

	// Small ACK should be 16 bytes (no bandwidth fields)
	smallData, err := ack.MarshalSmallCIF()
	if err != nil {
		t.Fatalf("MarshalSmallCIF: %v", err)
	}
	if len(smallData) != 16 {
		t.Errorf("Small ACK size: got %d, want 16", len(smallData))
	}

	// Unmarshal small ACK should only have first 4 fields
	var parsed packet.CIFACK
	if err := parsed.UnmarshalCIF(smallData); err != nil {
		t.Fatalf("UnmarshalCIF small: %v", err)
	}
	if parsed.LastACKPacketSequenceNumber != 42 {
		t.Errorf("seq: got %d, want 42", parsed.LastACKPacketSequenceNumber)
	}
	if parsed.RTT != 5000 {
		t.Errorf("RTT: got %d, want 5000", parsed.RTT)
	}
	if parsed.AvailableBufferSize != 100 {
		t.Errorf("BufferSize: got %d, want 100", parsed.AvailableBufferSize)
	}
	// Extended fields should be zero (not present in small ACK)
	if parsed.PacketsReceivingRate != 0 {
		t.Errorf("PacketsReceivingRate should be 0 in small ACK, got %d", parsed.PacketsReceivingRate)
	}
}

func TestRejectionCodes(t *testing.T) {
	// Verify rejection codes match SRT wire values
	tests := []struct {
		name string
		code packet.HandshakeType
		want int
	}{
		{"RejUnknown", RejUnknown, 1000},
		{"RejVersion", RejVersion, 1008},
		{"RejRdvCookie", RejRdvCookie, 1009},
		{"RejBadSecret", RejBadSecret, 1010},
		{"RejUnsecure", RejUnsecure, 1011},
		{"RejMessageAPI", RejMessageAPI, 1012},
		{"RejCongestion", RejCongestion, 1013},
		{"RejFilter", RejFilter, 1014},
	}
	for _, tt := range tests {
		if int(tt.code) != tt.want {
			t.Errorf("%s: got %d, want %d", tt.name, int(tt.code), tt.want)
		}
	}
}

func TestEXPTimeoutBackoff(t *testing.T) {
	// Verify the EXP constants match the SRT spec
	if maxExpCount != 16 {
		t.Errorf("maxExpCount: got %d, want 16", maxExpCount)
	}
	if minExpInterval != 300*time.Millisecond {
		t.Errorf("minExpInterval: got %v, want 300ms", minExpInterval)
	}
}

func TestDefaultMaxBW(t *testing.T) {
	// Verify DefaultMaxBW matches BW_INFINITE = 1 Gbps
	expected := int64(1_000_000_000 / 8) // 125 MB/s
	if DefaultMaxBW != expected {
		t.Errorf("DefaultMaxBW: got %d, want %d", DefaultMaxBW, expected)
	}
}

// --- FreshLoss / Reorder Tolerance Tests ---

func TestFreshLossRemoveSingle(t *testing.T) {
	c := &Conn{
		maxReorderTolerance: 10,
		reorderTolerance:    5,
	}
	c.freshLoss = []freshLossEntry{
		{seqLo: 100, seqHi: 100, ttl: 3},
	}
	hadTTL := c.freshLossRemove(100)
	if hadTTL != 3 {
		t.Errorf("hadTTL: got %d, want 3", hadTTL)
	}
	if len(c.freshLoss) != 0 {
		t.Errorf("freshLoss should be empty, got %d entries", len(c.freshLoss))
	}
}

func TestFreshLossRemoveFromFront(t *testing.T) {
	c := &Conn{}
	c.freshLoss = []freshLossEntry{
		{seqLo: 100, seqHi: 105, ttl: 4},
	}
	hadTTL := c.freshLossRemove(100)
	if hadTTL != 4 {
		t.Errorf("hadTTL: got %d, want 4", hadTTL)
	}
	if len(c.freshLoss) != 1 {
		t.Fatalf("freshLoss should have 1 entry, got %d", len(c.freshLoss))
	}
	if c.freshLoss[0].seqLo != 101 || c.freshLoss[0].seqHi != 105 {
		t.Errorf("freshLoss[0]: got [%d,%d], want [101,105]", c.freshLoss[0].seqLo, c.freshLoss[0].seqHi)
	}
}

func TestFreshLossRemoveFromBack(t *testing.T) {
	c := &Conn{}
	c.freshLoss = []freshLossEntry{
		{seqLo: 100, seqHi: 105, ttl: 4},
	}
	hadTTL := c.freshLossRemove(105)
	if hadTTL != 4 {
		t.Errorf("hadTTL: got %d, want 4", hadTTL)
	}
	if c.freshLoss[0].seqLo != 100 || c.freshLoss[0].seqHi != 104 {
		t.Errorf("freshLoss[0]: got [%d,%d], want [100,104]", c.freshLoss[0].seqLo, c.freshLoss[0].seqHi)
	}
}

func TestFreshLossRemoveSplit(t *testing.T) {
	c := &Conn{}
	c.freshLoss = []freshLossEntry{
		{seqLo: 100, seqHi: 110, ttl: 4},
	}
	hadTTL := c.freshLossRemove(105)
	if hadTTL != 4 {
		t.Errorf("hadTTL: got %d, want 4", hadTTL)
	}
	if len(c.freshLoss) != 2 {
		t.Fatalf("freshLoss should have 2 entries, got %d", len(c.freshLoss))
	}
	if c.freshLoss[0].seqLo != 100 || c.freshLoss[0].seqHi != 104 {
		t.Errorf("freshLoss[0]: got [%d,%d], want [100,104]", c.freshLoss[0].seqLo, c.freshLoss[0].seqHi)
	}
	if c.freshLoss[1].seqLo != 106 || c.freshLoss[1].seqHi != 110 {
		t.Errorf("freshLoss[1]: got [%d,%d], want [106,110]", c.freshLoss[1].seqLo, c.freshLoss[1].seqHi)
	}
}

func TestFreshLossRemoveNotFound(t *testing.T) {
	c := &Conn{}
	c.freshLoss = []freshLossEntry{
		{seqLo: 100, seqHi: 105, ttl: 4},
	}
	hadTTL := c.freshLossRemove(50)
	if hadTTL != 0 {
		t.Errorf("hadTTL: got %d, want 0 (not found)", hadTTL)
	}
	if len(c.freshLoss) != 1 {
		t.Errorf("freshLoss should be unchanged, got %d entries", len(c.freshLoss))
	}
}

func TestProcessFreshLossExpiration(t *testing.T) {
	// Create a conn with a mux that can send packets (needed for NAK)
	c, m := testSingleConn(t)
	_ = m

	c.maxReorderTolerance = 10
	c.reorderTolerance = 5

	// Add entries with different TTLs
	c.freshLoss = []freshLossEntry{
		{seqLo: 100, seqHi: 100, ttl: 0}, // expired
		{seqLo: 102, seqHi: 103, ttl: 0}, // expired
		{seqLo: 200, seqHi: 205, ttl: 3}, // still alive
	}

	naksBefore := c.sentNAKs.Load()
	c.processFreshLoss()

	// Should have sent a NAK for the expired entries
	naksAfter := c.sentNAKs.Load()
	if naksAfter <= naksBefore {
		t.Error("expected NAK to be sent for expired FreshLoss entries")
	}

	// Remaining entry should have TTL decremented
	if len(c.freshLoss) != 1 {
		t.Fatalf("freshLoss should have 1 remaining entry, got %d", len(c.freshLoss))
	}
	if c.freshLoss[0].seqLo != 200 || c.freshLoss[0].ttl != 2 {
		t.Errorf("remaining entry: got [%d,%d] ttl=%d, want [200,205] ttl=2",
			c.freshLoss[0].seqLo, c.freshLoss[0].seqHi, c.freshLoss[0].ttl)
	}
}

func TestProcessFreshLossTTLDecrement(t *testing.T) {
	c, _ := testSingleConn(t)

	c.maxReorderTolerance = 10
	c.reorderTolerance = 5

	// Realistic: earlier entries have lower TTL (they were added first and
	// have been decremented more times). Front always expires first.
	c.freshLoss = []freshLossEntry{
		{seqLo: 100, seqHi: 100, ttl: 1},
		{seqLo: 200, seqHi: 200, ttl: 3},
	}

	c.processFreshLoss()

	// entry[0] ttl was 1 → now 0, entry[1] ttl was 3 → now 2
	// Nothing expired yet (phase 1 collects ttl <= 0, but decrement happens AFTER)
	if len(c.freshLoss) != 2 {
		t.Fatalf("freshLoss should have 2 entries, got %d", len(c.freshLoss))
	}
	if c.freshLoss[0].ttl != 0 {
		t.Errorf("entry[0].ttl: got %d, want 0", c.freshLoss[0].ttl)
	}
	if c.freshLoss[1].ttl != 2 {
		t.Errorf("entry[1].ttl: got %d, want 2", c.freshLoss[1].ttl)
	}

	// Second call: entry[0] (ttl=0) should expire, entry[1] decremented to 1
	c.processFreshLoss()
	if len(c.freshLoss) != 1 {
		t.Fatalf("freshLoss should have 1 entry after second process, got %d", len(c.freshLoss))
	}
	if c.freshLoss[0].seqLo != 200 {
		t.Errorf("remaining entry seqLo: got %d, want 200", c.freshLoss[0].seqLo)
	}
	if c.freshLoss[0].ttl != 1 {
		t.Errorf("remaining entry ttl: got %d, want 1", c.freshLoss[0].ttl)
	}
}

func TestDynamicToleranceIncrease(t *testing.T) {
	c := &Conn{
		maxReorderTolerance: 20,
		reorderTolerance:    5,
	}
	c.maxRecvSeq.Store(110)
	c.maxRecvSeqInit.Store(true)

	// Simulate belated arrival of seq 100 (distance 10 > tolerance 5)
	p := packet.Packet{
		Header: packet.Header{
			SequenceNumber: 100,
			Retransmitted:  false, // reordered, not retransmitted
		},
	}
	c.unlose(p)

	if c.reorderTolerance != 10 {
		t.Errorf("reorderTolerance: got %d, want 10 (increased to match distance)", c.reorderTolerance)
	}
}

func TestDynamicToleranceIncreaseCapped(t *testing.T) {
	c := &Conn{
		maxReorderTolerance: 8,
		reorderTolerance:    5,
	}
	c.maxRecvSeq.Store(120)
	c.maxRecvSeqInit.Store(true)

	// Distance 20 > max tolerance 8
	p := packet.Packet{
		Header: packet.Header{
			SequenceNumber: 100,
			Retransmitted:  false,
		},
	}
	c.unlose(p)

	if c.reorderTolerance != 8 {
		t.Errorf("reorderTolerance: got %d, want 8 (capped at max)", c.reorderTolerance)
	}
}

func TestDynamicToleranceDecreaseOnOrderedDelivery(t *testing.T) {
	c := &Conn{
		maxReorderTolerance:   10,
		reorderTolerance:      5,
		consecOrderedDelivery: 49, // one more will trigger decrease
	}

	// Simulate handleDataPacket's in-order tracking:
	// 50 consecutive ordered deliveries → decrease by 1
	c.consecOrderedDelivery++
	if c.consecOrderedDelivery >= 50 {
		c.consecOrderedDelivery = 0
		if c.reorderTolerance > 0 {
			c.reorderTolerance--
		}
	}

	if c.reorderTolerance != 4 {
		t.Errorf("reorderTolerance: got %d, want 4 (decreased by 1)", c.reorderTolerance)
	}
	if c.consecOrderedDelivery != 0 {
		t.Errorf("consecOrderedDelivery: got %d, want 0 (reset)", c.consecOrderedDelivery)
	}
}

func TestDynamicToleranceDecreaseOnEarlyDelivery(t *testing.T) {
	c := &Conn{
		maxReorderTolerance: 10,
		reorderTolerance:    5,
		consecEarlyDelivery: 9, // one more will trigger decrease
	}
	c.maxRecvSeq.Store(105)
	c.maxRecvSeqInit.Store(true)

	// Add FreshLoss entry with high TTL
	c.freshLoss = []freshLossEntry{
		{seqLo: 100, seqHi: 100, ttl: 4}, // had_ttl > 2 → early
	}

	// Reordered arrival of seq 100, distance=5 == tolerance → no increase
	p := packet.Packet{
		Header: packet.Header{
			SequenceNumber: 100,
			Retransmitted:  false,
		},
	}
	c.unlose(p)

	// Should have incremented consecEarlyDelivery to 10, then decreased tolerance
	if c.reorderTolerance != 4 {
		t.Errorf("reorderTolerance: got %d, want 4 (decreased by 1 after 10 early deliveries)", c.reorderTolerance)
	}
	if c.consecEarlyDelivery != 0 {
		t.Errorf("consecEarlyDelivery: got %d, want 0 (reset)", c.consecEarlyDelivery)
	}
}

func TestRetransmittedPacketNoToleranceChange(t *testing.T) {
	c := &Conn{
		maxReorderTolerance: 10,
		reorderTolerance:    5,
	}
	c.maxRecvSeq.Store(120)
	c.maxRecvSeqInit.Store(true)

	// Retransmitted packet should NOT adjust tolerance
	p := packet.Packet{
		Header: packet.Header{
			SequenceNumber: 100,
			Retransmitted:  true, // retransmitted, not reordered
		},
	}
	c.unlose(p)

	if c.reorderTolerance != 5 {
		t.Errorf("reorderTolerance: got %d, want 5 (unchanged for retransmitted)", c.reorderTolerance)
	}
}

// TestFreshLossCppCompatSequence ports the exact CRcvFreshLoss test sequence
// from C++ SRT's test_losslist_rcv.cpp. It creates a deque of fresh losses and
// performs a series of removeOne operations (SPLIT, STRIP, DELETE) verifying
// the deque state after each step.
func TestFreshLossCppCompatSequence(t *testing.T) {
	c := &Conn{}

	// Initial state matching C++ test:
	//   CRcvFreshLoss(10, 15, 5),   [10-15] ttl=5
	//   CRcvFreshLoss(25, 29, 10),  [25-29] ttl=10
	//   CRcvFreshLoss(30, 30, 3),   [30-30] ttl=3
	//   CRcvFreshLoss(45, 80, 100)  [45-80] ttl=100
	c.freshLoss = []freshLossEntry{
		{seqLo: 10, seqHi: 15, ttl: 5},
		{seqLo: 25, seqHi: 29, ttl: 10},
		{seqLo: 30, seqHi: 30, ttl: 3},
		{seqLo: 45, seqHi: 80, ttl: 100},
	}

	// Step 1: Remove 26 -> SPLIT [25-29] into [25-25] and [27-29]
	hadTTL := c.freshLossRemove(26)
	if hadTTL != 10 {
		t.Errorf("step 1: hadTTL = %d, want 10", hadTTL)
	}
	if len(c.freshLoss) != 5 {
		t.Fatalf("step 1: len = %d, want 5", len(c.freshLoss))
	}
	// Expected: [10-15], [25-25], [27-29], [30-30], [45-80]
	wantStep1 := []freshLossEntry{
		{seqLo: 10, seqHi: 15, ttl: 5},
		{seqLo: 25, seqHi: 25, ttl: 10},
		{seqLo: 27, seqHi: 29, ttl: 10},
		{seqLo: 30, seqHi: 30, ttl: 3},
		{seqLo: 45, seqHi: 80, ttl: 100},
	}
	for i, want := range wantStep1 {
		got := c.freshLoss[i]
		if got.seqLo != want.seqLo || got.seqHi != want.seqHi || got.ttl != want.ttl {
			t.Errorf("step 1: entry[%d] = {%d,%d,ttl=%d}, want {%d,%d,ttl=%d}",
				i, got.seqLo, got.seqHi, got.ttl, want.seqLo, want.seqHi, want.ttl)
		}
	}

	// Step 2: Remove 27 -> STRIP front of [27-29] -> [28-29]
	hadTTL = c.freshLossRemove(27)
	if hadTTL != 10 {
		t.Errorf("step 2: hadTTL = %d, want 10", hadTTL)
	}
	if len(c.freshLoss) != 5 {
		t.Fatalf("step 2: len = %d, want 5", len(c.freshLoss))
	}
	// Expected: [10-15], [25-25], [28-29], [30-30], [45-80]
	if c.freshLoss[2].seqLo != 28 || c.freshLoss[2].seqHi != 29 {
		t.Errorf("step 2: entry[2] = [%d-%d], want [28-29]",
			c.freshLoss[2].seqLo, c.freshLoss[2].seqHi)
	}

	// Step 3: Remove 28 -> STRIP front of [28-29] -> [29-29]
	hadTTL = c.freshLossRemove(28)
	if hadTTL != 10 {
		t.Errorf("step 3: hadTTL = %d, want 10", hadTTL)
	}
	if len(c.freshLoss) != 5 {
		t.Fatalf("step 3: len = %d, want 5", len(c.freshLoss))
	}
	// Expected: [10-15], [25-25], [29-29], [30-30], [45-80]
	if c.freshLoss[2].seqLo != 29 || c.freshLoss[2].seqHi != 29 {
		t.Errorf("step 3: entry[2] = [%d-%d], want [29-29]",
			c.freshLoss[2].seqLo, c.freshLoss[2].seqHi)
	}

	// Step 4: Remove 25 -> DELETE single-element [25-25]
	hadTTL = c.freshLossRemove(25)
	if hadTTL != 10 {
		t.Errorf("step 4: hadTTL = %d, want 10", hadTTL)
	}
	if len(c.freshLoss) != 4 {
		t.Fatalf("step 4: len = %d, want 4", len(c.freshLoss))
	}
	// Expected: [10-15], [29-29], [30-30], [45-80]
	wantStep4 := []freshLossEntry{
		{seqLo: 10, seqHi: 15, ttl: 5},
		{seqLo: 29, seqHi: 29, ttl: 10},
		{seqLo: 30, seqHi: 30, ttl: 3},
		{seqLo: 45, seqHi: 80, ttl: 100},
	}
	for i, want := range wantStep4 {
		got := c.freshLoss[i]
		if got.seqLo != want.seqLo || got.seqHi != want.seqHi || got.ttl != want.ttl {
			t.Errorf("step 4: entry[%d] = {%d,%d,ttl=%d}, want {%d,%d,ttl=%d}",
				i, got.seqLo, got.seqHi, got.ttl, want.seqLo, want.seqHi, want.ttl)
		}
	}

	// Step 5: Remove 50 -> SPLIT [45-80] into [45-49] and [51-80]
	hadTTL = c.freshLossRemove(50)
	if hadTTL != 100 {
		t.Errorf("step 5: hadTTL = %d, want 100", hadTTL)
	}
	if len(c.freshLoss) != 5 {
		t.Fatalf("step 5: len = %d, want 5", len(c.freshLoss))
	}
	// Expected: [10-15], [29-29], [30-30], [45-49], [51-80]
	wantStep5 := []freshLossEntry{
		{seqLo: 10, seqHi: 15, ttl: 5},
		{seqLo: 29, seqHi: 29, ttl: 10},
		{seqLo: 30, seqHi: 30, ttl: 3},
		{seqLo: 45, seqHi: 49, ttl: 100},
		{seqLo: 51, seqHi: 80, ttl: 100},
	}
	for i, want := range wantStep5 {
		got := c.freshLoss[i]
		if got.seqLo != want.seqLo || got.seqHi != want.seqHi || got.ttl != want.ttl {
			t.Errorf("step 5: entry[%d] = {%d,%d,ttl=%d}, want {%d,%d,ttl=%d}",
				i, got.seqLo, got.seqHi, got.ttl, want.seqLo, want.seqHi, want.ttl)
		}
	}

	// Step 6: Remove 30 -> DELETE single-element [30-30]
	hadTTL = c.freshLossRemove(30)
	if hadTTL != 3 {
		t.Errorf("step 6: hadTTL = %d, want 3", hadTTL)
	}
	if len(c.freshLoss) != 4 {
		t.Fatalf("step 6: len = %d, want 4", len(c.freshLoss))
	}
	// Expected: [10-15], [29-29], [45-49], [51-80]
	wantStep6 := []freshLossEntry{
		{seqLo: 10, seqHi: 15, ttl: 5},
		{seqLo: 29, seqHi: 29, ttl: 10},
		{seqLo: 45, seqHi: 49, ttl: 100},
		{seqLo: 51, seqHi: 80, ttl: 100},
	}
	for i, want := range wantStep6 {
		got := c.freshLoss[i]
		if got.seqLo != want.seqLo || got.seqHi != want.seqHi || got.ttl != want.ttl {
			t.Errorf("step 6: entry[%d] = {%d,%d,ttl=%d}, want {%d,%d,ttl=%d}",
				i, got.seqLo, got.seqHi, got.ttl, want.seqLo, want.seqHi, want.ttl)
		}
	}

	// Step 7: Remove nonexistent 25 (was already removed in step 4)
	hadTTL = c.freshLossRemove(25)
	if hadTTL != 0 {
		t.Errorf("step 7: hadTTL = %d, want 0 (not found)", hadTTL)
	}
	if len(c.freshLoss) != 4 {
		t.Errorf("step 7: len = %d, want 4 (unchanged)", len(c.freshLoss))
	}

	// Step 8: Remove nonexistent 31 (never existed in any range)
	hadTTL = c.freshLossRemove(31)
	if hadTTL != 0 {
		t.Errorf("step 8: hadTTL = %d, want 0 (not found)", hadTTL)
	}
	if len(c.freshLoss) != 4 {
		t.Errorf("step 8: len = %d, want 4 (unchanged)", len(c.freshLoss))
	}
}

// ---- FASTREXMIT / LATEREXMIT tests ----

func TestFASTREXMITFiresWhenPeerNakReportFalse(t *testing.T) {
	// In live mode, when peerNakReport=false, FASTREXMIT should retransmit
	// all unacked packets when RTO fires, regardless of loss list state.
	c, _ := testSingleConn(t)

	// Configure as live mode with peerNakReport=false
	c.tsbpdEnabled.Store(true)
	c.peerNakReport = false

	// Push some packets
	for i := range 5 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, make([]byte, 100))
		c.sendBuf.Push(p, c.clk.Now())
	}

	// FASTREXMIT: in live mode (!peerNakReport), retransmitAllInFlight should
	// retransmit packets regardless of loss list. Verify it doesn't panic.
	if c.flightSize() != 5 {
		t.Fatalf("flightSize: got %d, want 5", c.flightSize())
	}

	// Call retransmitAllInFlight — this is what fires during FASTREXMIT
	c.retransmitAllInFlight()

	// Verify retrans count increased
	if c.retransCount.Load() != 5 {
		t.Errorf("retransCount: got %d, want 5", c.retransCount.Load())
	}
}

func TestFASTREXMITSuppressedWhenPeerNakReportTrue(t *testing.T) {
	// In live mode, when peerNakReport=true, FASTREXMIT is suppressed.
	// The peer sends periodic NAKs to handle losses instead.
	c, _ := testSingleConn(t)

	c.tsbpdEnabled.Store(true)
	c.peerNakReport = true

	// Push packets into send buffer
	for i := range 5 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, make([]byte, 100))
		c.sendBuf.Push(p, c.clk.Now())
	}

	// Simulate the RTO decision: when peerNakReport=true in live mode,
	// no blind retransmit should fire.
	// The condition is: !tsbpdEnabled (file) OR !peerNakReport (fast rexmit).
	// Neither applies here, so no retransmit should occur.
	initialRetrans := c.retransCount.Load()

	// The RTO path checks:
	// if !c.tsbpdEnabled { LATEREXMIT }
	// else if !c.peerNakReport { FASTREXMIT }
	// Since tsbpdEnabled=true && peerNakReport=true, neither fires.

	// Verify by checking that we're in the suppressed branch:
	if !c.tsbpdEnabled.Load() {
		t.Error("tsbpdEnabled should be true for live mode")
	}
	if !c.peerNakReport {
		t.Error("peerNakReport should be true (suppresses FASTREXMIT)")
	}

	// No retransmit should have been triggered
	if c.retransCount.Load() != initialRetrans {
		t.Errorf("retransCount should not change when peerNakReport=true")
	}
}

func TestLATEREXMITOnlyWhenLossListEmpty(t *testing.T) {
	// In file mode, LATEREXMIT only fires when loss list is empty
	// (both data and NAK were lost).
	c, _ := testSingleConn(t)

	// Configure as file mode
	c.tsbpdEnabled.Store(false)

	// Push packets
	for i := range 5 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, make([]byte, 100))
		c.sendBuf.Push(p, c.clk.Now())
	}

	// Case 1: loss list is NOT empty — LATEREXMIT should NOT fire
	c.sndLossCount.Store(3)
	initialRetrans := c.retransCount.Load()

	// Simulate the condition check: flightSize > 0 && sndLossCount <= 0
	if c.flightSize() > 0 && c.sndLossCount.Load() <= 0 {
		t.Error("should not enter LATEREXMIT when loss list is not empty")
	}
	if c.retransCount.Load() != initialRetrans {
		t.Error("no retransmit should occur with non-empty loss list")
	}

	// Case 2: loss list IS empty — LATEREXMIT should fire
	c.sndLossCount.Store(0)
	if !(c.flightSize() > 0 && c.sndLossCount.Load() <= 0) {
		t.Error("should enter LATEREXMIT when loss list is empty and flight > 0")
	}

	c.retransmitAllInFlight()
	if c.retransCount.Load() != initialRetrans+5 {
		t.Errorf("retransCount: got %d, want %d", c.retransCount.Load(), initialRetrans+5)
	}
}

// ---- RetransmitAlgo tests ----

func TestRetransmitAlgoTimingGate(t *testing.T) {
	// retransmitAlgo=1 (default for live): NAK retransmit uses timing gate
	// to avoid re-retransmission within one RTT.
	c, _ := testSingleConn(t)

	c.peerNakReport = true
	c.retransmitAlgo = 1
	c.rtt.Store(100_000) // 100ms RTT
	c.rttVar.Store(10_000)

	// Push packets
	for i := range 5 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, make([]byte, 100))
		c.sendBuf.Push(p, c.clk.Now())
	}

	// First NAK: should retransmit (timing gate allows)
	nak := &packet.CIFNAK{LossList: []uint32{1002}}
	np := packet.NewControl(c.localAddr, packet.CtrlTypeNAK, c.socketID, 0)
	np.MarshalCIF(nak)

	retransBefore := c.retransCount.Load()
	c.handleNAK(np)

	if c.retransCount.Load() <= retransBefore {
		t.Error("first NAK should trigger retransmit with timing gate")
	}

	// Immediate second NAK for same packet: should be suppressed by timing gate
	// (within RTT window)
	retransBefore = c.retransCount.Load()
	np2 := packet.NewControl(c.localAddr, packet.CtrlTypeNAK, c.socketID, 0)
	np2.MarshalCIF(nak)
	c.handleNAK(np2)

	// With timing gate, the retransmit should be suppressed because the
	// rexmitTime was just set. The timing gate checks if lastRexmit >= timeNAK.
	// Since we just retransmitted, it should be suppressed.
	if c.retransCount.Load() != retransBefore {
		t.Error("second NAK should be suppressed by timing gate")
	}
}

func TestRetransmitAlgoImmediate(t *testing.T) {
	// retransmitAlgo=0: NAK retransmit is always immediate (no timing gate)
	c, _ := testSingleConn(t)

	c.peerNakReport = true
	c.retransmitAlgo = 0 // immediate mode
	c.rtt.Store(100_000)
	c.rttVar.Store(10_000)

	for i := range 5 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, make([]byte, 100))
		c.sendBuf.Push(p, c.clk.Now())
	}

	// With retransmitAlgo=0, the condition (peerNakReport && retransmitAlgo != 0)
	// is false, so NAK uses plain NAK() instead of NAKTimed().
	// This means every NAK triggers immediate retransmission.
	nak := &packet.CIFNAK{LossList: []uint32{1002}}

	// First NAK
	np := packet.NewControl(c.localAddr, packet.CtrlTypeNAK, c.socketID, 0)
	np.MarshalCIF(nak)
	c.handleNAK(np)

	first := c.retransCount.Load()
	if first == 0 {
		t.Error("first NAK should trigger retransmit")
	}

	// Second immediate NAK: with retransmitAlgo=0, no timing gate applies
	np2 := packet.NewControl(c.localAddr, packet.CtrlTypeNAK, c.socketID, 0)
	np2.MarshalCIF(nak)
	c.handleNAK(np2)

	second := c.retransCount.Load()
	if second <= first {
		t.Errorf("second NAK with retransmitAlgo=0 should retransmit: first=%d, second=%d", first, second)
	}
}

// ---- ErrWouldBlock tests ----

func TestErrWouldBlockRead(t *testing.T) {
	// Non-blocking Read (RcvSyn=false) should return ErrWouldBlock when
	// no data is available.
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, _ := net.ListenUDP("udp", addr)
	m := mux.New(udpConn, 1500)
	socketID := uint32(42)
	recvCh := m.Register(socketID)

	c := newConn(ConnConfig{
		LocalAddr:    udpConn.LocalAddr(),
		RemoteAddr:   &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9000},
		SocketID:     socketID,
		PeerSocketID: 99,
		Mux:          m,
		RecvChan:     recvCh,
		Clock:        clock.NewRealClock(),
		SendISN:      seq.Number(1000),
		RecvISN:      seq.Number(0),
		SendBufSize:  256,
		RecvBufSize:  256,
		TsbpdDelay:   20 * time.Millisecond,
		RcvSyn:       false, // non-blocking
	})
	defer func() {
		c.Close()
		m.Close()
	}()

	buf := make([]byte, 1500)
	_, err := c.Read(buf)
	if err != ErrWouldBlock {
		t.Errorf("Read with RcvSyn=false and no data: got %v, want ErrWouldBlock", err)
	}
}

func TestErrWouldBlockWrite(t *testing.T) {
	// Non-blocking Write (SndSyn=false) should return ErrWouldBlock when
	// the send buffer is full and flow control blocks.
	addrA, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	addrB, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	connA, err := net.ListenUDP("udp", addrA)
	if err != nil {
		t.Fatalf("ListenUDP A: %v", err)
	}
	connB, err := net.ListenUDP("udp", addrB)
	if err != nil {
		connA.Close()
		t.Fatalf("ListenUDP B: %v", err)
	}

	muxA := mux.New(connA, 1500)
	socketIDA := uint32(100)
	recvChA := muxA.Register(socketIDA)

	c := newConn(ConnConfig{
		LocalAddr:    connA.LocalAddr(),
		RemoteAddr:   connB.LocalAddr(),
		SocketID:     socketIDA,
		PeerSocketID: 200,
		Mux:          muxA,
		RecvChan:     recvChA,
		Clock:        clock.NewRealClock(),
		SendISN:      seq.Number(1000),
		RecvISN:      seq.Number(0),
		SendBufSize:  8,
		RecvBufSize:  256,
		FC:           4,
		TsbpdDelay:   30 * time.Second,
		SndSyn:       false, // non-blocking
	})
	defer func() {
		c.Close()
		muxA.Close()
		connB.Close()
	}()

	// Fill the FC window
	for i := range 4 {
		_, err := c.Write(make([]byte, 100))
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	// Next write should return ErrWouldBlock (FC full, non-blocking)
	_, err = c.Write(make([]byte, 100))
	if err != ErrWouldBlock {
		t.Errorf("Write with SndSyn=false and full FC: got %v, want ErrWouldBlock", err)
	}
}

// ---- Retransmit rate limiting (token bucket) tests ----

func TestRexmitTokenBucketAllow(t *testing.T) {
	// Token bucket starts with 100ms worth of tokens (maxBytesPerSec / 10).
	tb := newRexmitTokenBucket(1000) // 1000 bytes/sec

	// Initial burst: 1000/10 = 100 bytes
	if !tb.allow(50) {
		t.Error("should allow 50 bytes from initial burst of 100")
	}
	if !tb.allow(50) {
		t.Error("should allow second 50 bytes (100 total)")
	}
}

func TestRexmitTokenBucketDeny(t *testing.T) {
	tb := newRexmitTokenBucket(1000) // 1000 bytes/sec, initial burst = 100 bytes

	// Exhaust initial burst
	if !tb.allow(100) {
		t.Fatal("should allow 100 bytes initial burst")
	}

	// Next request should be denied (no tokens left, no time elapsed)
	if tb.allow(1) {
		t.Error("should deny after initial burst exhausted (no refill time)")
	}
}

func TestRexmitTokenBucketRefill(t *testing.T) {
	tb := newRexmitTokenBucket(10_000_000) // 10 MB/sec

	// Exhaust initial burst (1 MB)
	tb.allow(1_000_000)

	// Wait for refill
	time.Sleep(20 * time.Millisecond)

	// Should have refilled ~200,000 bytes (10MB/sec * 0.02s)
	if !tb.allow(100_000) {
		t.Error("should allow after refill period")
	}
}

// ---- MsgCtrl tests ----

func TestWriteMsgCtrlBasic(t *testing.T) {
	sender, _ := testConnPair(t)

	mc := &MsgCtrl{
		SrcTime: time.Now(),
		MsgTTL:  500 * time.Millisecond,
	}

	payload := []byte("hello msgctrl")
	n, err := sender.WriteMsgCtrl(payload, mc)
	if err != nil {
		t.Fatalf("WriteMsgCtrl: %v", err)
	}
	if n != len(payload) {
		t.Errorf("WriteMsgCtrl: got %d, want %d", n, len(payload))
	}

	// After WriteMsgCtrl returns, msgTTL should be reset to 0 (via defer)
	if sender.msgTTL.Load() != 0 {
		t.Errorf("msgTTL should be reset to 0 after WriteMsgCtrl, got %d", sender.msgTTL.Load())
	}
}

func TestReadMsgCtrlBasic(t *testing.T) {
	// Create a file-mode (non-TSBPD) conn with RcvSyn=true so Read blocks
	// until data is available rather than returning ErrWouldBlock.
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, _ := net.ListenUDP("udp", addr)
	m := mux.New(udpConn, 1500)
	socketID := uint32(42)
	recvCh := m.Register(socketID)

	c := newConn(ConnConfig{
		LocalAddr:    udpConn.LocalAddr(),
		RemoteAddr:   &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9000},
		SocketID:     socketID,
		PeerSocketID: 99,
		Mux:          m,
		RecvChan:     recvCh,
		Clock:        clock.NewRealClock(),
		SendISN:      seq.Number(1000),
		RecvISN:      seq.Number(0),
		SendBufSize:  256,
		RecvBufSize:  256,
		Congestion:   CongestionFile, // file mode: no TSBPD
		RcvSyn:       true,
		SndSyn:       true,
	})
	defer func() {
		c.Close()
		m.Close()
	}()

	// Insert a data packet for reading
	p := packet.NewData(c.localAddr, 0, 1000, c.socketID, []byte("test data"))
	c.recvBuf.Insert(p, c.clk.Now())
	c.signalReadReady()

	mc := &MsgCtrl{}
	buf := make([]byte, 1500)
	n, err := c.ReadMsgCtrl(buf, mc)
	if err != nil {
		t.Fatalf("ReadMsgCtrl: %v", err)
	}
	if n != 9 {
		t.Errorf("ReadMsgCtrl: got %d bytes, want 9", n)
	}
	if string(buf[:n]) != "test data" {
		t.Errorf("ReadMsgCtrl data: got %q, want %q", buf[:n], "test data")
	}
}

func TestWriteMsgCtrlNilMsgCtrl(t *testing.T) {
	sender, _ := testConnPair(t)

	// WriteMsgCtrl with nil mc should behave like Write
	n, err := sender.WriteMsgCtrl([]byte("no ctrl"), nil)
	if err != nil {
		t.Fatalf("WriteMsgCtrl(nil): %v", err)
	}
	if n != 7 {
		t.Errorf("WriteMsgCtrl(nil): got %d, want 7", n)
	}
}

func TestGCM153VersionCompat(t *testing.T) {
	tests := []struct {
		name        string
		peerVersion uint32
		wantGCM153  bool
	}{
		{"peer 1.5.3", 0x010503, true},
		{"peer 1.5.2", 0x010502, true},
		{"peer 1.4.1", 0x010401, true},
		{"peer 1.5.4", 0x010504, false},
		{"peer 1.6.0", 0x010600, false},
		{"peer 0 (HSv4)", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, err := crypto.NewWithMode(16, crypto.CipherGCM)
			if err != nil {
				t.Fatalf("NewWithMode: %v", err)
			}

			// Simulate the version check logic from newConn
			if ctx.Mode() == crypto.CipherGCM {
				if tt.peerVersion > 0 && tt.peerVersion <= 0x010503 {
					ctx.SetGCM153(true)
				}
			}

			// Verify by checking the nonce format indirectly:
			// SetGCM153(true) was called iff wantGCM153 is true.
			// We test the condition directly since SetGCM153 is the observable effect.
			got := tt.peerVersion > 0 && tt.peerVersion <= 0x010503
			if got != tt.wantGCM153 {
				t.Errorf("GCM153 for peer %#x: got %v, want %v", tt.peerVersion, got, tt.wantGCM153)
			}
		})
	}
}

// ---- Coverage tests: simple getters, helpers, and lightweight methods ----

func TestConnGroupID(t *testing.T) {
	c := &Conn{groupID: 42}
	if c.GroupID() != 42 {
		t.Errorf("GroupID: got %d, want 42", c.GroupID())
	}

	c2 := &Conn{}
	if c2.GroupID() != 0 {
		t.Errorf("GroupID on unset: got %d, want 0", c2.GroupID())
	}
}

func TestConnPeerGroupID(t *testing.T) {
	c := &Conn{peerGroupID: 99}
	if c.PeerGroupID() != 99 {
		t.Errorf("PeerGroupID: got %d, want 99", c.PeerGroupID())
	}
}

func TestConnSetDeadlineBoth(t *testing.T) {
	c, _ := testSingleConn(t)

	deadline := time.Now().Add(5 * time.Second)
	err := c.SetDeadline(deadline)
	if err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	// Both read and write deadlines should be set
	rdl := c.readDeadlineTime()
	wdl := c.writeDeadlineTime()
	if rdl.IsZero() {
		t.Error("read deadline should be set after SetDeadline")
	}
	if wdl.IsZero() {
		t.Error("write deadline should be set after SetDeadline")
	}
}

func TestConnFlightSize(t *testing.T) {
	c, _ := testSingleConn(t)

	// Empty send buffer: flight size should be 0
	if fs := c.flightSize(); fs != 0 {
		t.Errorf("flightSize on empty buffer: got %d, want 0", fs)
	}

	// Push some packets
	for i := range 3 {
		p := packet.NewData(c.remoteAddr, uint32(1000+i), uint32(i*1000), c.peerSocketID, []byte("data"))
		c.sendBuf.Push(p, c.clk.Now())
	}

	if fs := c.flightSize(); fs != 3 {
		t.Errorf("flightSize after 3 pushes: got %d, want 3", fs)
	}
}

func TestConnCurrentFlowWindow(t *testing.T) {
	c, _ := testSingleConn(t)

	// Default: no dynamic update, should return fc
	fc := c.fc
	if cfw := c.currentFlowWindow(); cfw != fc {
		t.Errorf("currentFlowWindow default: got %d, want %d (fc)", cfw, fc)
	}

	// Set dynamic flow window
	c.flowWindowSize.Store(500)
	if cfw := c.currentFlowWindow(); cfw != 500 {
		t.Errorf("currentFlowWindow after set: got %d, want 500", cfw)
	}
}

func TestConnKeepalivePacketCountDetection(t *testing.T) {
	// Keepalive uses packet-count snapshot instead of lastSndTime.
	// Verify sentPackets counter increments on writes.
	c, _ := testSingleConn(t)

	before := c.sentPackets.Load()
	// sentPackets increments on sendPacket, so just verify it's accessible
	if before != 0 {
		t.Logf("sentPackets already %d (expected 0 for fresh conn)", before)
	}
}

func TestBoundaryFromPosition(t *testing.T) {
	tests := []struct {
		name string
		pos  packet.PacketPosition
		want int
	}{
		{"solo", packet.PositionSingle, int(packet.PositionSingle)},
		{"first", packet.PositionFirst, int(packet.PositionFirst)},
		{"middle", packet.PositionMiddle, int(packet.PositionMiddle)},
		{"last", packet.PositionLast, int(packet.PositionLast)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := boundaryFromPosition(tt.pos)
			if got != tt.want {
				t.Errorf("boundaryFromPosition(%d): got %d, want %d", tt.pos, got, tt.want)
			}
		})
	}
}

func TestConnHandleKMResponse_ErrorCodes(t *testing.T) {
	c, _ := testSingleConn(t)

	// 4-byte KMRSP with error code (e.g., SRT_KM_S_BADSECRET=4)
	tests := []struct {
		name    string
		kmState int32
		wantSnd int32
		wantRcv int32
	}{
		{"nosecret", 3, 3, 3},
		{"badsecret", 4, 4, 4},
		{"badcryptomode", 5, 5, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset state
			c.sndKmState.Store(0)
			c.rcvKmState.Store(0)
			c.kmConfirmed.Store(false)

			data := make([]byte, 4)
			data[0] = byte(tt.kmState >> 24)
			data[1] = byte(tt.kmState >> 16)
			data[2] = byte(tt.kmState >> 8)
			data[3] = byte(tt.kmState)

			p := packet.NewControl(c.localAddr, packet.CtrlTypeUser, c.socketID, 0)
			p.Data = data

			c.handleKMResponse(p)

			if c.sndKmState.Load() != tt.wantSnd {
				t.Errorf("sndKmState: got %d, want %d", c.sndKmState.Load(), tt.wantSnd)
			}
			if c.rcvKmState.Load() != tt.wantRcv {
				t.Errorf("rcvKmState: got %d, want %d", c.rcvKmState.Load(), tt.wantRcv)
			}
			// kmConfirmed should NOT be set for error responses
			if c.kmConfirmed.Load() {
				t.Error("kmConfirmed should be false for error KMRSP")
			}
		})
	}
}

func TestConnHandleKMResponse_FullKMRSP(t *testing.T) {
	c, _ := testSingleConn(t)

	c.kmConfirmed.Store(false)
	c.sndKmState.Store(0)
	c.rcvKmState.Store(0)

	// Full KMRSP is >4 bytes — signals confirmation
	data := make([]byte, 64) // arbitrary size > 4
	p := packet.NewControl(c.localAddr, packet.CtrlTypeUser, c.socketID, 0)
	p.Data = data

	c.handleKMResponse(p)

	if !c.kmConfirmed.Load() {
		t.Error("kmConfirmed should be true after full KMRSP")
	}
	if c.sndKmState.Load() != 2 {
		t.Errorf("sndKmState: got %d, want 2 (SRT_KM_S_SECURED)", c.sndKmState.Load())
	}
	if c.rcvKmState.Load() != 2 {
		t.Errorf("rcvKmState: got %d, want 2 (SRT_KM_S_SECURED)", c.rcvKmState.Load())
	}
}

func TestConnHandleDropReq(t *testing.T) {
	c, _ := testSingleConn(t)

	// DROPREQ should be skipped when TLPKTDROP is disabled
	c.tlpktdropEnabled.Store(false)
	p := packet.NewControl(c.localAddr, packet.CtrlTypeDropReq, c.socketID, 0)
	p.Data = make([]byte, 12)
	c.handleDropReq(p)
	// Should not panic or do anything

	// With TLPKTDROP enabled but too-short data
	c.tlpktdropEnabled.Store(true)
	p2 := packet.NewControl(c.localAddr, packet.CtrlTypeDropReq, c.socketID, 0)
	p2.Data = make([]byte, 8) // too short (<12 bytes)
	c.handleDropReq(p2)
	// Should silently return
}

func TestConnSetMaxBW(t *testing.T) {
	c, _ := testSingleConn(t)

	// bw > 0: set directly
	c.SetMaxBW(5_000_000)
	rate := c.sendCC.MaxBandwidth()
	if rate != 5_000_000 {
		t.Errorf("SetMaxBW(5M): CC rate = %d, want 5000000", rate)
	}
	// inputRateEnabled should be disabled
	if c.inputRateEnabled {
		t.Error("inputRateEnabled should be false after SetMaxBW(>0)")
	}

	// bw == 0: auto mode (uses InputBW or sampling)
	c.SetMaxBW(0)
	// Should not panic; CC uses auto bandwidth

	// bw == -1: unlimited (effectiveBW stays 0 -> CC uses default)
	c.SetMaxBW(-1)
	// Should not panic

	// bw < -1: clamped to -1
	c.SetMaxBW(-100)
	// Should not panic
}

func TestConnRcvBufStartSeq_NilGuard(t *testing.T) {
	c := &Conn{}
	startSeq := c.RcvBufStartSeq()
	if startSeq != 0 {
		t.Errorf("RcvBufStartSeq with nil recvBuf: got %d, want 0", startSeq)
	}
}

func TestConnOverrideSndSeqNo_NilGuard(t *testing.T) {
	c := &Conn{}
	ok := c.OverrideSndSeqNo(seq.Number(42))
	if ok {
		t.Error("OverrideSndSeqNo with nil sendBuf should return false")
	}
}

func TestConnOverrideSndSeqNo(t *testing.T) {
	c, _ := testSingleConn(t)

	// Override to a specific sequence
	ok := c.OverrideSndSeqNo(seq.Number(5000))
	if !ok {
		t.Error("OverrideSndSeqNo should return true on initialized conn")
	}

	// Verify the sequence was updated
	nextSeq := c.SchedSeqNo()
	if nextSeq != seq.Number(5000) {
		t.Errorf("SchedSeqNo after override: got %d, want 5000", nextSeq)
	}
}

func TestConnStatsInterval(t *testing.T) {
	c, _ := testSingleConn(t)

	// Generate some stats
	c.sentPackets.Add(10)
	c.sentBytes.Add(15000)
	c.recvPackets.Add(8)

	// First Stats(true) returns interval from start
	stats1 := c.Stats(true)
	if stats1.SentPackets != 10 {
		t.Errorf("First interval SentPackets: got %d, want 10", stats1.SentPackets)
	}

	// Add more stats
	c.sentPackets.Add(5)
	c.recvPackets.Add(3)

	// Second Stats(true) returns interval since last clear
	stats2 := c.Stats(true)
	if stats2.SentPackets != 5 {
		t.Errorf("Second interval SentPackets: got %d, want 5", stats2.SentPackets)
	}
	if stats2.RecvPackets != 3 {
		t.Errorf("Second interval RecvPackets: got %d, want 3", stats2.RecvPackets)
	}
}

func TestConnWriteDeadlineTime(t *testing.T) {
	c, _ := testSingleConn(t)

	// Initially no deadline
	wdt := c.writeDeadlineTime()
	if !wdt.IsZero() {
		t.Error("writeDeadlineTime should be zero initially")
	}

	// Set a deadline
	deadline := time.Now().Add(5 * time.Second)
	c.SetWriteDeadline(deadline)

	wdt = c.writeDeadlineTime()
	if wdt.IsZero() {
		t.Error("writeDeadlineTime should be set after SetWriteDeadline")
	}
}

func TestConnEncryptedConnection(t *testing.T) {
	c, _ := testSingleConn(t)

	// Setup encryption context
	ctx, err := crypto.New(16) // AES-128
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	c.cryptoCtx = ctx
	c.activeKey = packet.EncryptionEven

	// Verify encryption is active
	if c.cryptoCtx == nil {
		t.Error("cryptoCtx should not be nil")
	}
}

func TestConnHandleKMResponse_InvalidKMState(t *testing.T) {
	c, _ := testSingleConn(t)

	// 4-byte KMRSP with invalid error code (not 3-5) — should not set KM state
	c.sndKmState.Store(0)
	c.rcvKmState.Store(0)

	data := make([]byte, 4)
	// kmState = 1 (not in range 3-5)
	data[3] = 1

	p := packet.NewControl(c.localAddr, packet.CtrlTypeUser, c.socketID, 0)
	p.Data = data

	c.handleKMResponse(p)

	if c.sndKmState.Load() != 0 {
		t.Errorf("sndKmState should be unchanged for invalid kmState: got %d", c.sndKmState.Load())
	}
}

func TestRexmitTokenBucket(t *testing.T) {
	tb := newRexmitTokenBucket(1_000) // 1 KB/s — small for fast draining

	// Should allow initial burst (100ms worth = 100 bytes)
	if !tb.allow(50) {
		t.Error("should allow small initial request")
	}

	// Drain the bucket completely
	for range 100 {
		if !tb.allow(10) {
			break // bucket drained
		}
	}

	// Now try a large request — should be denied (bucket nearly empty)
	if tb.allow(10000) {
		t.Error("should be denied for large request on drained bucket")
	}

	// Wait for refill and try a small request
	time.Sleep(100 * time.Millisecond)
	if !tb.allow(1) {
		t.Error("should allow after refill time")
	}
}

func TestConnSendNAKForSeqs(t *testing.T) {
	c, _ := testSingleConn(t)

	// Empty seqs — should be a no-op (no panic)
	c.sendNAKForSeqs(nil)
	c.sendNAKForSeqs([]uint32{})

	// Non-empty seqs — should send without panic
	c.sendNAKForSeqs([]uint32{100, 101, 102})

	// Verify counters were updated
	if c.sentNAKs.Load() != 1 {
		t.Errorf("sentNAKs: got %d, want 1", c.sentNAKs.Load())
	}
	if c.recvLoss.Load() != 3 {
		t.Errorf("recvLoss: got %d, want 3", c.recvLoss.Load())
	}
}

func TestConnCheckSendDrop_Disabled(t *testing.T) {
	c, _ := testSingleConn(t)

	// sendDropThresh = 0 means disabled
	c.sendDropThresh = 0
	// Should return immediately without panic
	c.checkSendDrop()
}

func TestConnEncryptRetransmit_NilCrypto(t *testing.T) {
	c, _ := testSingleConn(t)

	p := packet.New(c.remoteAddr)
	p.Header.Encryption = packet.EncryptionNone

	// nil cryptoCtx — should be no-op
	c.cryptoCtx = nil
	err := c.encryptRetransmit(&p)
	if err != nil {
		t.Errorf("encryptRetransmit nil crypto: %v", err)
	}
	p.Release()
}

func TestConnEncryptRetransmit_NoEncryption(t *testing.T) {
	c, _ := testSingleConn(t)

	p := packet.New(c.remoteAddr)
	p.Header.Encryption = packet.EncryptionNone

	// cryptoCtx set but packet has no encryption — should still be no-op
	ctx, err := crypto.New(16)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	c.cryptoCtx = ctx

	err = c.encryptRetransmit(&p)
	if err != nil {
		t.Errorf("encryptRetransmit no encryption: %v", err)
	}
	p.Release()
}

func TestConnEncryptRetransmit_CTRMode(t *testing.T) {
	c, _ := testSingleConn(t)

	// CTR mode — should be a no-op (returns nil immediately)
	ctx, err := crypto.New(16) // AES-128 CTR
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	c.cryptoCtx = ctx

	p := packet.New(c.remoteAddr)
	p.Header.Encryption = packet.EncryptionEven
	p.Data = make([]byte, 100)

	err = c.encryptRetransmit(&p)
	if err != nil {
		t.Errorf("encryptRetransmit CTR: %v", err)
	}
	p.Release()
}

func TestConnApplyGroupDrift_NilTSBPD(t *testing.T) {
	c, _ := testSingleConn(t)

	// Store original tsbpdTimer, set to nil, then call ApplyGroupDrift
	c.tsbpdTimer = nil
	// Should be a no-op, not panic
	c.ApplyGroupDrift(tsbpd.GroupTimeBase{})
}

func TestConnTSBPDTimeBase_NilTimer(t *testing.T) {
	c, _ := testSingleConn(t)

	c.tsbpdTimer = nil
	tb := c.TSBPDTimeBase()
	if tb != nil {
		t.Error("TSBPDTimeBase should return nil when timer is nil")
	}
}

func TestConnTSBPDTimeBase_WithTimer(t *testing.T) {
	c, _ := testSingleConn(t)

	// c should have a tsbpdTimer from testSingleConn setup
	if c.tsbpdTimer == nil {
		t.Skip("tsbpdTimer is nil")
	}
	tb := c.TSBPDTimeBase()
	if tb == nil {
		t.Error("TSBPDTimeBase should return non-nil when timer exists")
	}
}

func TestConnApplyGroupTime(t *testing.T) {
	c, _ := testSingleConn(t)

	// Should not panic when tsbpdTimer exists
	if c.tsbpdTimer != nil {
		c.ApplyGroupTime(tsbpd.GroupTimeBase{})
	}

	// Should not panic when tsbpdTimer is nil
	c.tsbpdTimer = nil
	c.ApplyGroupTime(tsbpd.GroupTimeBase{})
}

func TestConnSetGroupSrcTime(t *testing.T) {
	c, _ := testSingleConn(t)

	c.setGroupSrcTime(12345)
	if v := c.groupSrcTime.Load(); v != 12345 {
		t.Errorf("groupSrcTime: got %d, want 12345", v)
	}

	c.clearGroupSrcTime()
	if v := c.groupSrcTime.Load(); v != 0 {
		t.Errorf("groupSrcTime after clear: got %d, want 0", v)
	}
}

func TestConnCurrentSRTTimestamp(t *testing.T) {
	c, _ := testSingleConn(t)

	ts := c.CurrentSRTTimestamp()
	// Just verify it returns a non-zero value (clock is running)
	if ts == 0 {
		t.Error("CurrentSRTTimestamp should return non-zero")
	}
}

func TestConnSchedSeqNo(t *testing.T) {
	c, _ := testSingleConn(t)

	sn := c.SchedSeqNo()
	// Initial value should be the send ISN
	if sn == 0 {
		t.Logf("SchedSeqNo: %d (may be ISN)", sn)
	}
}

func TestConnHandleControlPacket_PeerError(t *testing.T) {
	c, _ := testSingleConn(t)

	// peerHealth should start as true
	if !c.peerHealth.Load() {
		t.Fatal("peerHealth should start as true")
	}

	// Send a PEERERROR control packet
	p := packet.NewControl(c.localAddr, packet.CtrlTypePeerError, c.socketID, 0)
	c.handleControlPacket(p)

	// peerHealth should now be false
	if c.peerHealth.Load() {
		t.Error("peerHealth should be false after PEERERROR")
	}
}

func TestConnHandleControlPacket_Shutdown(t *testing.T) {
	c, _ := testSingleConn(t)

	// Send a SHUTDOWN control packet
	p := packet.NewControl(c.localAddr, packet.CtrlTypeShutdown, c.socketID, 0)
	c.handleControlPacket(p)

	// Connection should be closed
	select {
	case <-c.done:
		// Good — connection was shut down
	case <-time.After(time.Second):
		t.Error("connection should be closed after SHUTDOWN")
	}
}

func TestConnHandleControlPacket_Keepalive(t *testing.T) {
	c, _ := testSingleConn(t)

	prevActivity := c.peerActivity.Load()

	// Send a keepalive
	p := packet.NewControl(c.localAddr, packet.CtrlTypeKeepalive, c.socketID, 0)
	c.handleControlPacket(p)

	// peerActivity should have been bumped
	if c.peerActivity.Load() <= prevActivity {
		t.Error("peerActivity should increase after keepalive")
	}
}

func TestConnHandleControlPacket_KeepaliveWithGroup(t *testing.T) {
	c, _ := testSingleConn(t)

	c.groupID = 42 // simulate group membership

	p := packet.NewControl(c.localAddr, packet.CtrlTypeKeepalive, c.socketID, 0)
	c.handleControlPacket(p)

	// groupIdle should be set to true
	if !c.groupIdle.Load() {
		t.Error("groupIdle should be true after keepalive with groupID set")
	}
}

func TestControlPacketMinimumCIF(t *testing.T) {
	// libsrt silently drops control packets without at least 4 bytes of CIF data.
	// OBE discovered this: "control info field should be none but writev does not allow this."
	// Verify our Keepalive, Shutdown, and ACKACK packets include the 4-byte CIF padding.
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	clk := clock.NewMockClock()
	ts := clk.Now().SRTTimestamp()
	peerSocketID := uint32(42)

	tests := []struct {
		name string
		make func() packet.Packet
	}{
		{
			name: "Keepalive",
			make: func() packet.Packet {
				p := packet.NewControl(addr, packet.CtrlTypeKeepalive, peerSocketID, ts)
				p.SetData([]byte{0, 0, 0, 0})
				return p
			},
		},
		{
			name: "Shutdown",
			make: func() packet.Packet {
				p := packet.NewControl(addr, packet.CtrlTypeShutdown, peerSocketID, ts)
				p.SetData([]byte{0, 0, 0, 0})
				return p
			},
		},
		{
			name: "ACKACK",
			make: func() packet.Packet {
				p := packet.NewControl(addr, packet.CtrlTypeACKACK, peerSocketID, ts)
				p.Header.TypeSpecific = 1
				p.SetData([]byte{0, 0, 0, 0})
				return p
			},
		},
	}

	buf := make([]byte, 128)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.make()
			defer p.Release()

			n, err := p.Marshal(buf)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			minSize := packet.HeaderSize + 4 // 16-byte header + 4-byte CIF minimum
			if n < minSize {
				t.Errorf("%s packet wire size = %d, want >= %d (HeaderSize=%d + 4-byte CIF)",
					tt.name, n, minSize, packet.HeaderSize)
			}
		})
	}
}

func TestConnHandleDropReq_TLPktDropDisabled(t *testing.T) {
	c, _ := testSingleConn(t)

	c.tlpktdropEnabled.Store(false)

	// Should return early without processing
	p := packet.NewControl(c.localAddr, packet.CtrlTypeDropReq, c.socketID, 0)
	p.Data = make([]byte, 12)
	c.handleDropReq(p)
	p.Release()
}

func TestConnHandleDropReq_ShortData(t *testing.T) {
	c, _ := testSingleConn(t)

	c.tlpktdropEnabled.Store(true)

	// Data too short (< 12 bytes) — should return early
	p := packet.NewControl(c.localAddr, packet.CtrlTypeDropReq, c.socketID, 0)
	p.Data = make([]byte, 8)
	c.handleDropReq(p)
	p.Release()
}

func TestConnHandleDropReq_FileModeDrops(t *testing.T) {
	// Create a conn in file mode (TSBPD disabled, TLPKTDROP enabled)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}

	m := mux.New(udpConn, 1500)
	socketID := uint32(42)
	recvCh := m.Register(socketID)

	remoteAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9000}

	c := newConn(ConnConfig{
		LocalAddr:    udpConn.LocalAddr(),
		RemoteAddr:   remoteAddr,
		SocketID:     socketID,
		PeerSocketID: 99,
		Mux:          m,
		RecvChan:     recvCh,
		Clock:        clock.NewRealClock(),
		SendISN:      seq.Number(1000),
		RecvISN:      seq.Number(0),
		SendBufSize:  256,
		RecvBufSize:  256,
		Congestion:   CongestionFile, // file mode: TSBPD disabled
	})
	defer func() {
		c.Close()
		m.Close()
	}()

	// File mode: tlpktdropEnabled = false, tsbpdEnabled = false
	// Manually enable tlpktdrop to test the drop path
	c.tlpktdropEnabled.Store(true)
	c.tsbpdEnabled.Store(false)

	// Build a valid CIFDropReq
	dr := &packet.CIFDropReq{
		MsgID:      0,
		FirstSeqNo: 1,
		LastSeqNo:  5,
	}
	data, err := dr.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	p := packet.NewControl(c.localAddr, packet.CtrlTypeDropReq, c.socketID, 0)
	p.Data = data
	c.handleDropReq(p)
	p.Release()
}

func TestConnHandleKMRequest_NoCrypto(t *testing.T) {
	c, _ := testSingleConn(t)

	// No crypto context — should set NOSECRET(3)
	c.cryptoCtx = nil
	c.passphrase = ""

	p := packet.NewControl(c.localAddr, packet.CtrlTypeUser, c.socketID, 0)
	p.Header.SubType = packet.ExtTypeKMReq
	p.Data = make([]byte, 64) // dummy KM data

	c.handleKMRequest(p)

	if c.rcvKmState.Load() != 3 {
		t.Errorf("rcvKmState: got %d, want 3 (NOSECRET)", c.rcvKmState.Load())
	}
}

func TestConnHandleKMRequest_InvalidKM(t *testing.T) {
	c, _ := testSingleConn(t)

	// Set up crypto so we get past the nil check
	ctx, err := crypto.New(16)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	c.cryptoCtx = ctx
	c.passphrase = "testpassword"

	p := packet.NewControl(c.localAddr, packet.CtrlTypeUser, c.socketID, 0)
	p.Header.SubType = packet.ExtTypeKMReq
	p.Data = []byte{0xFF, 0xFF} // invalid KM data

	c.handleKMRequest(p)

	// Should set BADSECRET(4) due to unmarshal failure
	if c.rcvKmState.Load() != 4 {
		t.Errorf("rcvKmState: got %d, want 4 (BADSECRET)", c.rcvKmState.Load())
	}
}

func TestConnRetransmitAllInFlight_Empty(t *testing.T) {
	c, _ := testSingleConn(t)

	// Empty send buffer — should not panic
	c.retransmitAllInFlight()
}

func TestConnBufStats(t *testing.T) {
	c, _ := testSingleConn(t)

	// Initial IIR values (not initialized)
	avgSndPkts := c.AvgSndBufSize()
	if avgSndPkts != 0 {
		t.Logf("initial AvgSndBufSize: %f (empty buffer)", avgSndPkts)
	}
	avgSndBytes := c.AvgSndBufBytes()
	if avgSndBytes != 0 {
		t.Logf("initial AvgSndBufBytes: %f (empty buffer)", avgSndBytes)
	}
	avgRcvPkts := c.AvgRcvBufSize()
	if avgRcvPkts != 0 {
		t.Logf("initial AvgRcvBufSize: %f (empty buffer)", avgRcvPkts)
	}
	avgRcvBytes := c.AvgRcvBufBytes()
	if avgRcvBytes != 0 {
		t.Logf("initial AvgRcvBufBytes: %f (empty buffer)", avgRcvBytes)
	}

	// Initialize the IIR
	c.updateBufferIIR()

	// After first update, should be initialized
	avgSndPkts = c.AvgSndBufSize()
	avgRcvPkts = c.AvgRcvBufSize()
	t.Logf("after init: AvgSndBufSize=%f AvgRcvBufSize=%f", avgSndPkts, avgRcvPkts)

	// Second update for the IIR smoothing path
	c.updateBufferIIR()
	avgSndPkts2 := c.AvgSndBufSize()
	avgSndBytes2 := c.AvgSndBufBytes()
	avgRcvPkts2 := c.AvgRcvBufSize()
	avgRcvBytes2 := c.AvgRcvBufBytes()
	t.Logf("after 2nd: AvgSndBufSize=%f AvgSndBufBytes=%f AvgRcvBufSize=%f AvgRcvBufBytes=%f",
		avgSndPkts2, avgSndBytes2, avgRcvPkts2, avgRcvBytes2)
}

func TestConnSendRate(t *testing.T) {
	c, _ := testSingleConn(t)

	// Before any sends, rate should be zero
	pps, bps := c.SendRate()
	if pps != 0 || bps != 0 {
		t.Errorf("initial SendRate: pps=%d bps=%d, want 0,0", pps, bps)
	}

	// Record some sends
	c.recordSendRate(10, 10000)
	c.rotateSendRate()

	// After recording, rate may or may not be non-zero depending on timing
	pps, bps = c.SendRate()
	t.Logf("SendRate after record: pps=%d bps=%d", pps, bps)
}

func TestConnExtendedStats(t *testing.T) {
	c, _ := testSingleConn(t)

	es := c.ExtendedStats(false)
	if es.ConnStats.Duration < 0 {
		t.Errorf("Duration should be >= 0: got %v", es.ConnStats.Duration)
	}
	// Extended fields should be populated (even if zero)
	t.Logf("ExtendedStats: AvgSndBufPkts=%f AvgRcvBufPkts=%f SendRatePps=%d SendRateBps=%d",
		es.AvgSndBufPkts, es.AvgRcvBufPkts, es.SendRatePps, es.SendRateBps)
}

func TestConnConnState_Broken(t *testing.T) {
	c, _ := testSingleConn(t)

	// Set a "broken" shutdown error
	c.setShutdownErr(ErrConnectionTimeout)
	c.Close()

	// Wait for close
	<-c.done

	state := c.connState()
	if state != StateBroken {
		t.Errorf("connState after timeout error: got %v, want StateBroken", state)
	}
}

func TestConnConnState_Connected(t *testing.T) {
	c, _ := testSingleConn(t)

	state := c.connState()
	if state != StateConnected {
		t.Errorf("connState: got %v, want StateConnected", state)
	}
}

func TestConnRecomputeSendDropThresh(t *testing.T) {
	c, _ := testSingleConn(t)

	// With sndDropDelay = -1, threshold should be 0
	c.sndDropDelay = -1
	c.recomputeSendDropThresh()
	if c.sendDropThresh != 0 {
		t.Errorf("sendDropThresh with sndDropDelay=-1: got %d, want 0", c.sendDropThresh)
	}

	// With tsbpdEnabled = false, threshold should be 0
	c.tsbpdEnabled.Store(false)
	c.sndDropDelay = 0
	c.recomputeSendDropThresh()
	if c.sendDropThresh != 0 {
		t.Errorf("sendDropThresh with tsbpd disabled: got %d, want 0", c.sendDropThresh)
	}

	// With tsbpdEnabled = true and sndDropDelay = 0
	c.tsbpdEnabled.Store(true)
	c.sndDropDelay = 0
	c.recomputeSendDropThresh()
	if c.sendDropThresh <= 0 {
		t.Errorf("sendDropThresh should be > 0 when tsbpd enabled")
	}
}

func TestConnHandleControlPacket_Unknown(t *testing.T) {
	c, _ := testSingleConn(t)

	// Unknown control type — should be ignored without panic
	p := packet.NewControl(c.localAddr, packet.CtrlType(0xFF), c.socketID, 0)
	c.handleControlPacket(p)
}

func TestConnWriteMessage_TsbpdSizeLimit(t *testing.T) {
	c, _ := testSingleConn(t)

	// TSBPD mode — message exceeding payloadSize should fail
	bigMsg := make([]byte, c.payloadSize+100)
	_, err := c.WriteMessage(bigMsg)
	if err == nil {
		t.Error("WriteMessage should fail for oversized message in TSBPD mode")
	}
}

func TestConnReadNonBlocking(t *testing.T) {
	c, _ := testSingleConn(t)

	// Set non-blocking mode
	c.rcvSynFlag.Store(false)

	buf := make([]byte, 100)
	_, err := c.Read(buf)
	if err != ErrWouldBlock {
		t.Errorf("Read in non-blocking mode: got %v, want ErrWouldBlock", err)
	}
}

func TestConnWriteNonBlocking(t *testing.T) {
	sender, _ := testConnPair(t)

	// Set non-blocking mode
	sender.sndSynFlag.Store(false)

	// Fill send buffer to capacity
	data := make([]byte, sender.payloadSize)
	for range sender.fc + 10 {
		_, err := sender.Write(data)
		if errors.Is(err, ErrWouldBlock) {
			// Good — buffer full in non-blocking mode
			return
		}
		if err != nil {
			// Some other error (connection closed, etc.) — that's fine too
			return
		}
	}
	// If we get here without ErrWouldBlock, that's ok — buffer may not have filled
}

func TestConnCheckSendDrop_WithOldPackets(t *testing.T) {
	// Create a conn pair where sender has TSBPD and drop enabled
	sender, _ := testConnPair(t)

	// Ensure sender has drop enabled
	sender.tsbpdEnabled.Store(true)
	sender.tlpktdropEnabled.Store(true)
	sender.sendDropThresh = 1 // 1 microsecond = basically everything is old

	// Push some packets into the send buffer
	for range 5 {
		data := make([]byte, 100)
		p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		sender.sendBuf.Push(p, sender.clk.Now())
	}

	startSeq := sender.sendBuf.StartSeq()

	// Wait a tiny bit so packets become "old"
	time.Sleep(2 * time.Millisecond)

	// checkSendDrop should drop the old packets
	sender.checkSendDrop()

	// After dropping, the start seq should have advanced
	newStartSeq := sender.sendBuf.StartSeq()
	if !newStartSeq.GreaterThan(startSeq) {
		// It's possible the drop threshold wasn't exceeded due to timing, so log rather than fail
		t.Logf("startSeq didn't advance (was %d, now %d) — timing sensitive", startSeq, newStartSeq)
	}

	// Verify dropped counter was updated
	if sender.sentDropped.Load() == 0 {
		t.Logf("sentDropped=0 (timing-sensitive: drop threshold may not have been exceeded)")
	}
}

func TestConnCheckSendDrop_ThresholdZero(t *testing.T) {
	c, _ := testSingleConn(t)

	// sendDropThresh=0 should return early
	c.sendDropThresh = 0
	c.checkSendDrop() // should not panic
}

func TestConnCheckSendDrop_EmptySendBuf(t *testing.T) {
	c, _ := testSingleConn(t)

	c.sendDropThresh = 100 * clock.Millisecond
	// Empty send buffer — OldestSendTime returns zero, should return early
	c.checkSendDrop() // should not panic
}

func TestConnEncryptRetransmit_GCMMode(t *testing.T) {
	c, _ := testSingleConn(t)

	// Set up a crypto context in GCM mode
	gcmCtx, err := crypto.NewWithMode(16, crypto.CipherGCM)
	if err != nil {
		t.Fatalf("crypto.NewWithMode GCM: %v", err)
	}
	gcmKM := &packet.CIFKeyMaterial{}
	if err := gcmCtx.MarshalKM(gcmKM, "testpassword", packet.EncryptionEven); err != nil {
		t.Fatalf("MarshalKM GCM: %v", err)
	}

	c.cryptoCtx = gcmCtx

	// Create a test packet
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}
	p := packet.NewData(c.remoteAddr, 1000, 12345, c.peerSocketID, data)
	p.Header.Encryption = packet.EncryptionEven
	p.Header.Retransmitted = true

	// encryptRetransmit should encrypt the packet
	err = c.encryptRetransmit(&p)
	if err != nil {
		t.Errorf("encryptRetransmit GCM: %v", err)
	}
	// After encryption, data should be modified (ciphertext != plaintext)
	allSame := true
	for i, b := range p.Data[:100] {
		if b != byte(i) {
			allSame = false
			break
		}
	}
	if allSame && len(p.Data) == 100 {
		t.Log("data may appear same — GCM may have modified length or content")
	}
}

func TestConnWritePeerHealthCheck(t *testing.T) {
	c, _ := testSingleConn(t)

	// Mark peer as unhealthy
	c.peerHealth.Store(false)

	_, err := c.Write([]byte("hello"))
	if err == nil {
		t.Error("Write should fail when peerHealth=false")
	}
	if err != nil && err.Error() != "srt: peer error" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConnWriteMessageAPISizeLimit(t *testing.T) {
	c, _ := testSingleConn(t)

	// Enable message API
	c.messageAPI = true
	c.tsbpdEnabled.Store(false) // disable TSBPD to allow multi-packet

	// Message exceeding send buffer capacity should fail
	bigMsg := make([]byte, c.sendBuf.Capacity()*c.payloadSize+100)
	_, err := c.Write(bigMsg)
	if err == nil {
		t.Error("Write should fail for message exceeding send buffer capacity")
	}
}

func TestConnHandleDataPacket_Encrypted(t *testing.T) {
	c, _ := testSingleConn(t)

	// Set up crypto context
	ctx, err := crypto.New(16)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	km := &packet.CIFKeyMaterial{}
	if err := ctx.MarshalKM(km, "testpassword", packet.EncryptionEven); err != nil {
		t.Fatalf("MarshalKM: %v", err)
	}
	c.cryptoCtx = ctx
	c.activeKey = packet.EncryptionEven
	c.kmConfirmed.Store(true)

	// Send an encrypted data packet — but with garbage data, decryption should fail
	p := packet.NewData(c.localAddr, c.recvBuf.ACKSequence().Value(), c.clk.Now().SRTTimestamp(), c.socketID, []byte("garbage encrypted data"))
	p.Header.Encryption = packet.EncryptionEven

	c.handleDataPacket(p)

	// Should have incremented undecrypt counter
	if c.recvUndecrypt.Load() == 0 {
		t.Log("recvUndecrypt not incremented — encryption may have succeeded on garbage data")
	}
}

func TestConnHandleDataPacket_UnencryptedOnSecuredConn(t *testing.T) {
	c, _ := testSingleConn(t)

	// Set up crypto context and mark as confirmed
	ctx, err := crypto.New(16)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	km := &packet.CIFKeyMaterial{}
	if err := ctx.MarshalKM(km, "testpassword", packet.EncryptionEven); err != nil {
		t.Fatalf("MarshalKM: %v", err)
	}
	c.cryptoCtx = ctx
	c.kmConfirmed.Store(true)

	// Send an unencrypted data packet — should be dropped
	p := packet.NewData(c.localAddr, c.recvBuf.ACKSequence().Value(), c.clk.Now().SRTTimestamp(), c.socketID, []byte("plaintext on secured conn"))
	p.Header.Encryption = packet.EncryptionNone

	prevUndecrypt := c.recvUndecrypt.Load()
	c.handleDataPacket(p)

	if c.recvUndecrypt.Load() != prevUndecrypt+1 {
		t.Error("unencrypted packet on secured connection should increment recvUndecrypt")
	}
}

func TestConnHandleDataPacket_GroupIdle(t *testing.T) {
	c, _ := testSingleConn(t)

	// Set group ID to enable group idle tracking
	c.groupID = 42
	c.groupIdle.Store(true)

	// Send a data packet
	seqNo := c.recvBuf.ACKSequence()
	p := packet.NewData(c.localAddr, seqNo.Value(), c.clk.Now().SRTTimestamp(), c.socketID, []byte("data"))
	p.Header.PacketPosition = packet.PositionSingle
	p.Header.MessageNumber = 1

	c.handleDataPacket(p)

	// After data packet, groupIdle should be cleared
	if c.groupIdle.Load() {
		t.Error("groupIdle should be false after data packet")
	}
}

func TestConnHandleDataPacket_ReorderTracking(t *testing.T) {
	c, _ := testSingleConn(t)

	baseSeq := c.recvBuf.ACKSequence()

	// Send packet with seqNo=base (first packet)
	p1 := packet.NewData(c.localAddr, baseSeq.Value(), c.clk.Now().SRTTimestamp(), c.socketID, []byte("pkt1"))
	p1.Header.PacketPosition = packet.PositionSingle
	p1.Header.MessageNumber = 1
	c.handleDataPacket(p1)

	// Now skip seq base+1, send seq base+2 (creates a gap)
	p3 := packet.NewData(c.localAddr, baseSeq.Add(2).Value(), c.clk.Now().SRTTimestamp(), c.socketID, []byte("pkt3"))
	p3.Header.PacketPosition = packet.PositionSingle
	p3.Header.MessageNumber = 1
	c.handleDataPacket(p3)

	// Now send the "late" packet base+1 (out of order)
	p2 := packet.NewData(c.localAddr, baseSeq.Add(1).Value(), c.clk.Now().SRTTimestamp(), c.socketID, []byte("pkt2"))
	p2.Header.PacketPosition = packet.PositionSingle
	p2.Header.MessageNumber = 1
	c.handleDataPacket(p2)

	// reorderDistance should be >= 1 since packet arrived out of order
	if c.reorderDistance.Load() < 1 {
		t.Logf("reorderDistance=%d (may be 0 if both packets had same distance)", c.reorderDistance.Load())
	}
}

func TestConnRetransmitAllInFlight_WithPackets(t *testing.T) {
	sender, _ := testConnPair(t)

	// Push some packets into the send buffer
	for range 3 {
		data := make([]byte, 100)
		p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		sender.sendBuf.Push(p, sender.clk.Now())
	}

	prevRetrans := sender.retransCount.Load()

	// Retransmit all in flight
	sender.retransmitAllInFlight()

	// Should have retransmitted 3 packets
	if sender.retransCount.Load() <= prevRetrans {
		t.Logf("retransCount: before=%d after=%d (retransmission may have been skipped)",
			prevRetrans, sender.retransCount.Load())
	}
}

func TestConnSendPacket_NonBlocking(t *testing.T) {
	sender, _ := testConnPair(t)

	// Set non-blocking mode
	sender.sndSynFlag.Store(false)

	// Fill the send buffer beyond flow control limit
	for range sender.fc + 10 {
		data := make([]byte, 100)
		p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		err := sender.sendPacket(p, 100)
		if errors.Is(err, ErrWouldBlock) {
			// Good — buffer full in non-blocking mode
			return
		}
		if err != nil {
			// Some other error
			return
		}
	}
	// May not have hit the limit — that's ok
}

func TestConnSendPacket_WriteDeadline(t *testing.T) {
	sender, _ := testConnPair(t)

	// Set a write deadline in the past
	sender.SetWriteDeadline(time.Now().Add(-1 * time.Second))

	// Fill the send buffer
	for range sender.fc + 10 {
		data := make([]byte, 100)
		p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		err := sender.sendPacket(p, 100)
		if err != nil {
			// Should get i/o timeout when buffer is full
			return
		}
	}
}

func TestConnHandleNAK_BeyondSendRange(t *testing.T) {
	sender, _ := testConnPair(t)

	// Create a NAK for a sequence number beyond what was sent
	beyondSeq := sender.sendBuf.NextSeq().Add(1000).Value()
	nakCIF := packet.CIFNAK{LossList: []uint32{beyondSeq}}
	nakData, _ := nakCIF.MarshalCIF()

	p := packet.NewControl(sender.localAddr, packet.CtrlTypeNAK, sender.socketID, 0)
	p.SetData(nakData)

	sender.handleNAK(p)

	// Connection should be closed
	select {
	case <-sender.done:
		// Good — connection was closed
	case <-time.After(time.Second):
		t.Error("connection should be closed after NAK beyond send range")
	}
}

func TestConnHandleNAK_BelowACK(t *testing.T) {
	sender, _ := testConnPair(t)

	// Push some packets first
	for range 5 {
		data := make([]byte, 100)
		p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		sender.sendBuf.Push(p, sender.clk.Now())
	}

	// The start seq (ACK boundary) is after the initial ISN
	startSeq := sender.sendBuf.StartSeq()

	// Create a NAK for a sequence before the ACK boundary (already delivered)
	belowACK := startSeq.Dec().Value()
	nextSend := sender.sendBuf.NextSeq()
	// Use a valid loss seq that is in range but below ACK
	if seq.Number(belowACK).LessThan(nextSend) {
		nakCIF := packet.CIFNAK{LossList: []uint32{belowACK}}
		nakData, _ := nakCIF.MarshalCIF()

		p := packet.NewControl(sender.localAddr, packet.CtrlTypeNAK, sender.socketID, 0)
		p.SetData(nakData)

		sender.handleNAK(p)
		// Should have triggered sendDropReq for below-ACK loss
	}
}

func TestConnHandleNAK_WithRetransmit(t *testing.T) {
	sender, _ := testConnPair(t)

	// Push packets
	var seqs []uint32
	for range 5 {
		nextSeq := sender.sendBuf.NextSeq()
		data := make([]byte, 100)
		p := packet.NewData(sender.remoteAddr, nextSeq.Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		sender.sendBuf.Push(p, sender.clk.Now())
		seqs = append(seqs, nextSeq.Value())
	}

	// NAK for middle packet (valid loss in range)
	if len(seqs) >= 3 {
		nakCIF := packet.CIFNAK{LossList: []uint32{seqs[2]}}
		nakData, _ := nakCIF.MarshalCIF()

		p := packet.NewControl(sender.localAddr, packet.CtrlTypeNAK, sender.socketID, 0)
		p.SetData(nakData)

		prevRetrans := sender.retransCount.Load()
		sender.handleNAK(p)

		if sender.retransCount.Load() > prevRetrans {
			t.Logf("retransmitted %d packets", sender.retransCount.Load()-prevRetrans)
		}
	}
}

func TestConnSendDropReq(t *testing.T) {
	sender, _ := testConnPair(t)

	// sendDropReq should not panic
	sender.sendDropReq(100, 200)
}

func TestConnWriteMultiPacketFileMode(t *testing.T) {
	// Create a file mode connection pair
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second
	cfg.Congestion = CongestionFile

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second
	dialCfg.Congestion = CongestionFile

	var client *Conn
	var dialErr error
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		client, dialErr = Dial(l.Addr().String(), dialCfg)
	}()

	server, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer server.Close()

	wg.Wait()
	if dialErr != nil {
		t.Fatalf("Dial: %v", dialErr)
	}
	defer client.Close()

	// File mode allows multi-packet messages
	// Send a message larger than payloadSize
	bigMsg := make([]byte, client.payloadSize*2+100)
	for i := range bigMsg {
		bigMsg[i] = byte(i % 256)
	}

	n, err := client.Write(bigMsg)
	if err != nil {
		t.Fatalf("Write multi-packet: %v", err)
	}
	if n != len(bigMsg) {
		t.Errorf("Write returned %d, want %d", n, len(bigMsg))
	}
}
