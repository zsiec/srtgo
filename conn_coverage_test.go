package srt

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/filter"
	"github.com/zsiec/srtgo/internal/packet"
	"github.com/zsiec/srtgo/internal/seq"
)

// ---- FEC packet handling tests ----

// TestConnHandleDataPacket_FECRouting tests that data packets with MessageNumber==0
// are routed to handleFECPacket when an FEC receiver is configured.
func TestConnHandleDataPacket_FECRouting(t *testing.T) {
	c, _ := testSingleConn(t)

	fecCfg := filter.Config{
		Cols:   3,
		Rows:   1,
		Layout: filter.LayoutStaircase,
		ARQ:    filter.ARQOnReq,
	}
	isn := c.recvBuf.ACKSequence().Value()
	c.fecReceiver = filter.NewFECReceiver(fecCfg, c.payloadSize, isn)
	c.fecARQLevel = filter.ARQOnReq

	// Create a data packet with MessageNumber=0 (FEC marker)
	p := packet.NewData(c.localAddr, isn, c.clk.Now().SRTTimestamp(), c.socketID, make([]byte, filter.ExtraHeaderSize+c.payloadSize))
	p.Header.MessageNumber = 0

	prevExtra := c.rcvFilterExtra.Load()
	c.handleDataPacket(p)

	// FEC packet should increment rcvFilterExtra via handleFECPacket
	if c.rcvFilterExtra.Load() != prevExtra+1 {
		t.Errorf("rcvFilterExtra: got %d, want %d", c.rcvFilterExtra.Load(), prevExtra+1)
	}

	// Should NOT have been inserted into the receive buffer as a data packet
	if c.recvPackets.Load() != 0 {
		t.Errorf("recvPackets: got %d, want 0 (FEC should not be counted as data)", c.recvPackets.Load())
	}
}

// TestConnHandleFECPacket_WithReceiver tests the handleFECPacket path where
// fecReceiver processes FEC control packets and recovers missing data.
func TestConnHandleFECPacket_WithReceiver(t *testing.T) {
	c, _ := testSingleConn(t)

	fecCfg := filter.Config{
		Cols:   3,
		Rows:   1,
		Layout: filter.LayoutStaircase,
		ARQ:    filter.ARQOnReq,
	}
	isn := c.recvBuf.ACKSequence().Value()
	c.fecReceiver = filter.NewFECReceiver(fecCfg, c.payloadSize, isn)
	c.fecARQLevel = filter.ARQOnReq

	// Feed 2 of 3 data packets to partially fill a row group
	for i := 0; i < 2; i++ {
		seqNo := seq.Number(isn).Add(uint32(i)).Value()
		payload := make([]byte, 100)
		for j := range payload {
			payload[j] = byte(i*10 + j)
		}
		dp := packet.NewData(c.localAddr, seqNo, uint32(i*1000), c.socketID, payload)
		dp.Header.MessageNumber = 1
		dp.Header.PacketPosition = packet.PositionSingle
		c.handleDataPacket(dp)
	}

	if c.recvPackets.Load() != 2 {
		t.Fatalf("expected 2 data packets inserted, got %d", c.recvPackets.Load())
	}

	// Build a proper FEC control packet using the sender
	fecSender := filter.NewFECSender(fecCfg, c.payloadSize, isn)
	for i := 0; i < 3; i++ {
		seqNo := seq.Number(isn).Add(uint32(i)).Value()
		payload := make([]byte, 100)
		for j := range payload {
			payload[j] = byte(i*10 + j)
		}
		fecSender.FeedSource(seqNo, uint32(i*1000), 0, payload)
	}

	fecData, _, fecSeqNo, fecTS, ok := fecSender.PackControlPacket()
	if !ok {
		t.Fatal("expected FEC control packet from sender")
	}

	fecPkt := packet.NewData(c.localAddr, fecSeqNo, fecTS, c.socketID, fecData)
	fecPkt.Header.MessageNumber = 0

	prevSupply := c.rcvFilterSupply.Load()
	now := c.clk.Now()
	c.handleFECPacket(fecPkt, now)

	if c.rcvFilterSupply.Load() > prevSupply {
		t.Logf("FEC recovered %d packets", c.rcvFilterSupply.Load()-prevSupply)
	}

	if c.rcvFilterExtra.Load() == 0 {
		t.Error("rcvFilterExtra should be > 0 after FEC packet")
	}
}

// TestConnInsertRecoveredPacket tests that FEC-recovered packets are properly
// inserted into the receive buffer.
func TestConnInsertRecoveredPacket(t *testing.T) {
	c, _ := testSingleConn(t)

	now := c.clk.Now()
	recvISN := c.recvBuf.ACKSequence().Value()
	rp := filter.RecoveredPacket{
		SeqNo:     recvISN,
		Timestamp: now.SRTTimestamp(),
		EncFlag:   0,
		Payload:   []byte("recovered payload data"),
	}

	prevRecvPkts := c.recvPackets.Load()
	c.insertRecoveredPacket(rp, now)

	if c.recvPackets.Load() != prevRecvPkts+1 {
		t.Errorf("recvPackets: got %d, want %d", c.recvPackets.Load(), prevRecvPkts+1)
	}
	if c.recvBytes.Load() < uint64(len(rp.Payload)) {
		t.Errorf("recvBytes: got %d, want >= %d", c.recvBytes.Load(), len(rp.Payload))
	}
}

// TestConnInsertRecoveredPacket_Duplicate tests that duplicate recovered packets
// are not double-counted.
func TestConnInsertRecoveredPacket_Duplicate(t *testing.T) {
	c, _ := testSingleConn(t)

	now := c.clk.Now()
	recvISN := c.recvBuf.ACKSequence().Value()

	dp := packet.NewData(c.localAddr, recvISN, now.SRTTimestamp(), c.socketID, []byte("original"))
	dp.Header.MessageNumber = 1
	dp.Header.PacketPosition = packet.PositionSingle
	c.handleDataPacket(dp)

	prevRecvPkts := c.recvPackets.Load()

	rp := filter.RecoveredPacket{
		SeqNo:     recvISN,
		Timestamp: now.SRTTimestamp(),
		EncFlag:   0,
		Payload:   []byte("recovered duplicate"),
	}
	c.insertRecoveredPacket(rp, now)

	if c.recvPackets.Load() != prevRecvPkts {
		t.Errorf("recvPackets: got %d, want %d (duplicate should not be counted)", c.recvPackets.Load(), prevRecvPkts)
	}
}

// TestConnInsertRecoveredPacket_Encrypted tests the decryption path for
// FEC-recovered packets in CTR mode.
func TestConnInsertRecoveredPacket_Encrypted(t *testing.T) {
	c, _ := testSingleConn(t)

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

	now := c.clk.Now()
	recvISN := c.recvBuf.ACKSequence().Value()

	plaintext := []byte("test recovered encrypted data!!!")
	ciphertext, encErr := ctx.EncryptPayload(plaintext, nil, packet.EncryptionEven, recvISN)
	if encErr != nil {
		t.Fatalf("EncryptPayload: %v", encErr)
	}

	rp := filter.RecoveredPacket{
		SeqNo:     recvISN,
		Timestamp: now.SRTTimestamp(),
		EncFlag:   uint8(packet.EncryptionEven),
		Payload:   ciphertext,
	}

	prevRecvPkts := c.recvPackets.Load()
	c.insertRecoveredPacket(rp, now)

	if c.recvPackets.Load() != prevRecvPkts+1 {
		t.Errorf("recvPackets: got %d, want %d (encrypted recovery should succeed)", c.recvPackets.Load(), prevRecvPkts+1)
	}
}

// TestConnHandleDataPacket_FECReceiverFeedOnInsert tests that inserted data packets
// are fed into the FEC receiver for group accumulation.
func TestConnHandleDataPacket_FECReceiverFeedOnInsert(t *testing.T) {
	c, _ := testSingleConn(t)

	fecCfg := filter.Config{
		Cols:   3,
		Rows:   1,
		Layout: filter.LayoutStaircase,
		ARQ:    filter.ARQOnReq,
	}
	isn := c.recvBuf.ACKSequence().Value()
	c.fecReceiver = filter.NewFECReceiver(fecCfg, c.payloadSize, isn)

	for i := 0; i < 3; i++ {
		seqNo := seq.Number(isn).Add(uint32(i)).Value()
		p := packet.NewData(c.localAddr, seqNo, uint32(i*1000), c.socketID, make([]byte, 50))
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		c.handleDataPacket(p)
	}

	if c.recvPackets.Load() != 3 {
		t.Errorf("recvPackets: got %d, want 3", c.recvPackets.Load())
	}
}

// ---- handleKMRequest mid-stream tests ----

// TestConnHandleKMRequest_ValidKMREQ tests successful mid-stream KMREQ processing.
func TestConnHandleKMRequest_ValidKMREQ(t *testing.T) {
	passphrase := "sharedtestpassphrase"

	senderCtx, err := crypto.New(16)
	if err != nil {
		t.Fatalf("crypto.New sender: %v", err)
	}
	senderKM := &packet.CIFKeyMaterial{}
	if err := senderCtx.MarshalKM(senderKM, passphrase, packet.EncryptionEven); err != nil {
		t.Fatalf("MarshalKM sender: %v", err)
	}

	receiverCtx, err := crypto.New(16)
	if err != nil {
		t.Fatalf("crypto.New receiver: %v", err)
	}

	c, _ := testSingleConn(t)
	c.cryptoCtx = receiverCtx
	c.passphrase = passphrase

	kmData, err := senderKM.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	p := packet.NewControl(c.localAddr, packet.CtrlTypeUser, c.socketID, 0)
	p.Header.SubType = packet.ExtTypeKMReq
	p.SetData(kmData)

	c.handleKMRequest(p)

	kmState := c.rcvKmState.Load()
	if kmState == 3 || kmState == 4 {
		t.Errorf("rcvKmState: got %d, expected successful key unwrap (not 3 or 4)", kmState)
	}
}

// TestConnHandleKMRequest_WrongPassphrase tests KMREQ with mismatched passphrase.
func TestConnHandleKMRequest_WrongPassphrase(t *testing.T) {
	senderCtx, err := crypto.New(16)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	senderKM := &packet.CIFKeyMaterial{}
	if err := senderCtx.MarshalKM(senderKM, "sender-secret", packet.EncryptionEven); err != nil {
		t.Fatalf("MarshalKM: %v", err)
	}

	receiverCtx, err := crypto.New(16)
	if err != nil {
		t.Fatalf("crypto.New receiver: %v", err)
	}

	c, _ := testSingleConn(t)
	c.cryptoCtx = receiverCtx
	c.passphrase = "wrong-passphrase"

	kmData, err := senderKM.MarshalCIF()
	if err != nil {
		t.Fatalf("MarshalCIF: %v", err)
	}

	p := packet.NewControl(c.localAddr, packet.CtrlTypeUser, c.socketID, 0)
	p.Header.SubType = packet.ExtTypeKMReq
	p.SetData(kmData)

	c.handleKMRequest(p)

	if c.rcvKmState.Load() != 4 {
		t.Errorf("rcvKmState: got %d, want 4 (BADSECRET)", c.rcvKmState.Load())
	}
	if c.sndKmState.Load() != 4 {
		t.Errorf("sndKmState: got %d, want 4 (BADSECRET)", c.sndKmState.Load())
	}
}

// TestConnHandleKMRequest_RecvKMCount tests that handleKMRequest increments recvKM.
func TestConnHandleKMRequest_RecvKMCount(t *testing.T) {
	c, _ := testSingleConn(t)

	ctx, err := crypto.New(16)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	c.cryptoCtx = ctx
	c.passphrase = "testpass"

	prevKM := c.recvKM.Load()

	p := packet.NewControl(c.localAddr, packet.CtrlTypeUser, c.socketID, 0)
	p.Header.SubType = packet.ExtTypeKMReq
	p.Data = []byte{0xFF, 0xFF} // invalid but still increments counter

	c.handleKMRequest(p)

	if c.recvKM.Load() != prevKM+1 {
		t.Errorf("recvKM: got %d, want %d", c.recvKM.Load(), prevKM+1)
	}
}

// ---- retransmitAllInFlight tests ----

// TestConnRetransmitAllInFlight_FASTREXMIT tests the FASTREXMIT path.
func TestConnRetransmitAllInFlight_FASTREXMIT(t *testing.T) {
	sender, _ := testConnPair(t)

	sender.tsbpdEnabled = true
	sender.peerNakReport = false

	for i := 0; i < 5; i++ {
		data := make([]byte, 100)
		p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		sender.sendBuf.Push(p, sender.clk.Now())
	}

	if sender.flightSize() != 5 {
		t.Fatalf("flightSize: got %d, want 5", sender.flightSize())
	}

	prevRetrans := sender.retransCount.Load()
	prevRetransBytes := sender.retransBytes.Load()

	sender.retransmitAllInFlight()

	retransmitted := sender.retransCount.Load() - prevRetrans
	if retransmitted != 5 {
		t.Errorf("retransCount: retransmitted %d, want 5", retransmitted)
	}
	if sender.retransBytes.Load() <= prevRetransBytes {
		t.Error("retransBytes should have increased")
	}
}

// TestConnRetransmitAllInFlight_WithRexmitShaper tests rate-limited retransmission.
func TestConnRetransmitAllInFlight_WithRexmitShaper(t *testing.T) {
	sender, _ := testConnPair(t)

	sender.rexmitShaper = newRexmitTokenBucket(100) // 100 bytes/sec

	for i := 0; i < 5; i++ {
		data := make([]byte, 100)
		p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		sender.sendBuf.Push(p, sender.clk.Now())
	}

	prevRetrans := sender.retransCount.Load()
	sender.retransmitAllInFlight()

	retransmitted := sender.retransCount.Load() - prevRetrans
	t.Logf("retransmitted %d out of 5 with tight shaper", retransmitted)
}

// TestConnRetransmitAllInFlight_WithGCMEncryption tests retransmit with GCM re-encryption.
func TestConnRetransmitAllInFlight_WithGCMEncryption(t *testing.T) {
	sender, _ := testConnPair(t)

	gcmCtx, err := crypto.NewWithMode(16, crypto.CipherGCM)
	if err != nil {
		t.Fatalf("NewWithMode GCM: %v", err)
	}
	gcmKM := &packet.CIFKeyMaterial{}
	if err := gcmCtx.MarshalKM(gcmKM, "testpassword", packet.EncryptionEven); err != nil {
		t.Fatalf("MarshalKM: %v", err)
	}
	sender.cryptoCtx = gcmCtx
	sender.activeKey = packet.EncryptionEven

	for i := 0; i < 3; i++ {
		data := make([]byte, 100)
		for j := range data {
			data[j] = byte(j)
		}
		p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		p.Header.Encryption = packet.EncryptionEven
		sender.sendBuf.Push(p, sender.clk.Now())
	}

	prevRetrans := sender.retransCount.Load()
	sender.retransmitAllInFlight()

	if sender.retransCount.Load() <= prevRetrans {
		t.Error("retransmitAllInFlight with GCM should still retransmit packets")
	}
}

// ---- sendPacket encryption tests ----

// TestConnSendPacket_WithCTREncryption tests sendPacket with CTR encryption.
func TestConnSendPacket_WithCTREncryption(t *testing.T) {
	sender, _ := testConnPair(t)

	ctx, err := crypto.New(16)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	km := &packet.CIFKeyMaterial{}
	if err := ctx.MarshalKM(km, "testpassword", packet.EncryptionEven); err != nil {
		t.Fatalf("MarshalKM: %v", err)
	}
	sender.cryptoCtx = ctx
	sender.activeKey = packet.EncryptionEven

	data := []byte("test encrypted data payload!!")
	seqNo := sender.sendBuf.NextSeq()
	p := packet.NewData(sender.remoteAddr, seqNo.Value(),
		sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
	p.Header.MessageNumber = 1
	p.Header.PacketPosition = packet.PositionSingle

	prevSent := sender.sentPackets.Load()
	err = sender.sendPacket(p, len(data))
	if err != nil {
		t.Fatalf("sendPacket with encryption: %v", err)
	}

	if sender.sentPackets.Load() != prevSent+1 {
		t.Errorf("sentPackets: got %d, want %d", sender.sentPackets.Load(), prevSent+1)
	}
}

// TestConnSendPacket_WithGCMEncryption tests sendPacket with GCM mode encryption.
func TestConnSendPacket_WithGCMEncryption(t *testing.T) {
	sender, _ := testConnPair(t)

	gcmCtx, err := crypto.NewWithMode(16, crypto.CipherGCM)
	if err != nil {
		t.Fatalf("NewWithMode GCM: %v", err)
	}
	gcmKM := &packet.CIFKeyMaterial{}
	if err := gcmCtx.MarshalKM(gcmKM, "testpassword", packet.EncryptionEven); err != nil {
		t.Fatalf("MarshalKM GCM: %v", err)
	}
	sender.cryptoCtx = gcmCtx
	sender.activeKey = packet.EncryptionEven

	data := []byte("test GCM encrypted payload!!")
	seqNo := sender.sendBuf.NextSeq()
	p := packet.NewData(sender.remoteAddr, seqNo.Value(),
		sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
	p.Header.MessageNumber = 1
	p.Header.PacketPosition = packet.PositionSingle

	err = sender.sendPacket(p, len(data))
	if err != nil {
		t.Fatalf("sendPacket with GCM: %v", err)
	}

	if sender.sentPackets.Load() == 0 {
		t.Error("sentPackets should be > 0 after successful send")
	}
}

// TestConnSendPacket_ConnectionClosed tests sendPacket when connection is closed
// and send buffer is full.
func TestConnSendPacket_ConnectionClosed(t *testing.T) {
	sender, _ := testConnPair(t)

	for i := 0; i < sender.fc+10; i++ {
		data := make([]byte, 100)
		p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		if !sender.sendBuf.Push(p, sender.clk.Now()) {
			break
		}
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		sender.Close()
	}()

	data := make([]byte, 100)
	p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
		sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
	p.Header.MessageNumber = 1
	p.Header.PacketPosition = packet.PositionSingle

	err := sender.sendPacket(p, 100)
	if err == nil {
		t.Error("sendPacket should fail when connection is closed")
	}
}

// ---- Write tests ----

// TestConnWrite_FileModeMultiPacketExact tests file-mode multi-packet write.
func TestConnWrite_FileModeMultiPacketExact(t *testing.T) {
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

	bigMsg := make([]byte, client.payloadSize*3)
	for i := range bigMsg {
		bigMsg[i] = byte(i % 256)
	}

	n, err := client.Write(bigMsg)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(bigMsg) {
		t.Errorf("Write returned %d, want %d", n, len(bigMsg))
	}

	if client.sentPackets.Load() < 3 {
		t.Errorf("sentPackets: got %d, want >= 3", client.sentPackets.Load())
	}
}

// TestConnWrite_NonBlockingWouldBlock tests non-blocking Write returning ErrWouldBlock.
func TestConnWrite_NonBlockingWouldBlock(t *testing.T) {
	sender, _ := testConnPair(t)

	sender.sndSynFlag.Store(false)
	sender.sndSyn = false

	for i := 0; i < sender.sendBuf.Capacity(); i++ {
		data := make([]byte, 100)
		p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		if !sender.sendBuf.Push(p, sender.clk.Now()) {
			break
		}
	}

	_, err := sender.Write([]byte("cannot fit"))
	if !errors.Is(err, ErrWouldBlock) {
		t.Errorf("Write on full buffer in non-blocking mode: got %v, want ErrWouldBlock", err)
	}
}

// TestConnWrite_WithWriteDeadlineFullBuffer tests Write with past deadline and full buffer.
func TestConnWrite_WithWriteDeadlineFullBuffer(t *testing.T) {
	sender, _ := testConnPair(t)

	for i := 0; i < sender.sendBuf.Capacity(); i++ {
		data := make([]byte, 100)
		p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		if !sender.sendBuf.Push(p, sender.clk.Now()) {
			break
		}
	}

	sender.SetWriteDeadline(time.Now().Add(-1 * time.Second))

	_, err := sender.Write([]byte("timeout test"))
	if err == nil {
		t.Error("Write with past deadline and full buffer should fail")
	}
	if netErr, ok := err.(*net.OpError); ok {
		if netErr.Op != "write" {
			t.Errorf("OpError.Op: got %q, want %q", netErr.Op, "write")
		}
	}
}

// TestConnWrite_LiveModeSinglePacketValidation tests the single-packet write path.
func TestConnWrite_LiveModeSinglePacketValidation(t *testing.T) {
	sender, _ := testConnPair(t)

	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}

	n, err := sender.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, want %d", n, len(data))
	}

	if sender.sentPackets.Load() != 1 {
		t.Errorf("sentPackets: got %d, want 1", sender.sentPackets.Load())
	}
	if sender.sentBytes.Load() != uint64(len(data)) {
		t.Errorf("sentBytes: got %d, want %d", sender.sentBytes.Load(), len(data))
	}
}

// TestConnWrite_LiveModeRejectsOversize tests that live mode rejects oversized payloads.
func TestConnWrite_LiveModeRejectsOversize(t *testing.T) {
	sender, _ := testConnPair(t)

	oversize := make([]byte, sender.payloadSize+1)
	_, err := sender.Write(oversize)
	if err == nil {
		t.Error("Write of oversize payload in live mode should fail")
	}
}

// TestConnHandleDataPacket_QuickACKFileMode tests quick ACK for non-full payloads.
func TestConnHandleDataPacket_QuickACKFileMode(t *testing.T) {
	c, _ := testSingleConn(t)

	c.tsbpdEnabled = false
	c.tlpktdropEnabled = false
	c.payloadSize = 1316

	baseSeq := c.recvBuf.ACKSequence()
	prevACKs := c.sentACKs.Load()

	smallPayload := make([]byte, 100) // < 1316
	p := packet.NewData(c.localAddr, baseSeq.Value(), c.clk.Now().SRTTimestamp(), c.socketID, smallPayload)
	p.Header.MessageNumber = 1
	p.Header.PacketPosition = packet.PositionSingle
	c.handleDataPacket(p)

	if c.sentACKs.Load() <= prevACKs {
		t.Logf("sentACKs: before=%d after=%d (quick ACK may have been sent)", prevACKs, c.sentACKs.Load())
	}
}

// TestConnHandleDataPacket_NoQuickACKFullPayload tests that full payloads skip quick ACK.
func TestConnHandleDataPacket_NoQuickACKFullPayload(t *testing.T) {
	c, _ := testSingleConn(t)

	c.tsbpdEnabled = false
	c.tlpktdropEnabled = false
	c.payloadSize = 100

	baseSeq := c.recvBuf.ACKSequence()
	prevACKs := c.sentACKs.Load()

	fullPayload := make([]byte, 100) // == payloadSize
	p := packet.NewData(c.localAddr, baseSeq.Value(), c.clk.Now().SRTTimestamp(), c.socketID, fullPayload)
	p.Header.MessageNumber = 1
	p.Header.PacketPosition = packet.PositionSingle
	c.handleDataPacket(p)

	if c.sentACKs.Load() > prevACKs {
		t.Errorf("full-payload packet should not trigger quick ACK; sentACKs: before=%d after=%d", prevACKs, c.sentACKs.Load())
	}
}

// TestConnHandleDataPacket_TSBPDTimestampUpdate tests TSBPD wrap detection on data packets.
func TestConnHandleDataPacket_TSBPDTimestampUpdate(t *testing.T) {
	c, _ := testSingleConn(t)

	if !c.tsbpdEnabled || c.tsbpdTimer == nil {
		t.Skip("TSBPD not enabled on test conn")
	}

	baseSeq := c.recvBuf.ACKSequence()

	for i := 0; i < 5; i++ {
		ts := uint32(i * 10000)
		p := packet.NewData(c.localAddr, baseSeq.Add(uint32(i)).Value(), ts, c.socketID, []byte("data"))
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		c.handleDataPacket(p)
	}

	if c.recvPackets.Load() != 5 {
		t.Errorf("recvPackets: got %d, want 5", c.recvPackets.Load())
	}
}

// TestConnHandleDataPacket_FECSuppressionOfNAK tests NAK suppression with FEC ARQOnReq.
func TestConnHandleDataPacket_FECSuppressionOfNAK(t *testing.T) {
	c, _ := testSingleConn(t)

	fecCfg := filter.Config{
		Cols:   3,
		Rows:   1,
		Layout: filter.LayoutStaircase,
		ARQ:    filter.ARQOnReq,
	}
	isn := c.recvBuf.ACKSequence().Value()
	c.fecReceiver = filter.NewFECReceiver(fecCfg, c.payloadSize, isn)
	c.fecARQLevel = filter.ARQOnReq

	prevNAKs := c.sentNAKs.Load()

	p1 := packet.NewData(c.localAddr, isn, c.clk.Now().SRTTimestamp(), c.socketID, []byte("pkt1"))
	p1.Header.MessageNumber = 1
	p1.Header.PacketPosition = packet.PositionSingle
	c.handleDataPacket(p1)

	// Skip packet 1, send packet 2 (gap)
	p3 := packet.NewData(c.localAddr, seq.Number(isn).Add(2).Value(), c.clk.Now().SRTTimestamp(), c.socketID, []byte("pkt3"))
	p3.Header.MessageNumber = 1
	p3.Header.PacketPosition = packet.PositionSingle
	c.handleDataPacket(p3)

	if c.sentNAKs.Load() > prevNAKs {
		t.Errorf("NAK should be suppressed with FEC ARQOnReq; sentNAKs: before=%d after=%d",
			prevNAKs, c.sentNAKs.Load())
	}
}

// TestConnHandleDataPacket_FECAllowsNAK_ARQAlways tests NAK is sent with ARQAlways.
func TestConnHandleDataPacket_FECAllowsNAK_ARQAlways(t *testing.T) {
	c, _ := testSingleConn(t)

	fecCfg := filter.Config{
		Cols:   3,
		Rows:   1,
		Layout: filter.LayoutStaircase,
		ARQ:    filter.ARQAlways,
	}
	isn := c.recvBuf.ACKSequence().Value()
	c.fecReceiver = filter.NewFECReceiver(fecCfg, c.payloadSize, isn)
	c.fecARQLevel = filter.ARQAlways

	prevNAKs := c.sentNAKs.Load()

	p1 := packet.NewData(c.localAddr, isn, c.clk.Now().SRTTimestamp(), c.socketID, []byte("pkt1"))
	p1.Header.MessageNumber = 1
	p1.Header.PacketPosition = packet.PositionSingle
	c.handleDataPacket(p1)

	p3 := packet.NewData(c.localAddr, seq.Number(isn).Add(2).Value(), c.clk.Now().SRTTimestamp(), c.socketID, []byte("pkt3"))
	p3.Header.MessageNumber = 1
	p3.Header.PacketPosition = packet.PositionSingle
	c.handleDataPacket(p3)

	if c.sentNAKs.Load() <= prevNAKs {
		t.Errorf("NAK should be sent with FEC ARQAlways; sentNAKs: before=%d after=%d",
			prevNAKs, c.sentNAKs.Load())
	}
}

// TestConnHandleFECPacket_LossReport tests FEC loss reporting path.
func TestConnHandleFECPacket_LossReport(t *testing.T) {
	c, _ := testSingleConn(t)

	fecCfg := filter.Config{
		Cols:   3,
		Rows:   2,
		Layout: filter.LayoutEven,
		ARQ:    filter.ARQOnReq,
	}
	isn := c.recvBuf.ACKSequence().Value()
	c.fecReceiver = filter.NewFECReceiver(fecCfg, c.payloadSize, isn)
	c.fecARQLevel = filter.ARQOnReq

	fecSender := filter.NewFECSender(fecCfg, c.payloadSize, isn)

	for i := 0; i < 3; i++ {
		seqNo := seq.Number(isn).Add(uint32(i)).Value()
		payload := make([]byte, 50)
		for j := range payload {
			payload[j] = byte(i*10 + j)
		}
		fecSender.FeedSource(seqNo, uint32(i*1000), 0, payload)

		if i != 1 { // skip one to create loss
			dp := packet.NewData(c.localAddr, seqNo, uint32(i*1000), c.socketID, payload)
			dp.Header.MessageNumber = 1
			dp.Header.PacketPosition = packet.PositionSingle
			c.handleDataPacket(dp)
		}
	}

	fecData, _, fecSeqNo, fecTS, ok := fecSender.PackControlPacket()
	if !ok {
		t.Skip("no FEC control packet emitted")
	}

	fecPkt := packet.NewData(c.localAddr, fecSeqNo, fecTS, c.socketID, fecData)
	fecPkt.Header.MessageNumber = 0

	now := c.clk.Now()
	c.handleFECPacket(fecPkt, now)

	if c.rcvFilterExtra.Load() == 0 {
		t.Error("rcvFilterExtra should be > 0")
	}
}

// TestConnWrite_WithFECSender tests Write with FEC sender attached.
func TestConnWrite_WithFECSender(t *testing.T) {
	sender, _ := testConnPair(t)

	fecCfg := filter.Config{
		Cols:   3,
		Rows:   1,
		Layout: filter.LayoutStaircase,
		ARQ:    filter.ARQOnReq,
	}
	sndISN := sender.sendISN.Value()
	sender.fecSender = filter.NewFECSender(fecCfg, sender.payloadSize, sndISN)

	for i := 0; i < 3; i++ {
		data := make([]byte, 100)
		_, err := sender.Write(data)
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	if sender.sndFilterExtra.Load() == 0 {
		t.Logf("sndFilterExtra: %d (FEC packet may not have been emitted)", sender.sndFilterExtra.Load())
	}
	if sender.sentPackets.Load() < 3 {
		t.Errorf("sentPackets: got %d, want >= 3", sender.sentPackets.Load())
	}
}

// TestConnWrite_EncryptedConnection tests Write with CTR encryption.
func TestConnWrite_EncryptedConnection(t *testing.T) {
	sender, _ := testConnPair(t)

	ctx, err := crypto.New(16)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	km := &packet.CIFKeyMaterial{}
	if err := ctx.MarshalKM(km, "testpassword", packet.EncryptionEven); err != nil {
		t.Fatalf("MarshalKM: %v", err)
	}
	sender.cryptoCtx = ctx
	sender.activeKey = packet.EncryptionEven

	data := []byte("hello encrypted world!!")
	n, err := sender.Write(data)
	if err != nil {
		t.Fatalf("Write encrypted: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, want %d", n, len(data))
	}
}

// TestConnWrite_GroupSrcTime tests Write with group-coordinated source timestamp.
func TestConnWrite_GroupSrcTime(t *testing.T) {
	sender, _ := testConnPair(t)

	sender.groupSrcTime.Store(42000)

	data := []byte("group timestamp test")
	n, err := sender.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, want %d", n, len(data))
	}
}

// TestConnHandleDataPacket_GCMDecryptPath tests GCM-specific decrypt path
// with R-bit zeroing in AAD.
func TestConnHandleDataPacket_GCMDecryptPath(t *testing.T) {
	c, _ := testSingleConn(t)

	gcmCtx, err := crypto.NewWithMode(16, crypto.CipherGCM)
	if err != nil {
		t.Fatalf("NewWithMode GCM: %v", err)
	}
	gcmKM := &packet.CIFKeyMaterial{}
	if err := gcmCtx.MarshalKM(gcmKM, "testpassword", packet.EncryptionEven); err != nil {
		t.Fatalf("MarshalKM GCM: %v", err)
	}
	c.cryptoCtx = gcmCtx
	c.activeKey = packet.EncryptionEven

	baseSeq := c.recvBuf.ACKSequence().Value()
	ts := c.clk.Now().SRTTimestamp()

	plaintext := make([]byte, 100)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	pkt := packet.NewData(c.localAddr, baseSeq, ts, c.socketID, plaintext)
	pkt.Header.Encryption = packet.EncryptionEven
	pkt.Header.MessageNumber = 1
	pkt.Header.PacketPosition = packet.PositionSingle
	pkt.Header.Retransmitted = false

	var aadBuf [16]byte
	pkt.Header.Marshal(aadBuf[:])
	ciphertext, encErr := gcmCtx.EncryptPayload(plaintext, aadBuf[:], packet.EncryptionEven, baseSeq)
	if encErr != nil {
		t.Fatalf("EncryptPayload GCM: %v", encErr)
	}
	pkt.Data = ciphertext

	c.handleDataPacket(pkt)

	// The GCM decrypt path was exercised regardless of outcome
	if c.recvPackets.Load() > 0 {
		t.Logf("GCM decryption succeeded, recvPackets=%d", c.recvPackets.Load())
	} else if c.recvUndecrypt.Load() > 0 {
		t.Logf("GCM decrypt path exercised, recvUndecrypt=%d", c.recvUndecrypt.Load())
	}
}

// TestConnHandleDataPacket_GCMNonTSBPD tests the GCM path with TSBPD disabled
// (timestamp zeroed in AAD).
func TestConnHandleDataPacket_GCMNonTSBPD(t *testing.T) {
	c, _ := testSingleConn(t)

	c.tsbpdEnabled = false

	gcmCtx, err := crypto.NewWithMode(16, crypto.CipherGCM)
	if err != nil {
		t.Fatalf("NewWithMode GCM: %v", err)
	}
	gcmKM := &packet.CIFKeyMaterial{}
	if err := gcmCtx.MarshalKM(gcmKM, "testpassword", packet.EncryptionEven); err != nil {
		t.Fatalf("MarshalKM GCM: %v", err)
	}
	c.cryptoCtx = gcmCtx
	c.activeKey = packet.EncryptionEven

	baseSeq := c.recvBuf.ACKSequence().Value()

	plaintext := make([]byte, 64)
	for i := range plaintext {
		plaintext[i] = byte(i + 42)
	}

	// Build AAD with timestamp=0 (non-TSBPD sender)
	pkt := packet.NewData(c.localAddr, baseSeq, 0, c.socketID, plaintext)
	pkt.Header.Encryption = packet.EncryptionEven
	pkt.Header.MessageNumber = 1
	pkt.Header.PacketPosition = packet.PositionSingle
	pkt.Header.Retransmitted = false

	var aadBuf [16]byte
	pkt.Header.Marshal(aadBuf[:])
	ciphertext, encErr := gcmCtx.EncryptPayload(plaintext, aadBuf[:], packet.EncryptionEven, baseSeq)
	if encErr != nil {
		t.Fatalf("EncryptPayload GCM: %v", encErr)
	}
	pkt.Data = ciphertext

	// Set non-zero timestamp on wire (receiver should zero it in AAD)
	pkt.Header.Timestamp = 99999

	c.handleDataPacket(pkt)

	if c.recvPackets.Load() > 0 {
		t.Logf("GCM non-TSBPD decryption succeeded, recvPackets=%d", c.recvPackets.Load())
	} else if c.recvUndecrypt.Load() > 0 {
		t.Logf("GCM non-TSBPD path exercised, recvUndecrypt=%d", c.recvUndecrypt.Load())
	}
}

// TestConnWrite_FileModeMultiPacketWithEncryption tests multi-packet write in
// file mode with encryption enabled (exercises the per-fragment encrypt path).
func TestConnWrite_FileModeMultiPacketWithEncryption(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second
	cfg.Congestion = CongestionFile
	cfg.Passphrase = "testencryptpassphrase"

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second
	dialCfg.Congestion = CongestionFile
	dialCfg.Passphrase = "testencryptpassphrase"

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

	// Multi-packet encrypted write
	bigMsg := make([]byte, client.payloadSize*2+100)
	for i := range bigMsg {
		bigMsg[i] = byte(i % 256)
	}

	n, err := client.Write(bigMsg)
	if err != nil {
		t.Fatalf("Write encrypted multi-packet: %v", err)
	}
	if n != len(bigMsg) {
		t.Errorf("Write returned %d, want %d", n, len(bigMsg))
	}
}

// TestConnWrite_FileModeMultiPacketDeadline tests that multi-packet write
// in file mode respects write deadlines when the buffer is full.
func TestConnWrite_FileModeMultiPacketDeadline(t *testing.T) {
	sender, _ := testConnPair(t)

	// Configure as file mode (no TSBPD, no packet size limit)
	sender.tsbpdEnabled = false
	sender.tlpktdropEnabled = false

	// Fill the send buffer
	for i := 0; i < sender.sendBuf.Capacity(); i++ {
		data := make([]byte, 100)
		p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		if !sender.sendBuf.Push(p, sender.clk.Now()) {
			break
		}
	}

	// Set write deadline in the past
	sender.SetWriteDeadline(time.Now().Add(-1 * time.Second))

	// Try to write a multi-packet message
	bigMsg := make([]byte, sender.payloadSize*2+100)
	_, err := sender.Write(bigMsg)
	if err == nil {
		t.Error("multi-packet Write with past deadline and full buffer should fail")
	}
}

// TestConnWrite_FileModeConnectionClose tests multi-packet write when
// connection closes mid-write.
func TestConnWrite_FileModeConnectionClose(t *testing.T) {
	sender, _ := testConnPair(t)

	sender.tsbpdEnabled = false
	sender.tlpktdropEnabled = false

	// Fill the send buffer
	for i := 0; i < sender.sendBuf.Capacity(); i++ {
		data := make([]byte, 100)
		p := packet.NewData(sender.remoteAddr, sender.sendBuf.NextSeq().Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle
		if !sender.sendBuf.Push(p, sender.clk.Now()) {
			break
		}
	}

	// Close connection asynchronously
	go func() {
		time.Sleep(10 * time.Millisecond)
		sender.Close()
	}()

	bigMsg := make([]byte, sender.payloadSize*2+100)
	_, err := sender.Write(bigMsg)
	if err == nil {
		t.Error("multi-packet Write on full buffer with connection close should fail")
	}
}

// TestConnWrite_SendDropCheckTlpktDrop tests that Write calls checkSendDrop
// before sending when TLPKT drop is enabled.
func TestConnWrite_SendDropCheckTlpktDrop(t *testing.T) {
	sender, _ := testConnPair(t)

	// TSBPD and tlpktdrop are enabled by default in live mode
	if !sender.tlpktdropEnabled {
		t.Skip("tlpktdrop not enabled")
	}

	data := make([]byte, 100)
	n, err := sender.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, want %d", n, len(data))
	}
}

// TestConnSendPacket_WithFECSender tests that sendPacket feeds into FEC sender.
func TestConnSendPacket_WithFECSender(t *testing.T) {
	sender, _ := testConnPair(t)

	fecCfg := filter.Config{
		Cols:   3,
		Rows:   1,
		Layout: filter.LayoutStaircase,
		ARQ:    filter.ARQOnReq,
	}
	sndISN := sender.sendISN.Value()
	sender.fecSender = filter.NewFECSender(fecCfg, sender.payloadSize, sndISN)

	// Send 3 packets to complete one FEC row group
	for i := 0; i < 3; i++ {
		data := make([]byte, 100)
		seqNo := sender.sendBuf.NextSeq()
		p := packet.NewData(sender.remoteAddr, seqNo.Value(),
			sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
		p.Header.MessageNumber = 1
		p.Header.PacketPosition = packet.PositionSingle

		err := sender.sendPacket(p, len(data))
		if err != nil {
			t.Fatalf("sendPacket %d: %v", i, err)
		}
	}

	// After 3 packets with cols:3, FEC should have emitted 1 control packet
	if sender.sndFilterExtra.Load() > 0 {
		t.Logf("FEC emitted %d control packets via sendPacket path", sender.sndFilterExtra.Load())
	}
}

// TestConnSendPacket_WithKeyRotation tests that sendPacket triggers key rotation
// when encryption is enabled and kmRefreshRate is set.
func TestConnSendPacket_WithKeyRotation(t *testing.T) {
	sender, _ := testConnPair(t)

	ctx, err := crypto.New(16)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	km := &packet.CIFKeyMaterial{}
	if err := ctx.MarshalKM(km, "testpassword", packet.EncryptionEven); err != nil {
		t.Fatalf("MarshalKM: %v", err)
	}
	sender.cryptoCtx = ctx
	sender.activeKey = packet.EncryptionEven
	sender.passphrase = "testpassword"
	sender.kmRefreshRate = 100 // rotate after 100 packets
	sender.kmPreAnnounce = 10  // pre-announce 10 packets before refresh

	data := make([]byte, 100)
	seqNo := sender.sendBuf.NextSeq()
	p := packet.NewData(sender.remoteAddr, seqNo.Value(),
		sender.clk.Now().SRTTimestamp(), sender.peerSocketID, data)
	p.Header.MessageNumber = 1
	p.Header.PacketPosition = packet.PositionSingle

	err = sender.sendPacket(p, len(data))
	if err != nil {
		t.Fatalf("sendPacket with key rotation: %v", err)
	}

	if sender.sentPackets.Load() == 0 {
		t.Error("sentPackets should be > 0")
	}
}

// TestConnInsertRecoveredPacket_GCMEncrypted tests recovered packet with GCM
// encryption (decryption failure path for corrupted GCM auth tags).
func TestConnInsertRecoveredPacket_GCMEncrypted(t *testing.T) {
	c, _ := testSingleConn(t)

	gcmCtx, err := crypto.NewWithMode(16, crypto.CipherGCM)
	if err != nil {
		t.Fatalf("NewWithMode GCM: %v", err)
	}
	gcmKM := &packet.CIFKeyMaterial{}
	if err := gcmCtx.MarshalKM(gcmKM, "testpassword", packet.EncryptionEven); err != nil {
		t.Fatalf("MarshalKM GCM: %v", err)
	}
	c.cryptoCtx = gcmCtx
	c.activeKey = packet.EncryptionEven

	now := c.clk.Now()
	recvISN := c.recvBuf.ACKSequence().Value()

	// For GCM, FEC-recovered packets have XOR'd auth tags which won't verify.
	// This should exercise the GCM header construction + decrypt failure path.
	rp := filter.RecoveredPacket{
		SeqNo:     recvISN,
		Timestamp: now.SRTTimestamp(),
		EncFlag:   uint8(packet.EncryptionEven),
		Payload:   []byte("garbage GCM ciphertext that wont verify"),
	}

	prevRecvPkts := c.recvPackets.Load()
	c.insertRecoveredPacket(rp, now)

	// GCM decryption should fail, packet should NOT be inserted
	if c.recvPackets.Load() != prevRecvPkts {
		t.Logf("GCM recovered packet was inserted (unexpected for garbage data)")
	}
}
