package session_test

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/session"
)

// TestGroupBroadcastUDP drives a broadcast bonding group over real UDP: a sender
// group fans each payload across two links (one of which permanently drops a set
// of packets) with a shared sequence space, and a receiver group merges the two
// links, delivering every payload once. The dropped packets must arrive via the
// healthy link — seamless redundancy through the real multi-member I/O loop.
func TestGroupBroadcastUDP(t *testing.T) {
	const (
		sharedISN  = 100
		rcvSendISN = 9000
		n          = 400
		payloadLen = 1200
		maxBW      = 125_000_000
		latency    = 120 * time.Millisecond
	)

	// Four sockets: sender/receiver endpoints of link A and link B.
	rawSndA, rcvA := mustUDP(t), mustUDP(t)
	sndB, rcvB := mustUDP(t), mustUDP(t)
	// Link A permanently drops these data sequence numbers; redundancy must
	// deliver them via link B.
	sndA := &lossyConn{
		PacketConn: rawSndA,
		permanent:  true,
		dropSeq:    map[uint32]bool{105: true, 106: true, 150: true, 222: true, 333: true, 400: true},
	}

	tsbpd := clock.FromDuration(latency)

	snd := session.NewEstablishedGroup(core.GroupBroadcast, []session.GroupMemberConfig{
		{
			Conn: sndA, LocalSocketID: 1, RemoteAddr: rcvA.LocalAddr(),
			Config: core.Config{PeerSocketID: 2, PayloadSize: payloadLen, SendISN: sharedISN, RecvISN: rcvSendISN, MaxBW: maxBW},
		},
		{
			Conn: sndB, LocalSocketID: 3, RemoteAddr: rcvB.LocalAddr(),
			Config: core.Config{PeerSocketID: 4, PayloadSize: payloadLen, SendISN: sharedISN, RecvISN: rcvSendISN + 1, MaxBW: maxBW},
		},
	}, nil)
	defer snd.Close()

	rcv := session.NewEstablishedGroup(core.GroupBroadcast, []session.GroupMemberConfig{
		{
			Conn: rcvA, LocalSocketID: 2, RemoteAddr: rawSndA.LocalAddr(),
			Config: core.Config{PeerSocketID: 1, PayloadSize: payloadLen, SendISN: rcvSendISN, RecvISN: sharedISN, MaxBW: maxBW, Live: true, TsbpdDelay: tsbpd},
		},
		{
			Conn: rcvB, LocalSocketID: 4, RemoteAddr: sndB.LocalAddr(),
			Config: core.Config{PeerSocketID: 3, PayloadSize: payloadLen, SendISN: rcvSendISN + 1, RecvISN: sharedISN, MaxBW: maxBW, Live: true, TsbpdDelay: tsbpd},
		},
	}, nil)
	defer rcv.Close()

	go func() {
		for i := 0; i < n; i++ {
			p := make([]byte, payloadLen)
			binary.BigEndian.PutUint32(p, uint32(i))
			if err := snd.Write(p); err != nil {
				return
			}
		}
	}()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2000)
		for i := 0; i < n; i++ {
			got, err := rcv.Read(buf)
			if err != nil {
				done <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			if got != payloadLen || binary.BigEndian.Uint32(buf) != uint32(i) {
				done <- fmt.Errorf("payload mismatch at %d (n=%d)", i, got)
				return
			}
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout: group did not deliver all payloads")
	}
}

// TestGroupBackupUDP drives a weighted backup bonding group over real UDP: the
// stream runs on the higher-weight active link until it is "killed" mid-stream,
// at which point the group fails over to the standby (replaying its sender
// buffer). The high TSBPD latency covers the failover window, so every payload
// is still delivered in order.
func TestGroupBackupUDP(t *testing.T) {
	const (
		sharedISN   = 100
		rcvSendISN  = 9000
		n           = 300
		payloadLen  = 1200
		maxBW       = 125_000_000
		latency     = 2 * time.Second        // generous buffer to span failover
		writePeriod = 5 * time.Millisecond   // pace writes so the kill lands mid-stream
		killAfter   = 400 * time.Millisecond // kill the active link partway in
	)

	rawSndA, rcvA := mustUDP(t), mustUDP(t)
	rawSndB, rcvB := mustUDP(t), mustUDP(t)
	sndA := &lossyConn{PacketConn: rawSndA} // killable active link

	tsbpd := clock.FromDuration(latency)

	snd := session.NewEstablishedGroup(core.GroupBackup, []session.GroupMemberConfig{
		{
			Conn: sndA, LocalSocketID: 1, RemoteAddr: rcvA.LocalAddr(), Weight: 10,
			Config: core.Config{PeerSocketID: 2, PayloadSize: payloadLen, SendISN: sharedISN, RecvISN: rcvSendISN, MaxBW: maxBW},
		},
		{
			Conn: rawSndB, LocalSocketID: 3, RemoteAddr: rcvB.LocalAddr(), Weight: 5,
			Config: core.Config{PeerSocketID: 4, PayloadSize: payloadLen, SendISN: sharedISN, RecvISN: rcvSendISN + 1, MaxBW: maxBW},
		},
	}, nil)
	defer snd.Close()

	rcv := session.NewEstablishedGroup(core.GroupBackup, []session.GroupMemberConfig{
		{
			Conn: rcvA, LocalSocketID: 2, RemoteAddr: rawSndA.LocalAddr(), Weight: 10,
			Config: core.Config{PeerSocketID: 1, PayloadSize: payloadLen, SendISN: rcvSendISN, RecvISN: sharedISN, MaxBW: maxBW, Live: true, TsbpdDelay: tsbpd},
		},
		{
			Conn: rcvB, LocalSocketID: 4, RemoteAddr: rawSndB.LocalAddr(), Weight: 5,
			Config: core.Config{PeerSocketID: 3, PayloadSize: payloadLen, SendISN: rcvSendISN + 1, RecvISN: sharedISN, MaxBW: maxBW, Live: true, TsbpdDelay: tsbpd},
		},
	}, nil)
	defer rcv.Close()

	// Kill the active link partway through the stream.
	go func() {
		time.Sleep(killAfter)
		sndA.kill.Store(true)
	}()

	go func() {
		for i := 0; i < n; i++ {
			p := make([]byte, payloadLen)
			binary.BigEndian.PutUint32(p, uint32(i))
			if err := snd.Write(p); err != nil {
				return
			}
			time.Sleep(writePeriod)
		}
	}()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2000)
		for i := 0; i < n; i++ {
			got, err := rcv.Read(buf)
			if err != nil {
				done <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			if got != payloadLen || binary.BigEndian.Uint32(buf) != uint32(i) {
				done <- fmt.Errorf("payload mismatch at %d (n=%d)", i, got)
				return
			}
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timeout: backup group did not deliver all payloads after failover")
	}
}
