package session_test

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/session"
)

// runEncryptedStream dials an encrypted caller to a new listener (both new
// stack) with the given DialConfig, streams n payloads, verifies they arrive in
// order intact, and returns the caller/receiver stats. cryptoMode selects the
// cipher (0/1 = AES-CTR, 2 = AES-GCM); the listener adopts the caller's mode
// from its KMREQ.
func runEncryptedStream(t *testing.T, dc core.DialConfig, n, payloadLen int) (core.Stats, core.Stats) {
	t.Helper()
	luconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := session.Listen(luconn, core.ListenerConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
		Passphrase: encPass,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan *session.Session, 1)
	go func() {
		if s, err := ln.Accept(); err == nil {
			accepted <- s
		}
	}()

	cuconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	caller, err := session.Dial(cuconn, ln.Addr(), dc, nil, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer caller.Close()

	var recv *session.Session
	select {
	case recv = <-accepted:
		defer recv.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not accept")
	}

	recvd := make(chan error, 1)
	go func() {
		buf := make([]byte, payloadLen+800)
		for i := 0; i < n; i++ {
			got, err := recv.Read(buf)
			if err != nil {
				recvd <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			if got != payloadLen || binary.BigEndian.Uint32(buf) != uint32(i) {
				recvd <- fmt.Errorf("payload mismatch at %d (n=%d)", i, got)
				return
			}
		}
		recvd <- nil
	}()
	go func() {
		for i := 0; i < n; i++ {
			p := make([]byte, payloadLen)
			binary.BigEndian.PutUint32(p, uint32(i))
			if err := caller.Write(p); err != nil {
				return
			}
		}
	}()

	select {
	case err := <-recvd:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout: not all payloads received")
	}
	time.Sleep(150 * time.Millisecond) // let the last ACKs/KMRSPs settle

	cs, err := caller.Stats()
	if err != nil {
		t.Fatal(err)
	}
	rs, err := recv.Stats()
	if err != nil {
		t.Fatal(err)
	}
	return cs, rs
}

// TestNewStackEncryptedGCM proves the AES-GCM data path end-to-end through the
// new stack: the caller chooses GCM, the listener adopts GCM from the KMREQ,
// unwraps the key, and authenticates+decrypts every payload.
func TestNewStackEncryptedGCM(t *testing.T) {
	_, rs := runEncryptedStream(t, core.DialConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
		Passphrase: encPass, KeyLength: 16, CryptoMode: 2, // AES-GCM
	}, 300, 1200)
	if rs.RecvUndecrypt != 0 {
		t.Errorf("receiver RecvUndecrypt = %d, want 0 (GCM must authenticate+decrypt)", rs.RecvUndecrypt)
	}
	if rs.RecvPackets < 300 {
		t.Errorf("receiver RecvPackets = %d, want >= 300", rs.RecvPackets)
	}
}

// TestNewStackKeyRotationGCM runs AES-GCM with a low refresh rate, exercising
// mid-stream key rotation under authenticated encryption.
func TestNewStackKeyRotationGCM(t *testing.T) {
	cs, rs := runEncryptedStream(t, core.DialConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
		Passphrase: encPass, KeyLength: 16, CryptoMode: 2,
		KMRefreshRate: 25, KMPreAnnounce: 6,
	}, 300, 1200)
	if cs.SentKM == 0 || rs.RecvKM == 0 {
		t.Errorf("expected KM traffic (caller sent=%d, receiver recv=%d)", cs.SentKM, rs.RecvKM)
	}
	if rs.RecvUndecrypt != 0 {
		t.Errorf("receiver RecvUndecrypt = %d, want 0 across GCM rotations", rs.RecvUndecrypt)
	}
}

// TestNewStackKeyRotation runs an encrypted (AES-CTR) stream with a deliberately
// low KM refresh rate, so the sender rotates its stream key many times mid-
// stream. Each rotation pre-announces the next key over a KMREQ, switches the
// active slot, and decommissions the old key. Every payload must still arrive
// intact and in order: that only holds if each new key reached the receiver
// (via KMREQ) before the sender switched to it, so the test is an end-to-end
// proof of mid-stream key rotation over real UDP.
func TestNewStackKeyRotation(t *testing.T) {
	cs, rs := runEncryptedStream(t, core.DialConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
		Passphrase: encPass, KeyLength: 16,
		KMRefreshRate: 25, KMPreAnnounce: 6, // rotate every 25 packets
	}, 300, 1200)

	if cs.SentKM == 0 || cs.RecvKM == 0 {
		t.Errorf("caller KM: sent=%d recv=%d, expected both > 0 (KMREQ out, KMRSP back)", cs.SentKM, cs.RecvKM)
	}
	if rs.RecvKM == 0 || rs.SentKM == 0 {
		t.Errorf("receiver KM: recv=%d sent=%d, expected both > 0 (KMREQ in, KMRSP out)", rs.RecvKM, rs.SentKM)
	}
	if rs.RecvUndecrypt != 0 {
		t.Errorf("receiver RecvUndecrypt = %d, want 0 (every rotation key must decrypt)", rs.RecvUndecrypt)
	}
	if cs.SndKmState != 2 { // SRT_KM_S_SECURED
		t.Errorf("caller SndKmState = %d, want 2 (secured/confirmed)", cs.SndKmState)
	}
}
