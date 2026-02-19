package srt

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/packet"
)

// requireUDP sends a single UDP packet to localhost and skips the test if the
// OS blocks it (EPERM). This happens in CI environments where the macOS
// Application Firewall blocks UDP sends from race-instrumented test binaries.
func requireUDP(t *testing.T) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping: cannot bind UDP: %v", err)
	}
	defer conn.Close()
	_, err = conn.WriteTo([]byte("probe"), conn.LocalAddr())
	if err != nil {
		t.Skipf("skipping: UDP send blocked (CI firewall): %v", err)
	}
}

// --- Unit tests for cookie contest ---

func TestRdvCookieContest(t *testing.T) {
	tests := []struct {
		name   string
		agent  uint32
		peer   uint32
		expect rdvSide
	}{
		{"agent larger (both positive)", 1000, 500, rdvInitiator},
		{"agent smaller (both positive)", 500, 1000, rdvResponder},
		{"equal cookies", 42, 42, rdvDraw},
		{"equal zero", 0, 0, rdvDraw},
		{"agent=0 peer=1", 0, 1, rdvResponder},
		{"agent=1 peer=0", 1, 0, rdvInitiator},
		{"high bit agent", 0x80000001, 0x00000001, rdvResponder},
		{"high bit peer", 0x00000001, 0x80000001, rdvInitiator},
		{"both high bit, agent larger", 0xFFFFFFFF, 0x80000000, rdvInitiator},
		{"both high bit, agent smaller", 0x80000000, 0xFFFFFFFF, rdvResponder},
		// 0x7FFFFFFF as int32=MAX_INT, 0x80000001 as int32=-MAX_INT
		// contest=4294967294 (0xFFFFFFFE), bit 31 set → enter negative branch
		// revert=-4294967294 (0xFFFFFFFF00000002), bit 31 NOT set → RESPONDER
		{"overflow case 1", 0x7FFFFFFF, 0x80000001, rdvResponder},
		{"max uint32", 0xFFFFFFFF, 0xFFFFFFFE, rdvInitiator},
		{"max uint32 reversed", 0xFFFFFFFE, 0xFFFFFFFF, rdvResponder},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rdvCookieContest(tt.agent, tt.peer)
			if got != tt.expect {
				t.Errorf("rdvCookieContest(%#x, %#x) = %d, want %d", tt.agent, tt.peer, got, tt.expect)
			}
		})
	}
}

// Verify symmetry: if A→B is INITIATOR, then B→A is RESPONDER
func TestRdvCookieContestSymmetry(t *testing.T) {
	pairs := [][2]uint32{
		{100, 200},
		{0x80000001, 0x00000001},
		{0xFFFFFFFF, 1},
		{0x7FFFFFFF, 0x80000001},
	}
	for _, p := range pairs {
		a, b := p[0], p[1]
		ab := rdvCookieContest(a, b)
		ba := rdvCookieContest(b, a)
		if ab == rdvDraw || ba == rdvDraw {
			t.Errorf("unexpected draw for %#x vs %#x", a, b)
			continue
		}
		if ab == ba {
			t.Errorf("rdvCookieContest not symmetric: (%#x,%#x)=%d, (%#x,%#x)=%d", a, b, ab, b, a, ba)
		}
		if ab == rdvInitiator && ba != rdvResponder {
			t.Errorf("expected RESPONDER for reverse, got %d", ba)
		}
		if ab == rdvResponder && ba != rdvInitiator {
			t.Errorf("expected INITIATOR for reverse, got %d", ba)
		}
	}
}

// --- Unit tests for state machine ---

func TestRdvSwitchState(t *testing.T) {
	tests := []struct {
		name        string
		state       rdvState
		recvType    packet.HandshakeType
		side        rdvSide
		hasExtFlags bool
		expect      rdvTransition
	}{
		// WAVING state
		{
			"WAVING+WAVEHAND→ATTENTION (INITIATOR)",
			rdvWaving, packet.HandshakeTypeWavehand, rdvInitiator, false,
			rdvTransition{rdvAttention, packet.HandshakeTypeConclusion, true, false},
		},
		{
			"WAVING+WAVEHAND→ATTENTION (RESPONDER)",
			rdvWaving, packet.HandshakeTypeWavehand, rdvResponder, false,
			rdvTransition{rdvAttention, packet.HandshakeTypeConclusion, false, false},
		},
		{
			"WAVING+CONCLUSION→FINE (INITIATOR)",
			rdvWaving, packet.HandshakeTypeConclusion, rdvInitiator, false,
			rdvTransition{rdvFine, packet.HandshakeTypeConclusion, true, false},
		},
		{
			"WAVING+CONCLUSION+ext→FINE (RESPONDER)",
			rdvWaving, packet.HandshakeTypeConclusion, rdvResponder, true,
			rdvTransition{rdvFine, packet.HandshakeTypeConclusion, true, true},
		},

		// ATTENTION state
		{
			"ATTENTION+WAVEHAND (INITIATOR resend)",
			rdvAttention, packet.HandshakeTypeWavehand, rdvInitiator, false,
			rdvTransition{rdvAttention, packet.HandshakeTypeConclusion, true, false},
		},
		{
			"ATTENTION+WAVEHAND (RESPONDER resend)",
			rdvAttention, packet.HandshakeTypeWavehand, rdvResponder, false,
			rdvTransition{rdvAttention, packet.HandshakeTypeConclusion, false, false},
		},
		{
			"ATTENTION+CONCLUSION+HSRSP→CONNECTED (INITIATOR)",
			rdvAttention, packet.HandshakeTypeConclusion, rdvInitiator, true,
			rdvTransition{rdvConnected, packet.HandshakeTypeAgreement, false, false},
		},
		{
			"ATTENTION+CONCLUSION(empty)→stay (INITIATOR)",
			rdvAttention, packet.HandshakeTypeConclusion, rdvInitiator, false,
			rdvTransition{rdvAttention, packet.HandshakeTypeConclusion, true, false},
		},
		{
			"ATTENTION+CONCLUSION+HSREQ→INITIATED (RESPONDER)",
			rdvAttention, packet.HandshakeTypeConclusion, rdvResponder, true,
			rdvTransition{rdvInitiated, packet.HandshakeTypeConclusion, true, true},
		},
		{
			"ATTENTION+CONCLUSION(empty)→stay (RESPONDER)",
			rdvAttention, packet.HandshakeTypeConclusion, rdvResponder, false,
			rdvTransition{rdvAttention, packet.HandshakeTypeConclusion, false, false},
		},
		{
			"ATTENTION+AGREEMENT→CONNECTED (INITIATOR)",
			rdvAttention, packet.HandshakeTypeAgreement, rdvInitiator, false,
			rdvTransition{rdvConnected, packet.HandshakeTypeDone, false, false},
		},
		{
			"ATTENTION+AGREEMENT→resend HSRSP (RESPONDER)",
			rdvAttention, packet.HandshakeTypeAgreement, rdvResponder, false,
			rdvTransition{rdvAttention, packet.HandshakeTypeConclusion, true, true},
		},

		// FINE state
		{
			"FINE+CONCLUSION+HSRSP→CONNECTED (INITIATOR)",
			rdvFine, packet.HandshakeTypeConclusion, rdvInitiator, true,
			rdvTransition{rdvConnected, packet.HandshakeTypeAgreement, false, false},
		},
		{
			"FINE+CONCLUSION(empty)→stay (INITIATOR resend HSREQ)",
			rdvFine, packet.HandshakeTypeConclusion, rdvInitiator, false,
			rdvTransition{rdvFine, packet.HandshakeTypeConclusion, true, false},
		},
		{
			"FINE+CONCLUSION→stay (RESPONDER resend HSRSP)",
			rdvFine, packet.HandshakeTypeConclusion, rdvResponder, true,
			rdvTransition{rdvFine, packet.HandshakeTypeConclusion, true, true},
		},
		{
			"FINE+AGREEMENT→CONNECTED",
			rdvFine, packet.HandshakeTypeAgreement, rdvInitiator, false,
			rdvTransition{rdvConnected, packet.HandshakeTypeDone, false, false},
		},

		// INITIATED state
		{
			"INITIATED+AGREEMENT→CONNECTED",
			rdvInitiated, packet.HandshakeTypeAgreement, rdvResponder, false,
			rdvTransition{rdvConnected, packet.HandshakeTypeDone, false, false},
		},
		{
			"INITIATED+CONCLUSION→resend HSRSP",
			rdvInitiated, packet.HandshakeTypeConclusion, rdvResponder, true,
			rdvTransition{rdvInitiated, packet.HandshakeTypeConclusion, true, true},
		},

		// CONNECTED state
		{
			"CONNECTED+anything→DONE",
			rdvConnected, packet.HandshakeTypeWavehand, rdvInitiator, false,
			rdvTransition{rdvConnected, packet.HandshakeTypeDone, false, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rdvSwitchState(tt.state, tt.recvType, tt.side, tt.hasExtFlags)
			if got != tt.expect {
				t.Errorf("rdvSwitchState(%v, %v, %v, %v)\n  got  %+v\n  want %+v",
					tt.state, tt.recvType, tt.side, tt.hasExtFlags, got, tt.expect)
			}
		})
	}
}

// --- Integration tests ---

func TestRdvStateString(t *testing.T) {
	tests := []struct {
		state rdvState
		want  string
	}{
		{rdvWaving, "WAVING"},
		{rdvAttention, "ATTENTION"},
		{rdvFine, "FINE"},
		{rdvInitiated, "INITIATED"},
		{rdvConnected, "CONNECTED"},
		{rdvState(99), "INVALID"},
	}

	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.want {
			t.Errorf("rdvState(%d).String(): got %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestRendezvousBasic(t *testing.T) {
	requireUDP(t)

	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 10 * time.Second

	// Bind two UDP sockets up front — avoids TOCTOU race where the OS
	// reassigns a closed ephemeral port before DialRendezvous can rebind.
	sockA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind A: %v", err)
	}
	sockB, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		sockA.Close()
		t.Fatalf("bind B: %v", err)
	}

	addrA := sockA.LocalAddr()
	addrB := sockB.LocalAddr()

	var connA, connB *Conn
	var errA, errB error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		connA, errA = dialRendezvous(sockA, addrB, cfg, nil)
	}()
	go func() {
		defer wg.Done()
		connB, errB = dialRendezvous(sockB, addrA, cfg, nil)
	}()
	wg.Wait()

	if errA != nil {
		t.Fatalf("DialRendezvous A: %v", errA)
	}
	if errB != nil {
		t.Fatalf("DialRendezvous B: %v", errB)
	}
	defer connA.Close()
	defer connB.Close()

	// Send A→B
	payload := []byte("hello from A")
	if _, err := connA.Write(payload); err != nil {
		t.Fatalf("Write A→B: %v", err)
	}

	connB.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1500)
	n, err := connB.Read(buf)
	if err != nil {
		t.Fatalf("Read B: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("A→B: got %q, want %q", buf[:n], payload)
	}

	// Send B→A
	payload2 := []byte("hello from B")
	if _, err := connB.Write(payload2); err != nil {
		t.Fatalf("Write B→A: %v", err)
	}

	connA.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err = connA.Read(buf)
	if err != nil {
		t.Fatalf("Read A: %v", err)
	}
	if !bytes.Equal(buf[:n], payload2) {
		t.Errorf("B→A: got %q, want %q", buf[:n], payload2)
	}
}

func TestRendezvousEncrypted(t *testing.T) {
	requireUDP(t)

	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 10 * time.Second // encryption + race detector need headroom
	cfg.Passphrase = "rendezvous-secret-key"

	sockA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind A: %v", err)
	}
	sockB, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		sockA.Close()
		t.Fatalf("bind B: %v", err)
	}

	var connA, connB *Conn
	var errA, errB error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		connA, errA = dialRendezvous(sockA, sockB.LocalAddr(), cfg, nil)
	}()
	go func() {
		defer wg.Done()
		connB, errB = dialRendezvous(sockB, sockA.LocalAddr(), cfg, nil)
	}()
	wg.Wait()

	if errA != nil {
		t.Fatalf("DialRendezvous A: %v", errA)
	}
	if errB != nil {
		t.Fatalf("DialRendezvous B: %v", errB)
	}
	defer connA.Close()
	defer connB.Close()

	// Send encrypted data A→B
	payload := []byte("encrypted rendezvous data")
	if _, err := connA.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	connB.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1500)
	n, err := connB.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("got %q, want %q", buf[:n], payload)
	}
}

func TestRendezvousTimeout(t *testing.T) {
	requireUDP(t)

	cfg := DefaultConfig()
	cfg.ConnTimeout = 500 * time.Millisecond

	sockA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	remoteAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:19999")

	start := time.Now()
	_, err = dialRendezvous(sockA, remoteAddr, cfg, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if elapsed < 400*time.Millisecond || elapsed > 2*time.Second {
		t.Errorf("timeout took %v, expected ~500ms", elapsed)
	}
}

func TestRendezvousCookieDraw(t *testing.T) {
	// Test the state machine directly — cookie draw produces DRAW
	result := rdvCookieContest(42, 42)
	if result != rdvDraw {
		t.Errorf("expected rdvDraw for equal cookies, got %d", result)
	}
}

func TestRendezvousFileMode(t *testing.T) {
	requireUDP(t)

	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 10 * time.Second
	cfg.TransType = TransTypeFile

	sockA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind A: %v", err)
	}
	sockB, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		sockA.Close()
		t.Fatalf("bind B: %v", err)
	}

	var connA, connB *Conn
	var errA, errB error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		connA, errA = dialRendezvous(sockA, sockB.LocalAddr(), cfg, nil)
	}()
	go func() {
		defer wg.Done()
		connB, errB = dialRendezvous(sockB, sockA.LocalAddr(), cfg, nil)
	}()
	wg.Wait()

	if errA != nil {
		t.Fatalf("DialRendezvous A: %v", errA)
	}
	if errB != nil {
		t.Fatalf("DialRendezvous B: %v", errB)
	}
	defer connA.Close()
	defer connB.Close()

	// Send data in file mode
	payload := bytes.Repeat([]byte("file-data"), 100)
	if _, err := connA.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	connB.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, len(payload)+100)
	total := 0
	for total < len(payload) {
		n, err := connB.Read(buf[total:])
		if err != nil {
			t.Fatalf("Read: %v (got %d/%d bytes)", err, total, len(payload))
		}
		total += n
	}

	if !bytes.Equal(buf[:total], payload) {
		t.Errorf("file data mismatch: got %d bytes, want %d", total, len(payload))
	}
}

// --- Additional state machine edge case tests ---

func TestRdvSwitchState_InvalidTransitions(t *testing.T) {
	// Test invalid state machine transitions that produce rejection.
	tests := []struct {
		name     string
		state    rdvState
		recvType packet.HandshakeType
		side     rdvSide
	}{
		// WAVING + AGREEMENT is not a valid transition
		{"WAVING+AGREEMENT", rdvWaving, packet.HandshakeTypeAgreement, rdvInitiator},
		// FINE + WAVEHAND is not handled (falls through to rejection)
		{"FINE+WAVEHAND", rdvFine, packet.HandshakeTypeWavehand, rdvInitiator},
		// INITIATED + WAVEHAND is not handled
		{"INITIATED+WAVEHAND", rdvInitiated, packet.HandshakeTypeWavehand, rdvResponder},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := rdvSwitchState(tt.state, tt.recvType, tt.side, false)
			if !trans.rspType.IsRejection() {
				t.Errorf("expected rejection for invalid transition %s, got rspType=%v newState=%v",
					tt.name, trans.rspType, trans.newState)
			}
		})
	}
}

func TestRdvSwitchState_DrawInAttention(t *testing.T) {
	// ATTENTION + CONCLUSION with DRAW side should produce rejection.
	trans := rdvSwitchState(rdvAttention, packet.HandshakeTypeConclusion, rdvDraw, false)
	if trans.newState != rdvWaving {
		t.Errorf("expected newState=rdvWaving, got %v", trans.newState)
	}
	// The rspType should be the RejRdvCookie code
	if uint32(trans.rspType) != uint32(RejRdvCookie) {
		t.Errorf("expected rspType=RejRdvCookie (%d), got %d", RejRdvCookie, uint32(trans.rspType))
	}
}

func TestRdvSwitchState_FineResponderResend(t *testing.T) {
	// FINE + CONCLUSION for RESPONDER without ext flags should resend with HSRSP.
	trans := rdvSwitchState(rdvFine, packet.HandshakeTypeConclusion, rdvResponder, false)
	if trans.newState != rdvFine {
		t.Errorf("expected newState=rdvFine, got %v", trans.newState)
	}
	if !trans.needsExt {
		t.Error("expected needsExt=true")
	}
	if !trans.needsHSRSP {
		t.Error("expected needsHSRSP=true for RESPONDER")
	}
}

func TestRdvSwitchState_InitiatedConclusionResend(t *testing.T) {
	// INITIATED + CONCLUSION should resend CONCLUSION+HSRSP.
	trans := rdvSwitchState(rdvInitiated, packet.HandshakeTypeConclusion, rdvResponder, false)
	if trans.newState != rdvInitiated {
		t.Errorf("expected newState=rdvInitiated, got %v", trans.newState)
	}
	if !trans.needsExt {
		t.Error("expected needsExt=true for resend")
	}
	if !trans.needsHSRSP {
		t.Error("expected needsHSRSP=true for RESPONDER resend")
	}
}

func TestRendezvousInvalidConfig(t *testing.T) {
	// DialRendezvous with invalid config should fail at validation.
	cfg := Config{
		MSS: 10, // too small
	}
	_, err := DialRendezvous("127.0.0.1:5000", "127.0.0.1:5001", cfg)
	if err == nil {
		t.Error("DialRendezvous with invalid config should fail")
	}
}

func TestRendezvousInvalidLocalAddr(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ConnTimeout = 500 * time.Millisecond

	_, err := DialRendezvous("invalid:addr:too:many", "127.0.0.1:5001", cfg)
	if err == nil {
		t.Error("DialRendezvous with invalid local address should fail")
	}
}

func TestRendezvousInvalidRemoteAddr(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ConnTimeout = 500 * time.Millisecond

	_, err := DialRendezvous("127.0.0.1:0", "invalid:addr:too:many", cfg)
	if err == nil {
		t.Error("DialRendezvous with invalid remote address should fail")
	}
}

func TestRendezvousCookieContest_SpecialCases(t *testing.T) {
	// Test additional cookie contest edge cases.
	tests := []struct {
		name   string
		agent  uint32
		peer   uint32
		expect rdvSide
	}{
		// Both zero => draw
		{"both-zero", 0, 0, rdvDraw},
		// Large gap
		{"large-gap", 0xFFFF0000, 0x0000FFFF, rdvResponder},
		// Adjacent values
		{"adjacent", 100, 101, rdvResponder},
		{"adjacent-reverse", 101, 100, rdvInitiator},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rdvCookieContest(tt.agent, tt.peer)
			if got != tt.expect {
				t.Errorf("rdvCookieContest(%#x, %#x) = %d, want %d",
					tt.agent, tt.peer, got, tt.expect)
			}
		})
	}
}

func TestRendezvousWithStreamID(t *testing.T) {
	requireUDP(t)

	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 10 * time.Second
	cfg.StreamID = "rendezvous/stream"

	sockA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind A: %v", err)
	}
	sockB, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		sockA.Close()
		t.Fatalf("bind B: %v", err)
	}

	var connA, connB *Conn
	var errA, errB error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		connA, errA = dialRendezvous(sockA, sockB.LocalAddr(), cfg, nil)
	}()
	go func() {
		defer wg.Done()
		connB, errB = dialRendezvous(sockB, sockA.LocalAddr(), cfg, nil)
	}()
	wg.Wait()

	if errA != nil {
		t.Fatalf("DialRendezvous A: %v", errA)
	}
	if errB != nil {
		t.Fatalf("DialRendezvous B: %v", errB)
	}
	defer connA.Close()
	defer connB.Close()

	// Both should have the same stream ID
	if connA.StreamID() != "rendezvous/stream" {
		t.Errorf("A StreamID: got %q, want %q", connA.StreamID(), "rendezvous/stream")
	}
	if connB.StreamID() != "rendezvous/stream" {
		t.Errorf("B StreamID: got %q, want %q", connB.StreamID(), "rendezvous/stream")
	}
}
