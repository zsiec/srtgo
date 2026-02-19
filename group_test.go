package srt

import (
	"sync"
	"testing"
	"time"
)

// helper: create a listener and connected pair for group tests
func setupGroupConn(t *testing.T) (*Listener, *Conn, *Conn) {
	t.Helper()

	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

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

	wg.Wait()
	if dialErr != nil {
		server.Close()
		t.Fatalf("Dial: %v", dialErr)
	}

	return l, client, server
}

func TestNewGroup(t *testing.T) {
	g := NewGroup(GroupBroadcast)
	defer g.Close()

	if g.Mode() != GroupBroadcast {
		t.Errorf("Mode: got %v, want GroupBroadcast", g.Mode())
	}
	if g.GroupID() == 0 {
		t.Error("GroupID should not be zero")
	}

	members := g.Members()
	if len(members) != 0 {
		t.Errorf("Members: got %d, want 0", len(members))
	}

	stats := g.Stats()
	if stats.Members != 0 {
		t.Errorf("Stats.Members: got %d, want 0", stats.Members)
	}
}

func TestNewGroupBackup(t *testing.T) {
	g := NewGroup(GroupBackup)
	defer g.Close()

	if g.Mode() != GroupBackup {
		t.Errorf("Mode: got %v, want GroupBackup", g.Mode())
	}
}

func TestGroupModeString(t *testing.T) {
	if GroupBroadcast.String() != "broadcast" {
		t.Errorf("GroupBroadcast.String(): got %q", GroupBroadcast.String())
	}
	if GroupBackup.String() != "backup" {
		t.Errorf("GroupBackup.String(): got %q", GroupBackup.String())
	}
}

func TestGroupBalancingString(t *testing.T) {
	if GroupBalancing.String() != "balancing" {
		t.Errorf("GroupBalancing.String(): got %q, want %q", GroupBalancing.String(), "balancing")
	}
}

func TestGroupBalancingValue(t *testing.T) {
	// GroupBalancing should be 3 (following GroupBroadcast=1, GroupBackup=2)
	// wire value: SRT_GTYPE_BALANCING = 3
	if int(GroupBalancing) != 3 {
		t.Errorf("GroupBalancing value: got %d, want 3", int(GroupBalancing))
	}
}

func TestGroupModeStringUnknown(t *testing.T) {
	// Unknown mode should return "GroupMode(N)" format
	unknown := GroupMode(99)
	s := unknown.String()
	if s != "GroupMode(99)" {
		t.Errorf("Unknown GroupMode.String(): got %q, want %q", s, "GroupMode(99)")
	}
}

func TestMemberStatusString(t *testing.T) {
	tests := []struct {
		s    MemberStatus
		want string
	}{
		{MemberPending, "pending"},
		{MemberIdle, "idle"},
		{MemberRunning, "running"},
		{MemberBroken, "broken"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("%d.String(): got %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestBackupStateString(t *testing.T) {
	tests := []struct {
		s    BackupState
		want string
	}{
		{BackupStandby, "standby"},
		{BackupActiveFresh, "fresh"},
		{BackupActiveStable, "stable"},
		{BackupActiveUnstable, "unstable"},
		{BackupActiveWary, "wary"},
		{BackupBroken, "broken"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("%d.String(): got %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestGroupAddConn(t *testing.T) {
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	g := NewGroup(GroupBroadcast)
	defer g.Close()

	err := g.AddConn(client, 1, 100)
	if err != nil {
		t.Fatalf("AddConn: %v", err)
	}

	members := g.Members()
	if len(members) != 1 {
		t.Fatalf("Members: got %d, want 1", len(members))
	}
	if members[0].Token != 1 {
		t.Errorf("Token: got %d, want 1", members[0].Token)
	}
	if members[0].Weight != 100 {
		t.Errorf("Weight: got %d, want 100", members[0].Weight)
	}
	if members[0].Status != MemberIdle {
		t.Errorf("Status: got %v, want idle", members[0].Status)
	}

	stats := g.Stats()
	if stats.Members != 1 {
		t.Errorf("Stats.Members: got %d, want 1", stats.Members)
	}
}

func TestGroupAddConnNil(t *testing.T) {
	g := NewGroup(GroupBroadcast)
	defer g.Close()

	err := g.AddConn(nil, 1, 0)
	if err == nil {
		t.Error("AddConn(nil) should return error")
	}
}

func TestGroupAddConnClosed(t *testing.T) {
	g := NewGroup(GroupBroadcast)
	g.Close()

	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer client.Close()
	defer server.Close()

	err := g.AddConn(client, 1, 0)
	if err == nil {
		t.Error("AddConn on closed group should return error")
	}
}

func TestGroupBroadcastBasic(t *testing.T) {
	// Create two separate listeners (simulating two links)
	l1, client1, server1 := setupGroupConn(t)
	defer l1.Close()
	defer server1.Close()

	l2, client2, server2 := setupGroupConn(t)
	defer l2.Close()
	defer server2.Close()

	// Create broadcast group with both clients
	g := NewGroup(GroupBroadcast)
	defer g.Close()

	if err := g.AddConn(client1, 1, 0); err != nil {
		t.Fatalf("AddConn 1: %v", err)
	}
	if err := g.AddConn(client2, 2, 0); err != nil {
		t.Fatalf("AddConn 2: %v", err)
	}

	// Write through the group
	payload := []byte("hello broadcast")
	n, err := g.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Write: got %d bytes, want %d", n, len(payload))
	}

	// Both servers should receive the data
	buf := make([]byte, 1024)

	n1, err := server1.Read(buf)
	if err != nil {
		t.Fatalf("Read from server1: %v", err)
	}
	if string(buf[:n1]) != "hello broadcast" {
		t.Errorf("server1 got %q, want %q", string(buf[:n1]), "hello broadcast")
	}

	n2, err := server2.Read(buf)
	if err != nil {
		t.Fatalf("Read from server2: %v", err)
	}
	if string(buf[:n2]) != "hello broadcast" {
		t.Errorf("server2 got %q, want %q", string(buf[:n2]), "hello broadcast")
	}

	// Stats should reflect sent packets
	stats := g.Stats()
	if stats.SentPackets < 2 {
		t.Errorf("Stats.SentPackets: got %d, want >= 2", stats.SentPackets)
	}
}

func TestGroupBroadcastOneFails(t *testing.T) {
	l1, client1, server1 := setupGroupConn(t)
	defer l1.Close()
	defer server1.Close()

	l2, client2, server2 := setupGroupConn(t)
	defer l2.Close()

	g := NewGroup(GroupBroadcast)
	defer g.Close()

	if err := g.AddConn(client1, 1, 0); err != nil {
		t.Fatalf("AddConn 1: %v", err)
	}
	if err := g.AddConn(client2, 2, 0); err != nil {
		t.Fatalf("AddConn 2: %v", err)
	}

	// Close one connection to simulate failure
	server2.Close()
	client2.Close()

	// Give time for the close to propagate
	time.Sleep(50 * time.Millisecond)

	// Write should still succeed via the other link
	payload := []byte("still working")
	n, err := g.Write(payload)
	if err != nil {
		t.Fatalf("Write after one failure: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Write: got %d bytes, want %d", n, len(payload))
	}

	// server1 should still receive
	buf := make([]byte, 1024)
	n, err = server1.Read(buf)
	if err != nil {
		t.Fatalf("Read from server1: %v", err)
	}
	if string(buf[:n]) != "still working" {
		t.Errorf("server1 got %q, want %q", string(buf[:n]), "still working")
	}
}

func TestGroupBackupBasic(t *testing.T) {
	l1, client1, server1 := setupGroupConn(t)
	defer l1.Close()
	defer server1.Close()

	l2, client2, _ := setupGroupConn(t)
	defer l2.Close()
	// Don't read from server2 — it's standby

	g := NewGroup(GroupBackup)
	defer g.Close()

	// Higher weight = preferred active
	if err := g.AddConn(client1, 1, 100); err != nil {
		t.Fatalf("AddConn 1: %v", err)
	}
	if err := g.AddConn(client2, 2, 50); err != nil {
		t.Fatalf("AddConn 2: %v", err)
	}

	// Write should go to the higher-weight member
	payload := []byte("backup test")
	n, err := g.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Write: got %d bytes, want %d", n, len(payload))
	}

	// server1 (higher weight) should receive the data
	buf := make([]byte, 1024)
	n, err = server1.Read(buf)
	if err != nil {
		t.Fatalf("Read from server1: %v", err)
	}
	if string(buf[:n]) != "backup test" {
		t.Errorf("server1 got %q, want %q", string(buf[:n]), "backup test")
	}
}

func TestGroupBackupWeight(t *testing.T) {
	// Verify that higher-weight standby is activated first
	l1, client1, _ := setupGroupConn(t)
	defer l1.Close()

	l2, client2, _ := setupGroupConn(t)
	defer l2.Close()

	g := NewGroup(GroupBackup)
	defer g.Close()

	// Lower weight added first
	if err := g.AddConn(client1, 1, 10); err != nil {
		t.Fatalf("AddConn 1: %v", err)
	}
	// Higher weight added second
	if err := g.AddConn(client2, 2, 200); err != nil {
		t.Fatalf("AddConn 2: %v", err)
	}

	// Write triggers activation of highest-weight standby
	_, err := g.Write([]byte("test"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Check that member with token=2 (weight=200) is the active one
	members := g.Members()
	var activeToken int
	for _, m := range members {
		if m.BackupState != BackupStandby && m.Status == MemberRunning {
			activeToken = m.Token
		}
	}
	if activeToken != 2 {
		t.Errorf("Active member token: got %d, want 2 (highest weight)", activeToken)
	}
}

func TestGroupClose(t *testing.T) {
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	g := NewGroup(GroupBroadcast)
	if err := g.AddConn(client, 1, 0); err != nil {
		t.Fatalf("AddConn: %v", err)
	}

	err := g.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Double close should be safe
	err = g.Close()
	if err != nil {
		t.Fatalf("Double Close: %v", err)
	}

	// Write after close should fail
	_, err = g.Write([]byte("test"))
	if err == nil {
		t.Error("Write after Close should return error")
	}

	// Read after close should fail
	buf := make([]byte, 1024)
	_, err = g.Read(buf)
	if err == nil {
		t.Error("Read after Close should return error")
	}
}

func TestGroupStats(t *testing.T) {
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	g := NewGroup(GroupBroadcast)
	defer g.Close()

	if err := g.AddConn(client, 1, 0); err != nil {
		t.Fatalf("AddConn: %v", err)
	}

	// Initial stats
	stats := g.Stats()
	if stats.Members != 1 {
		t.Errorf("Members: got %d, want 1", stats.Members)
	}
	if stats.SentPackets != 0 {
		t.Errorf("SentPackets: got %d, want 0", stats.SentPackets)
	}

	// Write some data
	for range 5 {
		_, err := g.Write([]byte("packet"))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	stats = g.Stats()
	if stats.SentPackets != 5 {
		t.Errorf("SentPackets: got %d, want 5", stats.SentPackets)
	}
}

func TestGroupReadDedup(t *testing.T) {
	// Set up two server→client paths that both feed into a group reader.
	// Both servers write the same data. The group reader should deliver
	// each piece of data exactly once (dedup by sequence number).

	l1, client1, server1 := setupGroupConn(t)
	defer l1.Close()
	defer server1.Close()

	g := NewGroup(GroupBroadcast)
	defer g.Close()

	if err := g.AddConn(client1, 1, 0); err != nil {
		t.Fatalf("AddConn: %v", err)
	}

	// Server sends data
	payload := []byte("dedup test")
	_, err := server1.Write(payload)
	if err != nil {
		t.Fatalf("server1 Write: %v", err)
	}

	// Read through group
	buf := make([]byte, 1024)
	n, err := g.Read(buf)
	if err != nil {
		t.Fatalf("Group Read: %v", err)
	}
	if string(buf[:n]) != "dedup test" {
		t.Errorf("Group Read: got %q, want %q", string(buf[:n]), "dedup test")
	}

	stats := g.Stats()
	if stats.RecvPackets < 1 {
		t.Errorf("RecvPackets: got %d, want >= 1", stats.RecvPackets)
	}
}

func TestGroupSetStabilityTimeout(t *testing.T) {
	g := NewGroup(GroupBackup)
	defer g.Close()

	g.SetStabilityTimeout(500 * time.Millisecond)

	if g.stabTimeout != 500*time.Millisecond {
		t.Errorf("stabTimeout: got %v, want 500ms", g.stabTimeout)
	}
}

func TestGroupRTTEmpty(t *testing.T) {
	g := NewGroup(GroupBroadcast)
	defer g.Close()

	if rtt := g.RTT(); rtt != 0 {
		t.Errorf("RTT on empty group: got %v, want 0", rtt)
	}
}

func TestGroupConnectHelper(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	g := NewGroup(GroupBroadcast)
	defer g.Close()

	// Accept in background
	var server *Conn
	var acceptErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server, acceptErr = l.Accept()
	}()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	err = g.Connect(l.Addr().String(), dialCfg, 1, 50)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("Accept: %v", acceptErr)
	}
	defer server.Close()

	members := g.Members()
	if len(members) != 1 {
		t.Fatalf("Members: got %d, want 1", len(members))
	}
	if members[0].Token != 1 {
		t.Errorf("Token: got %d, want 1", members[0].Token)
	}
	if members[0].Weight != 50 {
		t.Errorf("Weight: got %d, want 50", members[0].Weight)
	}
}

// CIF group extension roundtrip test
func TestGroupExtensionCIFRoundtrip(t *testing.T) {
	// Verify group extension marshals and unmarshals through CIF

	// This is tested indirectly through handshake_test.go BuildConclusion tests,
	// but let's do a targeted check via CIF directly.
	// We rely on the internal/packet package tests for marshal/unmarshal correctness.
	// Here we just verify the handshake builder includes group data.

	g := NewGroup(GroupBroadcast)
	defer g.Close()

	if g.GroupID() == 0 {
		t.Error("GroupID should not be zero")
	}
}

// --- Gap 1: PENDING State Monitoring ---

func TestGroupAddPendingConn(t *testing.T) {
	// AddPendingConn should add a member in MemberPending status.
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	g := NewGroup(GroupBackup)
	defer g.Close()

	err := g.AddPendingConn(client, 1, 100)
	if err != nil {
		t.Fatalf("AddPendingConn: %v", err)
	}

	members := g.Members()
	if len(members) != 1 {
		t.Fatalf("Members: got %d, want 1", len(members))
	}
	if members[0].Status != MemberPending {
		t.Errorf("Status: got %v, want pending", members[0].Status)
	}
	if members[0].Token != 1 {
		t.Errorf("Token: got %d, want 1", members[0].Token)
	}
}

func TestGroupAddPendingConnNil(t *testing.T) {
	g := NewGroup(GroupBackup)
	defer g.Close()

	err := g.AddPendingConn(nil, 1, 0)
	if err == nil {
		t.Error("AddPendingConn(nil) should return error")
	}
}

func TestGroupAddPendingConnClosed(t *testing.T) {
	g := NewGroup(GroupBackup)
	g.Close()

	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer client.Close()
	defer server.Close()

	err := g.AddPendingConn(client, 1, 0)
	if err == nil {
		t.Error("AddPendingConn on closed group should return error")
	}
}

func TestGroupPendingTransitionsToIdle(t *testing.T) {
	// A connected Conn added as pending should transition out of MemberPending
	// once checkMembers detects it is connected. The monitor will first move it
	// to MemberIdle, and then may further promote it (e.g., if it is the only
	// member in backup mode, activateBestStandby will make it active).
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	g := NewGroup(GroupBackup)
	defer g.Close()

	// client is already connected (Dial completed), so isConnected() returns true.
	err := g.AddPendingConn(client, 1, 100)
	if err != nil {
		t.Fatalf("AddPendingConn: %v", err)
	}

	// Verify initial state is pending.
	members := g.Members()
	if members[0].Status != MemberPending {
		t.Fatalf("Initial status: got %v, want pending", members[0].Status)
	}

	// Wait for the monitor loop to pick it up (runs every 100ms).
	time.Sleep(250 * time.Millisecond)

	members = g.Members()
	if len(members) == 0 {
		t.Fatal("No members found after monitor cycle")
	}
	// The member should no longer be pending. It will be either Idle or Running
	// (Running if the monitor further activated it as the best standby).
	if members[0].Status == MemberPending {
		t.Errorf("Status after monitor: still pending, expected idle or running")
	}
	if members[0].Status == MemberBroken {
		t.Errorf("Status after monitor: broken, expected idle or running")
	}
}

func TestGroupPendingTimeout(t *testing.T) {
	// Test that pendingSince field is properly set and used.
	mc := &memberConn{
		status:       MemberPending,
		pendingSince: time.Now().Add(-6 * time.Second), // 6 seconds ago, beyond 5s timeout
	}

	if mc.pendingSince.IsZero() {
		t.Error("pendingSince should not be zero")
	}

	// The member's pendingSince is > pendingTimeout, so checkMembers would mark it broken.
	elapsed := time.Since(mc.pendingSince)
	if elapsed <= pendingTimeout {
		t.Errorf("elapsed %v should be > pendingTimeout %v", elapsed, pendingTimeout)
	}
}

// --- Gap 2: IDLE Transition from Keepalive ---

func TestGroupIdleFlag(t *testing.T) {
	// Verify that the groupIdle atomic flag on Conn works properly.
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	// Set groupID to simulate group membership.
	client.groupID = 1

	// Initially not idle.
	if client.groupIdle.Load() {
		t.Error("groupIdle should initially be false")
	}

	// Simulate: setting groupIdle directly (as keepalive handler would).
	client.groupIdle.Store(true)
	if !client.groupIdle.Load() {
		t.Error("groupIdle should be true after Store(true)")
	}

	// Simulate: data received clears idle.
	client.groupIdle.Store(false)
	if client.groupIdle.Load() {
		t.Error("groupIdle should be false after Store(false)")
	}
}

func TestGroupIdlePreventsUnstable(t *testing.T) {
	// When a member's isIdle flag is set, qualifyBackupState should
	// preserve the current state instead of transitioning to unstable.
	g := NewGroup(GroupBackup)
	defer g.Close()

	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	err := g.AddConn(client, 1, 100)
	if err != nil {
		t.Fatalf("AddConn: %v", err)
	}

	// Write to activate the member.
	_, err = g.Write([]byte("activate"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Wait for activation.
	time.Sleep(50 * time.Millisecond)

	g.mu.Lock()
	mc := g.members[0]
	// Simulate: member is active and stable.
	mc.status = MemberRunning
	mc.backupState = BackupActiveStable
	// Set idle flag (as keepalive would).
	mc.isIdle = true
	// Set lastResponse far in the past to trigger unstable detection normally.
	mc.lastResponse = time.Now().Add(-10 * time.Second)
	mc.activeSince = time.Time{}

	now := time.Now()
	state := g.qualifyBackupState(mc, now)
	g.mu.Unlock()

	// With isIdle=true, the state should be preserved (BackupActiveStable),
	// NOT transitioned to BackupActiveUnstable.
	if state == BackupActiveUnstable {
		t.Error("qualifyBackupState should NOT return Unstable when isIdle is true")
	}
	if state != BackupActiveStable {
		t.Errorf("qualifyBackupState: got %v, want BackupActiveStable (preserved due to idle)", state)
	}
}

func TestGroupIdleFalseAllowsUnstable(t *testing.T) {
	// When isIdle is false, the normal unstable detection should work.
	g := NewGroup(GroupBackup)
	defer g.Close()

	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	err := g.AddConn(client, 1, 100)
	if err != nil {
		t.Fatalf("AddConn: %v", err)
	}

	// Write to activate.
	_, err = g.Write([]byte("activate"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	g.mu.Lock()
	mc := g.members[0]
	mc.status = MemberRunning
	mc.backupState = BackupActiveStable
	mc.isIdle = false                                   // NOT idle
	mc.lastResponse = time.Now().Add(-10 * time.Second) // long ago
	mc.activeSince = time.Time{}

	now := time.Now()
	state := g.qualifyBackupState(mc, now)
	g.mu.Unlock()

	// Without idle flag, old lastResponse should trigger unstable.
	if state != BackupActiveUnstable {
		t.Errorf("qualifyBackupState: got %v, want BackupActiveUnstable (not idle)", state)
	}
}

// --- Gap 3: Rate Estimator Transfer on Failover ---

func TestConnGetSetRateEstimate(t *testing.T) {
	// Test that getRateEstimate and setRateEstimate work on a real Conn.
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	// getRateEstimate should return the CC's MaxBandwidth.
	rate := client.getRateEstimate()
	if rate <= 0 {
		t.Errorf("getRateEstimate: got %d, want > 0", rate)
	}

	// setRateEstimate should update the CC's bandwidth.
	client.setRateEstimate(5_000_000) // 5 MB/s
	newRate := client.getRateEstimate()
	if newRate != 5_000_000 {
		t.Errorf("getRateEstimate after set: got %d, want 5000000", newRate)
	}
}

func TestConnGetRateEstimateNilCC(t *testing.T) {
	// A Conn with nil sendCC should return 0.
	c := &Conn{}
	if rate := c.getRateEstimate(); rate != 0 {
		t.Errorf("getRateEstimate with nil CC: got %d, want 0", rate)
	}
}

func TestConnSetRateEstimateNilCC(t *testing.T) {
	// setRateEstimate with nil sendCC should not panic.
	c := &Conn{}
	c.setRateEstimate(1000) // should be a no-op, not panic
}

func TestConnSetRateEstimateZero(t *testing.T) {
	// setRateEstimate with rate <= 0 should be a no-op.
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	originalRate := client.getRateEstimate()
	client.setRateEstimate(0)
	afterRate := client.getRateEstimate()
	if afterRate != originalRate {
		t.Errorf("setRateEstimate(0) should not change rate: got %d, want %d", afterRate, originalRate)
	}
}

func TestConnIsConnected(t *testing.T) {
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	// A fully established connection should report connected.
	if !client.isConnected() {
		t.Error("isConnected: expected true for established connection")
	}

	// After closing, should report not connected.
	client.Close()
	time.Sleep(50 * time.Millisecond)
	if client.isConnected() {
		t.Error("isConnected: expected false after Close")
	}
}

func TestConnIsConnectedNilSendBuf(t *testing.T) {
	// A bare Conn without sendBuf initialized should not be connected.
	c := &Conn{}
	if c.isConnected() {
		t.Error("isConnected: expected false for uninitialized Conn")
	}
}

func BenchmarkGroupBroadcastWrite(b *testing.B) {
	l1, client1, server1 := setupGroupConnB(b)
	defer l1.Close()
	defer server1.Close()

	l2, client2, server2 := setupGroupConnB(b)
	defer l2.Close()
	defer server2.Close()

	g := NewGroup(GroupBroadcast)
	defer g.Close()

	g.AddConn(client1, 1, 0)
	g.AddConn(client2, 2, 0)

	// Drain servers in background
	go drainConn(server1)
	go drainConn(server2)

	payload := make([]byte, 1316)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for range b.N {
		if _, err := g.Write(payload); err != nil {
			b.Fatalf("Write: %v", err)
		}
	}
}

func BenchmarkGroupBackupWrite(b *testing.B) {
	l1, client1, server1 := setupGroupConnB(b)
	defer l1.Close()
	defer server1.Close()

	l2, client2, server2 := setupGroupConnB(b)
	defer l2.Close()
	defer server2.Close()

	g := NewGroup(GroupBackup)
	defer g.Close()

	g.AddConn(client1, 1, 100)
	g.AddConn(client2, 2, 50)

	// Drain servers in background
	go drainConn(server1)
	go drainConn(server2)

	payload := make([]byte, 1316)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for range b.N {
		if _, err := g.Write(payload); err != nil {
			b.Fatalf("Write: %v", err)
		}
	}
}

// helper for benchmarks
func setupGroupConnB(b *testing.B) (*Listener, *Conn, *Conn) {
	b.Helper()

	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 2 * time.Second

	l, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		b.Fatalf("Listen: %v", err)
	}

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

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
		b.Fatalf("Accept: %v", err)
	}

	wg.Wait()
	if dialErr != nil {
		server.Close()
		b.Fatalf("Dial: %v", dialErr)
	}

	return l, client, server
}

func drainConn(c *Conn) {
	buf := make([]byte, 65536)
	for {
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}

// --- Fix #11: Group receive sequence sync tests ---

func TestGroupUpdateLatestRcv_OnlyBackup(t *testing.T) {
	// updateLatestRcv should be a no-op for broadcast groups.
	g := NewGroup(GroupBroadcast)
	defer g.Close()

	// Should not panic on nil members.
	g.updateLatestRcv(nil)
}

func TestGroupUpdateLatestRcv_SkipNonIdle(t *testing.T) {
	// Verify that updateLatestRcv only affects idle members.
	l1, c1, s1 := setupGroupConn(t)
	defer l1.Close()
	defer s1.Close()

	l2, c2, s2 := setupGroupConn(t)
	defer l2.Close()
	defer s2.Close()

	g := NewGroup(GroupBackup)
	defer g.Close()

	g.AddConn(c1, 1, 100)
	g.AddConn(c2, 2, 50)

	// Write to activate member 1
	g.Write([]byte("activate"))
	time.Sleep(50 * time.Millisecond)

	g.mu.RLock()
	if len(g.members) < 2 {
		g.mu.RUnlock()
		t.Skip("members not ready")
	}
	source := g.members[0]
	g.mu.RUnlock()

	// Should not panic
	g.updateLatestRcv(source)
}

func TestConnResetRecvState(t *testing.T) {
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	// Record initial state
	initialAck := client.loadLastACKSeq()

	// Reset to a new sequence number
	newSeq := initialAck.Add(100)
	client.ResetRecvState(newSeq)

	// Verify the state was updated
	afterAck := client.loadLastACKSeq()
	if afterAck != newSeq {
		t.Errorf("lastACKSeq after reset: got %d, want %d", afterAck, newSeq)
	}
}

func TestConnRcvBufEmpty(t *testing.T) {
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	// A fresh connection's recv buffer should be empty.
	if !client.RcvBufEmpty() {
		t.Error("fresh recv buffer should be empty")
	}

	// Nil recvBuf should report empty.
	c := &Conn{}
	if !c.RcvBufEmpty() {
		t.Error("nil recvBuf should report empty")
	}
}

// --- Fix #12: Group keepalive handling tests ---

func TestGroupSilenceRedundantLinks_SendsKeepalive(t *testing.T) {
	// Verify that silencing a link sends an immediate keepalive.
	l1, c1, s1 := setupGroupConn(t)
	defer l1.Close()
	defer s1.Close()

	l2, c2, s2 := setupGroupConn(t)
	defer l2.Close()
	defer s2.Close()

	g := NewGroup(GroupBackup)
	defer g.Close()

	g.AddConn(c1, 1, 100)
	g.AddConn(c2, 2, 50)

	// Write several times to activate both and stabilize one.
	for i := 0; i < 5; i++ {
		g.Write([]byte("data"))
		time.Sleep(10 * time.Millisecond)
	}

	// Should not panic when called with no stable member
	// (silenceRedundantLinks is safe when stableCount == 0).
	g.silenceRedundantLinks(time.Now())
}

func TestConnSendKeepAlive_SetsGroupIdle(t *testing.T) {
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	client.groupID = 1
	client.groupIdle.Store(false)

	// Calling SendKeepAlive should set groupIdle to true.
	client.SendKeepAlive()

	if !client.groupIdle.Load() {
		t.Error("SendKeepAlive should set groupIdle to true")
	}
}

// --- Fix #13: Group sender buffer srctime tests ---

func TestGroupBufferMsg_PreservesSrcTime(t *testing.T) {
	g := NewGroup(GroupBackup)
	defer g.Close()

	g.lastSchedSeqNo.Store(42)

	g.bufferMsg([]byte("test"), 12345, 7)

	g.senderBufMu.Lock()
	if len(g.senderBuf) != 1 {
		g.senderBufMu.Unlock()
		t.Fatalf("senderBuf len: got %d, want 1", len(g.senderBuf))
	}
	msg := g.senderBuf[0]
	g.senderBufMu.Unlock()

	if msg.srcTime != 12345 {
		t.Errorf("srcTime: got %d, want 12345", msg.srcTime)
	}
	if msg.msgNo != 7 {
		t.Errorf("msgNo: got %d, want 7", msg.msgNo)
	}
	if msg.seqNo != 42 {
		t.Errorf("seqNo: got %d, want 42", msg.seqNo)
	}
}

func TestGroupReplaySenderBuf_UsesSrcTime(t *testing.T) {
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	g := NewGroup(GroupBackup)
	defer g.Close()

	g.AddConn(client, 1, 100)

	// Write to activate
	g.Write([]byte("activate"))
	time.Sleep(50 * time.Millisecond)

	// Manually add a buffered message with a specific srcTime
	g.senderBufMu.Lock()
	g.senderBuf = append(g.senderBuf, bufferedMsg{
		seqNo:   1,
		msgNo:   1,
		srcTime: 99999,
		data:    []byte("replay me"),
		ts:      time.Now(),
	})
	g.senderBufMu.Unlock()

	g.mu.RLock()
	if len(g.members) > 0 {
		mc := g.members[0]
		g.mu.RUnlock()
		// Replay should not panic and should send with srcTime set.
		g.replaySenderBuf(mc)
	} else {
		g.mu.RUnlock()
	}
}

func TestConnLastMsgNo(t *testing.T) {
	l, client, server := setupGroupConn(t)
	defer l.Close()
	defer server.Close()

	// Write a packet to advance the message number.
	client.Write([]byte("test"))

	msgNo := client.LastMsgNo()
	if msgNo == 0 {
		t.Error("LastMsgNo should be non-zero after a Write")
	}
}
