package srt_test

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	srt "github.com/zsiec/srtgo"
)

// TestFacadeGroupBroadcast exercises the public Group API end to end: a caller
// group of two links broadcasts, and a listener group deduplicates the merged
// stream, delivering each payload once in order.
func TestFacadeGroupBroadcast(t *testing.T) {
	cfg := srt.DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 3 * time.Second

	ln, err := srt.Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// Listener-side group: accept two links and bond them.
	lg := srt.NewGroup(srt.GroupBroadcast)
	defer lg.Close()
	accErr := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				accErr <- err
				return
			}
			if err := lg.AddConn(c, i, 100); err != nil {
				accErr <- err
				return
			}
		}
		accErr <- nil
	}()

	// Caller-side group: dial two links into the group.
	cg := srt.NewGroup(srt.GroupBroadcast)
	defer cg.Close()
	for i := 0; i < 2; i++ {
		if err := cg.Connect(ln.Addr().String(), cfg, i, 100); err != nil {
			t.Fatalf("Connect %d: %v", i, err)
		}
	}
	if err := <-accErr; err != nil {
		t.Fatalf("listener accept/bond: %v", err)
	}

	if len(cg.Members()) != 2 {
		t.Fatalf("caller group Members = %d, want 2", len(cg.Members()))
	}

	const n = 100
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			p := make([]byte, 300)
			binary.BigEndian.PutUint32(p, uint32(i))
			if _, err := cg.Write(p); err != nil {
				t.Errorf("group Write %d: %v", i, err)
				return
			}
		}
	}()

	buf := make([]byte, 1000)
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; i < n; i++ {
		if time.Now().After(deadline) {
			t.Fatalf("timeout after %d/%d payloads", i, n)
		}
		m, err := lg.Read(buf)
		if err != nil {
			t.Fatalf("group Read %d: %v", i, err)
		}
		if got := binary.BigEndian.Uint32(buf[:m]); got != uint32(i) {
			t.Fatalf("payload %d = %d, want %d (dedup/order)", i, got, i)
		}
	}
	wg.Wait()

	gs := lg.Stats()
	t.Logf("group stats: members=%d active=%d recv=%d dedups=%d", gs.Members, gs.ActiveMembers, gs.RecvPackets, gs.RecvDedups)
	if gs.RecvDedups == 0 {
		t.Error("expected some deduplicated duplicates across the two broadcast links")
	}
}

// TestFacadeGroupBalancing exercises a balancing-mode group: the caller
// distributes messages round-robin across two links, each link carries an
// independent contiguous stream, and the listener group reorders by group
// message number to deliver everything once, in order.
func TestFacadeGroupBalancing(t *testing.T) {
	cfg := srt.DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 3 * time.Second

	ln, err := srt.Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	lg := srt.NewGroup(srt.GroupBalancing)
	defer lg.Close()
	accErr := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				accErr <- err
				return
			}
			if err := lg.AddConn(c, i, 100); err != nil {
				accErr <- err
				return
			}
		}
		accErr <- nil
	}()

	cg := srt.NewGroup(srt.GroupBalancing)
	defer cg.Close()
	for i := 0; i < 2; i++ {
		if err := cg.Connect(ln.Addr().String(), cfg, i, 100); err != nil {
			t.Fatalf("Connect %d: %v", i, err)
		}
	}
	if err := <-accErr; err != nil {
		t.Fatalf("listener accept/bond: %v", err)
	}

	const n = 100
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			p := make([]byte, 300)
			binary.BigEndian.PutUint32(p, uint32(i))
			if _, err := cg.Write(p); err != nil {
				t.Errorf("balancing group Write %d: %v", i, err)
				return
			}
		}
	}()

	buf := make([]byte, 1000)
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; i < n; i++ {
		if time.Now().After(deadline) {
			t.Fatalf("balancing timeout after %d/%d payloads", i, n)
		}
		m, err := lg.Read(buf)
		if err != nil {
			t.Fatalf("balancing group Read %d: %v", i, err)
		}
		if got := binary.BigEndian.Uint32(buf[:m]); got != uint32(i) {
			t.Fatalf("balancing payload %d = %d, want %d (reorder)", i, got, i)
		}
	}
	wg.Wait()

	// Balancing sends each message on exactly one link, so the receiver sees no
	// cross-link duplicates (unlike broadcast).
	gs := lg.Stats()
	t.Logf("balancing stats: members=%d recv=%d dedups=%d", gs.Members, gs.RecvPackets, gs.RecvDedups)
	if gs.RecvDedups != 0 {
		t.Errorf("balancing should not deduplicate (each message on one link), got %d dedups", gs.RecvDedups)
	}
}

// TestFacadeGroupBackup exercises a backup-mode group: the active (higher-weight)
// link carries the stream and the listener group delivers the merged stream.
func TestFacadeGroupBackup(t *testing.T) {
	cfg := srt.DefaultConfig()
	cfg.Latency = 20 * time.Millisecond
	cfg.ConnTimeout = 3 * time.Second

	ln, err := srt.Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	lg := srt.NewGroup(srt.GroupBackup)
	defer lg.Close()
	accErr := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				accErr <- err
				return
			}
			if err := lg.AddConn(c, i, uint16(100-i*40)); err != nil {
				accErr <- err
				return
			}
		}
		accErr <- nil
	}()

	cg := srt.NewGroup(srt.GroupBackup)
	defer cg.Close()
	for i := 0; i < 2; i++ {
		if err := cg.Connect(ln.Addr().String(), cfg, i, uint16(100-i*40)); err != nil {
			t.Fatalf("Connect %d: %v", i, err)
		}
	}
	if err := <-accErr; err != nil {
		t.Fatalf("listener accept/bond: %v", err)
	}

	const n = 80
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			p := make([]byte, 300)
			binary.BigEndian.PutUint32(p, uint32(i))
			if _, err := cg.Write(p); err != nil {
				t.Errorf("backup group Write %d: %v", i, err)
				return
			}
		}
	}()

	buf := make([]byte, 1000)
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; i < n; i++ {
		if time.Now().After(deadline) {
			t.Fatalf("backup timeout after %d/%d payloads", i, n)
		}
		m, err := lg.Read(buf)
		if err != nil {
			t.Fatalf("backup group Read %d: %v", i, err)
		}
		if got := binary.BigEndian.Uint32(buf[:m]); got != uint32(i) {
			t.Fatalf("backup payload %d = %d, want %d", i, got, i)
		}
	}
	wg.Wait()
}
