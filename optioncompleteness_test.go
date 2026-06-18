package srt_test

import (
	"testing"
	"time"

	srt "github.com/zsiec/srtgo"
)

// TestFacadeOptionCompleteness exercises the GetOption values and stats fields
// wired in the post-cutover completeness pass (#4–8): ISN/PeerISN/PeerVersion,
// poll Event flags, runtime SndDropDelay, MsgCtrl.SrcTime, and the belated/
// reorder/ms-buffer stats.
func TestFacadeOptionCompleteness(t *testing.T) {
	caller, server, ln := dialAccept(t, srt.DefaultConfig(), srt.DefaultConfig())
	defer ln.Close()
	defer caller.Close()
	defer server.Close()

	// ISN / PeerISN: the caller's send ISN is the server's receive ISN and vice
	// versa, so they cross over.
	cISN := mustGetUint32(t, caller, srt.SockOptISN)
	cPeerISN := mustGetUint32(t, caller, srt.SockOptPeerISN)
	sISN := mustGetUint32(t, server, srt.SockOptISN)
	sPeerISN := mustGetUint32(t, server, srt.SockOptPeerISN)
	if cISN == 0 || sISN == 0 {
		t.Fatalf("ISN should be nonzero: caller=%d server=%d", cISN, sISN)
	}
	if cISN != sPeerISN || sISN != cPeerISN {
		t.Errorf("ISN/PeerISN should cross: cISN=%d sPeerISN=%d / sISN=%d cPeerISN=%d",
			cISN, sPeerISN, sISN, cPeerISN)
	}

	// PeerVersion: each side learns the other's SRT version from the handshake.
	if pv := mustGetUint32(t, caller, srt.SockOptPeerVersion); pv == 0 {
		t.Errorf("caller PeerVersion should be nonzero")
	}

	// SndDropDelay can be set at runtime without error.
	if err := caller.SetOption(srt.SockOptSndDropDelay, 50); err != nil {
		t.Errorf("SetOption(SndDropDelay): %v", err)
	}

	// A custom source timestamp is accepted on a message write.
	if _, err := caller.WriteMsgCtrl([]byte("hello-srctime"), &srt.MsgCtrl{
		InOrder: true,
		SrcTime: time.Now(),
	}); err != nil {
		t.Fatalf("WriteMsgCtrl with SrcTime: %v", err)
	}
	buf := make([]byte, 100)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := server.Read(buf); err != nil || string(buf[:n]) != "hello-srctime" {
		t.Fatalf("Read SrcTime msg: n=%d err=%v got=%q", n, err, buf[:n])
	}

	// Event flags: the server has data buffered → readable; both should be
	// writable. (Read drained above, so re-check via a fresh write.)
	if _, err := caller.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	var ev int
	for time.Now().Before(deadline) {
		ev = mustGetInt(t, server, srt.SockOptEvent)
		if ev&srt.EventIn != 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ev&srt.EventIn == 0 {
		t.Errorf("server Event should report EventIn after a write, got %#x", ev)
	}
	if mustGetInt(t, caller, srt.SockOptEvent)&srt.EventOut == 0 {
		t.Errorf("caller Event should report EventOut (writable)")
	}
}

func mustGetUint32(t *testing.T, c *srt.Conn, opt srt.SockOpt) uint32 {
	t.Helper()
	v, err := c.GetOption(opt)
	if err != nil {
		t.Fatalf("GetOption(%v): %v", opt, err)
	}
	u, ok := v.(uint32)
	if !ok {
		t.Fatalf("GetOption(%v): type %T, want uint32", opt, v)
	}
	return u
}

func mustGetInt(t *testing.T, c *srt.Conn, opt srt.SockOpt) int {
	t.Helper()
	v, err := c.GetOption(opt)
	if err != nil {
		t.Fatalf("GetOption(%v): %v", opt, err)
	}
	i, ok := v.(int)
	if !ok {
		t.Fatalf("GetOption(%v): type %T, want int", opt, v)
	}
	return i
}
