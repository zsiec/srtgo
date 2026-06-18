package srt_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	srt "github.com/zsiec/srtgo"
)

// newUDP binds an ephemeral 127.0.0.1 UDP socket for tests.
func newUDP(t *testing.T) (net.PacketConn, error) {
	t.Helper()
	return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

// TestFacadeLoopback exercises the new public-API façade end to end over real
// UDP: Listen + Dial + Accept, bidirectional Write/Read, Stats, and Close.
func TestFacadeLoopback(t *testing.T) {
	cfg := srt.DefaultConfig()
	ln, err := srt.Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		c   *srt.Conn
		err error
	}
	accCh := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		accCh <- accepted{c, err}
	}()

	caller, err := srt.Dial(ln.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer caller.Close()

	var srv *srt.Conn
	select {
	case a := <-accCh:
		if a.err != nil {
			t.Fatalf("Accept: %v", a.err)
		}
		srv = a.c
	case <-time.After(3 * time.Second):
		t.Fatal("Accept timed out")
	}
	defer srv.Close()

	const n = 100
	payload := func(i int) []byte { return []byte(fmt.Sprintf("payload-%04d", i)) }

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			if _, err := caller.Write(payload(i)); err != nil {
				t.Errorf("Write %d: %v", i, err)
				return
			}
		}
	}()

	buf := make([]byte, 2000)
	for i := 0; i < n; i++ {
		_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))
		m, err := srv.Read(buf)
		if err != nil {
			t.Fatalf("Read %d: %v", i, err)
		}
		if !bytes.Equal(buf[:m], payload(i)) {
			t.Fatalf("payload %d mismatch: got %q want %q", i, buf[:m], payload(i))
		}
	}
	wg.Wait()

	// Reverse direction works too.
	if _, err := srv.Write([]byte("pong")); err != nil {
		t.Fatalf("server Write: %v", err)
	}
	_ = caller.SetReadDeadline(time.Now().Add(3 * time.Second))
	m, err := caller.Read(buf)
	if err != nil || string(buf[:m]) != "pong" {
		t.Fatalf("caller Read reverse: m=%d err=%v got=%q", m, err, buf[:m])
	}

	// Stats are wired through the façade.
	st := caller.Stats(false)
	if st.SentPackets == 0 {
		t.Errorf("caller Stats.SentPackets = 0, want > 0")
	}
	if st.RTT <= 0 {
		t.Errorf("caller Stats.RTT = %v, want > 0", st.RTT)
	}
}

// TestFacadeReadDeadline proves the net.Conn read deadline surfaces a timeout.
func TestFacadeReadDeadline(t *testing.T) {
	cfg := srt.DefaultConfig()
	ln, err := srt.Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accCh := make(chan *srt.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accCh <- c
		}
	}()

	caller, err := srt.Dial(ln.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer caller.Close()

	var srv *srt.Conn
	select {
	case srv = <-accCh:
		defer srv.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("Accept timed out")
	}

	_ = srv.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 100)
	_, err = srv.Read(buf)
	if !isTimeout(err) {
		t.Fatalf("Read after idle deadline: err = %v, want timeout", err)
	}
}

func isTimeout(err error) bool {
	var ne interface{ Timeout() bool }
	return errors.As(err, &ne) && ne.Timeout()
}

// dialAccept is a small helper: spin up a listener and a connected caller/server
// pair with the given configs.
func dialAccept(t *testing.T, lcfg, dcfg srt.Config) (caller, server *srt.Conn, ln *srt.Listener) {
	t.Helper()
	ln, err := srt.Listen("127.0.0.1:0", lcfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	accCh := make(chan *srt.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accCh <- c
		}
	}()
	caller, err = srt.Dial(ln.Addr().String(), dcfg)
	if err != nil {
		ln.Close()
		t.Fatalf("Dial: %v", err)
	}
	select {
	case server = <-accCh:
	case <-time.After(3 * time.Second):
		caller.Close()
		ln.Close()
		t.Fatal("Accept timed out")
	}
	return caller, server, ln
}

// TestFacadeStreamID proves the stream ID set by the caller is negotiated in the
// handshake and surfaced on both ends.
func TestFacadeStreamID(t *testing.T) {
	lcfg := srt.DefaultConfig()
	dcfg := srt.DefaultConfig()
	dcfg.StreamID = "live/stream-42"

	caller, server, ln := dialAccept(t, lcfg, dcfg)
	defer ln.Close()
	defer caller.Close()
	defer server.Close()

	if got := caller.StreamID(); got != "live/stream-42" {
		t.Errorf("caller.StreamID() = %q, want %q", got, "live/stream-42")
	}
	if got := server.StreamID(); got != "live/stream-42" {
		t.Errorf("accepted.StreamID() = %q, want %q", got, "live/stream-42")
	}
	if server.SocketID() == 0 {
		t.Error("accepted.SocketID() = 0, want nonzero")
	}
}

// TestFacadeRendezvous proves a peer-to-peer simultaneous-open connection works
// through the façade.
func TestFacadeRendezvous(t *testing.T) {
	cfg := srt.DefaultConfig()
	cfg.ConnTimeout = 5 * time.Second

	// Two ephemeral local sockets; each dials the other.
	addrA := freeUDPAddr(t)
	addrB := freeUDPAddr(t)

	type res struct {
		c   *srt.Conn
		err error
	}
	ch := make(chan res, 2)
	go func() { c, err := srt.DialRendezvous(addrA, addrB, cfg); ch <- res{c, err} }()
	go func() { c, err := srt.DialRendezvous(addrB, addrA, cfg); ch <- res{c, err} }()

	var conns []*srt.Conn
	for i := 0; i < 2; i++ {
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("rendezvous dial: %v", r.err)
			}
			conns = append(conns, r.c)
		case <-time.After(8 * time.Second):
			t.Fatal("rendezvous timed out")
		}
	}
	defer conns[0].Close()
	defer conns[1].Close()

	if _, err := conns[0].Write([]byte("rdv-hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = conns[1].SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 100)
	n, err := conns[1].Read(buf)
	if err != nil || string(buf[:n]) != "rdv-hello" {
		t.Fatalf("rendezvous Read: m=%d err=%v got=%q", n, err, buf[:n])
	}
}

// freeUDPAddr returns a free 127.0.0.1:port string by briefly binding a socket.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := newUDP(t)
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().String()
	c.Close()
	return addr
}

// TestFacadeParseStreamID proves the public stream-ID parser is wired.
func TestFacadeParseStreamID(t *testing.T) {
	info, ok := srt.ParseStreamID("#!::u=alice,r=live/stream")
	if !ok {
		t.Fatal("ParseStreamID returned ok=false")
	}
	if info.UserName != "alice" {
		t.Errorf("UserName = %q, want alice", info.UserName)
	}
	if info.ResourceName != "live/stream" {
		t.Errorf("ResourceName = %q, want live/stream", info.ResourceName)
	}
}

// TestFacadeMessageAPI proves WriteMessage/ReadMsgCtrl carry message boundaries
// and metadata through the façade.
func TestFacadeMessageAPI(t *testing.T) {
	cfg := srt.DefaultConfig() // live mode: message API on by default

	caller, server, ln := dialAccept(t, cfg, cfg)
	defer ln.Close()
	defer caller.Close()
	defer server.Close()

	const n = 50
	go func() {
		for i := 0; i < n; i++ {
			if _, err := caller.WriteMessage([]byte(fmt.Sprintf("msg-%03d", i))); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 2000)
	var lastMsgNo uint32
	for i := 0; i < n; i++ {
		_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
		var mc srt.MsgCtrl
		m, err := server.ReadMsgCtrl(buf, &mc)
		if err != nil {
			t.Fatalf("ReadMsgCtrl %d: %v", i, err)
		}
		if want := fmt.Sprintf("msg-%03d", i); string(buf[:m]) != want {
			t.Fatalf("message %d = %q, want %q", i, buf[:m], want)
		}
		if i > 0 && mc.MsgNo == lastMsgNo {
			t.Errorf("message %d: MsgNo did not advance (%d)", i, mc.MsgNo)
		}
		lastMsgNo = mc.MsgNo
	}
}
