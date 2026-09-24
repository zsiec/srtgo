package session

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/packet"
)

// immediateCallerConn delivers the first data packet while the listener is
// still sending its final handshake response. Waiting for the next ReadFrom
// proves the mux has dispatched (or dropped) that packet before WriteTo returns.
type immediateCallerConn struct {
	net.PacketConn
	caller       net.PacketConn
	dispatched   chan struct{}
	sawData      bool // owned by the mux's single read goroutine
	dispatchOnce sync.Once
	injectOnce   sync.Once
}

func (c *immediateCallerConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if c.sawData {
		c.dispatchOnce.Do(func() { close(c.dispatched) })
	}
	n, addr, err := c.PacketConn.ReadFrom(b)
	if n >= packet.HeaderSize && b[0]&0x80 == 0 {
		c.sawData = true
	}
	return n, addr, err
}

func (c *immediateCallerConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p, err := packet.Parse(b, nil)
	if err != nil {
		return 0, err
	}
	defer p.Release()
	if p.Header.IsControl && p.Header.ControlType == packet.CtrlTypeHandshake {
		var hs packet.CIFHandshake
		if p.UnmarshalCIF(&hs) == nil && hs.HandshakeType == packet.HandshakeTypeConclusion {
			var injectErr error
			c.injectOnce.Do(func() {
				data := packet.NewData(nil, 100, 0, hs.SRTSocketID, []byte("first payload"))
				wire := make([]byte, 1500)
				n, e := data.Marshal(wire)
				data.Release()
				if e != nil {
					injectErr = e
					return
				}
				if _, e = c.caller.WriteTo(wire[:n], c.LocalAddr()); e != nil {
					injectErr = e
					return
				}
				select {
				case <-c.dispatched:
				case <-time.After(time.Second):
					injectErr = fmt.Errorf("mux did not consume immediate data")
				}
			})
			if injectErr != nil {
				return 0, injectErr
			}
		}
	}
	return c.PacketConn.WriteTo(b, addr)
}

func TestListenerRegistersBeforeConclusionResponse(t *testing.T) {
	for _, v4 := range []bool{false, true} {
		t.Run(fmt.Sprintf("hsv4=%v", v4), func(t *testing.T) {
			client, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				client.Close()
				t.Fatal(err)
			}
			probe := &immediateCallerConn{PacketConn: server, caller: client, dispatched: make(chan struct{})}
			ln, err := Listen(probe, core.ListenerConfig{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			caller, err := Dial(client, ln.Addr(), core.DialConfig{CallerSocketID: 7, CallerISN: 100, ForceHSv4: v4}, nil, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer caller.Close()
			accepted, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer accepted.Close()
			accepted.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			buf := make([]byte, 100)
			n, err := accepted.Read(buf)
			if err != nil || string(buf[:n]) != "first payload" {
				t.Fatalf("immediate payload=%q,%v", buf[:n], err)
			}
		})
	}
}
