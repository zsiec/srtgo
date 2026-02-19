// Package mux provides a UDP multiplexer that allows multiple SRT connections
// to share a single UDP socket. This follows the quic-go Transport pattern:
// one read goroutine dispatches incoming packets to registered connections
// by DestinationSocketID.
//
// For the listener, packets with DestinationSocketID == 0 (handshake) are
// routed to a separate handshake channel.
package mux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/zsiec/srtgo/internal/packet"
)

// DefaultMSS is the default Maximum Segment Size (MTU - IP - UDP headers).
const DefaultMSS = 1500

// ErrClosed is returned when the Mux has been closed.
var ErrClosed = errors.New("mux: closed")

// connEntry holds a channel for dispatching packets to a registered connection.
type connEntry struct {
	ch chan packet.Packet
}

// Mux multiplexes multiple SRT connections over a single UDP socket.
type Mux struct {
	conn net.PacketConn
	mss  int

	// Connection registry: SocketID -> channel.
	// Using sync.Map for concurrent reads (packet dispatch) with rare writes (connect/disconnect).
	conns sync.Map

	// Handshake channel: packets with DestinationSocketID == 0
	// are routed here for the listener to process.
	Handshake chan packet.Packet

	// Write serialization: all sends go through the shared socket.
	writeMu  sync.Mutex
	sendPool sync.Pool // pool of []byte buffers for Send

	ctx    context.Context
	cancel context.CancelFunc

	// done signals when the read loop has exited.
	done chan struct{}
}

// New creates a Mux on the given PacketConn with the specified MSS.
func New(conn net.PacketConn, mss int) *Mux {
	if mss <= 0 {
		mss = DefaultMSS
	}

	ctx, cancel := context.WithCancel(context.Background())
	sendBufSize := mss + packet.HeaderSize
	m := &Mux{
		conn:      conn,
		mss:       mss,
		Handshake: make(chan packet.Packet, 128),
		sendPool: sync.Pool{
			New: func() any { return make([]byte, sendBufSize) },
		},
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	go m.readLoop()

	return m
}

// Register adds a connection to the mux. Packets with the given socketID
// as DestinationSocketID will be dispatched to the returned channel.
func (m *Mux) Register(socketID uint32) <-chan packet.Packet {
	ch := make(chan packet.Packet, 256)
	m.conns.Store(socketID, &connEntry{ch: ch})
	return ch
}

// Unregister removes a connection from the mux.
func (m *Mux) Unregister(socketID uint32) {
	m.conns.Delete(socketID)
}

// Send writes a packet to the wire. It is safe to call from multiple goroutines.
func (m *Mux) Send(p packet.Packet) error {
	if p.Header.Addr == nil {
		return fmt.Errorf("mux: packet has no destination address")
	}

	buf := m.sendPool.Get().([]byte)
	needed := packet.HeaderSize + len(p.Data)
	if len(buf) < needed {
		buf = make([]byte, needed)
	}

	n, err := p.Marshal(buf)
	if err != nil {
		m.sendPool.Put(buf)
		return fmt.Errorf("mux: marshal: %w", err)
	}

	m.writeMu.Lock()
	_, err = m.conn.WriteTo(buf[:n], p.Header.Addr)
	m.writeMu.Unlock()

	m.sendPool.Put(buf)
	return err
}

// Close shuts down the mux, stopping the read loop and closing the socket.
func (m *Mux) Close() error {
	m.cancel()
	err := m.conn.Close()
	<-m.done // wait for read loop to exit
	return err
}

// LocalAddr returns the local address of the underlying socket.
func (m *Mux) LocalAddr() net.Addr {
	return m.conn.LocalAddr()
}

// readLoop is the single goroutine that reads from the UDP socket and
// dispatches packets to registered connections.
func (m *Mux) readLoop() {
	defer close(m.done)

	buf := make([]byte, m.mss)

	for {
		// Check for shutdown
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		// Set a read deadline so we can periodically check for shutdown
		m.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, addr, err := m.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			// Check if we're shutting down
			select {
			case <-m.ctx.Done():
				return
			default:
			}
			// Unexpected error; log and continue.
			continue
		}

		p, err := packet.Parse(buf[:n], addr)
		if err != nil {
			continue
		}

		destID := p.Header.DestinationSocketID

		if destID == 0 {
			// Handshake packet — send to listener
			select {
			case m.Handshake <- p:
			default:
				p.Release()
			}
			continue
		}

		// Dispatch to registered connection
		if entry, ok := m.conns.Load(destID); ok {
			ce := entry.(*connEntry)
			select {
			case ce.ch <- p:
			default:
				// Connection queue full — drop packet
				p.Release()
			}
		} else {
			// No registered connection — drop
			p.Release()
		}
	}
}
