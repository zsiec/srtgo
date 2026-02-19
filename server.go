package srt

import (
	"errors"
	"sync"
)

// ConnType classifies how a connection should be handled.
type ConnType int

const (
	// Reject refuses the connection.
	Reject ConnType = iota
	// Publish indicates the caller will send data (write-only).
	Publish
	// Subscribe indicates the caller will receive data (read-only).
	Subscribe
)

// ErrServerClosed is returned by Serve when the server is shut down.
var ErrServerClosed = errors.New("srt: server closed")

// ConnectFunc is called for each incoming connection during the handshake.
// It receives a ConnRequest with the stream ID and peer address, and returns
// a ConnType to route the connection to the appropriate handler.
// Return Reject to refuse the connection.
type ConnectFunc func(req ConnRequest) ConnType

// Server is a high-level SRT server framework.
//
// It wraps a Listener and provides callback-based routing:
//   - HandleConnect classifies connections as Publish or Subscribe
//   - HandlePublish is called for publishing (write) connections
//   - HandleSubscribe is called for subscribing (read) connections
//
// Each accepted connection is handled in its own goroutine. The handler
// callbacks block for the lifetime of the connection.
type Server struct {
	// Addr is the address to listen on (e.g., ":6000").
	Addr string

	// Config is the SRT configuration. If nil, DefaultConfig() is used.
	Config *Config

	// HandleConnect is called during the handshake to classify and
	// authorize the connection. If nil, all connections are rejected.
	// This is called once per connection, during the handshake phase.
	HandleConnect ConnectFunc

	// HandlePublish is called for connections classified as Publish.
	// It blocks for the lifetime of the connection. The connection is
	// closed when the handler returns.
	HandlePublish func(conn *Conn)

	// HandleSubscribe is called for connections classified as Subscribe.
	// It blocks for the lifetime of the connection. The connection is
	// closed when the handler returns.
	HandleSubscribe func(conn *Conn)

	ln       *Listener
	mu       sync.Mutex
	wg       sync.WaitGroup
	shutdown bool

	// Active connections — closed on Shutdown for clean handler exit.
	activeConns   map[*Conn]struct{}
	activeConnsMu sync.Mutex

	// pendingModes stores the ConnType determined during the handshake
	// so it can be used after Accept returns. Keyed by remote addr string.
	pendingModes sync.Map
}

// ListenAndServe listens on the configured address and serves connections.
// It blocks until Shutdown is called or an unrecoverable error occurs.
func (s *Server) ListenAndServe() error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve()
}

// Listen opens the listener socket. Call Serve to start accepting connections.
func (s *Server) Listen() error {
	cfg := s.config()

	ln, err := Listen(s.Addr, cfg)
	if err != nil {
		return err
	}

	// Wire the accept function: classify during handshake and store the result
	ln.SetAcceptFunc(func(req ConnRequest) bool {
		if s.HandleConnect == nil {
			return false
		}
		mode := s.HandleConnect(req)
		if mode == Reject {
			return false
		}
		// Store the mode so Serve can retrieve it after Accept returns
		s.pendingModes.Store(req.RemoteAddr.String(), mode)
		return true
	})

	s.mu.Lock()
	s.ln = ln
	s.shutdown = false
	s.mu.Unlock()

	return nil
}

// Serve accepts connections on the listener and dispatches them to handlers.
// It blocks until Shutdown is called. Returns ErrServerClosed on clean shutdown.
func (s *Server) Serve() error {
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()

	if ln == nil {
		return errors.New("srt: server not listening")
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.shutdown
			s.mu.Unlock()
			if closed {
				return ErrServerClosed
			}
			return err
		}

		// Retrieve the classification from the handshake phase
		key := conn.RemoteAddr().String()
		modeVal, ok := s.pendingModes.LoadAndDelete(key)
		if !ok {
			// Should not happen — AcceptFunc stored the mode
			conn.Close()
			continue
		}
		mode, ok := modeVal.(ConnType)
		if !ok {
			conn.Close()
			continue
		}

		// Check shutdown under the lock before spawning a handler goroutine.
		// This prevents wg.Add(1) racing with wg.Wait() in Shutdown().
		s.mu.Lock()
		if s.shutdown {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.wg.Add(1)
		s.mu.Unlock()

		// Track the connection for graceful shutdown
		s.trackConn(conn)

		// Dispatch to the appropriate handler in a new goroutine
		go func(c *Conn, m ConnType) {
			defer s.wg.Done()
			defer s.untrackConn(c)
			defer c.Close()
			defer s.recoverHandler()

			switch m {
			case Publish:
				if s.HandlePublish != nil {
					s.HandlePublish(c)
				}
			case Subscribe:
				if s.HandleSubscribe != nil {
					s.HandleSubscribe(c)
				}
			}
		}(conn, mode)
	}
}

// Shutdown gracefully stops the server. It stops accepting new connections,
// closes all active connections, and waits for handler goroutines to finish.
func (s *Server) Shutdown() {
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		return
	}
	s.shutdown = true
	ln := s.ln
	s.mu.Unlock()

	if ln != nil {
		ln.Close()
	}

	// Close all active connections so handlers unblock
	s.activeConnsMu.Lock()
	for c := range s.activeConns {
		c.Close()
	}
	s.activeConnsMu.Unlock()

	// Wait for all handler goroutines to finish.
	// Safe because s.shutdown=true prevents new wg.Add(1) calls.
	s.wg.Wait()
}

func (s *Server) trackConn(c *Conn) {
	s.activeConnsMu.Lock()
	if s.activeConns == nil {
		s.activeConns = make(map[*Conn]struct{})
	}
	s.activeConns[c] = struct{}{}
	s.activeConnsMu.Unlock()
}

func (s *Server) untrackConn(c *Conn) {
	s.activeConnsMu.Lock()
	delete(s.activeConns, c)
	s.activeConnsMu.Unlock()
}

// recoverHandler catches panics from user-supplied handler callbacks,
// preventing a single misbehaving handler from crashing the process.
func (s *Server) recoverHandler() {
	if r := recover(); r != nil {
		// Silently recover — the deferred c.Close() and untrackConn
		// will still run because this defer was registered first.
		// Users who need panic visibility should recover inside their handlers.
	}
}

func (s *Server) config() Config {
	if s.Config != nil {
		return *s.Config
	}
	return DefaultConfig()
}
