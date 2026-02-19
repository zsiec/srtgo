package srt

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestServerListenAndServe(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	var publishCalled atomic.Bool

	s := &Server{
		Addr:   "127.0.0.1:0",
		Config: &cfg,
		HandleConnect: func(req ConnRequest) ConnType {
			return Publish
		},
		HandlePublish: func(conn *Conn) {
			publishCalled.Store(true)
			// Block until connection closes
			buf := make([]byte, 1500)
			conn.Read(buf)
		},
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	// Get the actual address
	addr := s.ln.Addr().String()

	// Start serving in background
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- s.Serve()
	}()

	// Connect a client
	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.StreamID = "live/test"
	dialCfg.ConnTimeout = 2 * time.Second

	client, err := Dial(addr, dialCfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Give time for the handler to be called
	time.Sleep(50 * time.Millisecond)

	if !publishCalled.Load() {
		t.Error("HandlePublish should have been called")
	}

	client.Close()
	s.Shutdown()

	select {
	case err := <-serveErr:
		if err != ErrServerClosed {
			t.Errorf("Serve: got %v, want ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Serve did not return after Shutdown")
	}
}

func TestServerSubscribe(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	var subscribeCalled atomic.Bool

	s := &Server{
		Addr:   "127.0.0.1:0",
		Config: &cfg,
		HandleConnect: func(req ConnRequest) ConnType {
			return Subscribe
		},
		HandleSubscribe: func(conn *Conn) {
			subscribeCalled.Store(true)
			buf := make([]byte, 1500)
			conn.Read(buf)
		},
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	addr := s.ln.Addr().String()

	go s.Serve()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	client, err := Dial(addr, dialCfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	if !subscribeCalled.Load() {
		t.Error("HandleSubscribe should have been called")
	}

	client.Close()
	s.Shutdown()
}

func TestServerReject(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	s := &Server{
		Addr:   "127.0.0.1:0",
		Config: &cfg,
		HandleConnect: func(req ConnRequest) ConnType {
			return Reject
		},
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	addr := s.ln.Addr().String()
	go s.Serve()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 1 * time.Second

	_, err := Dial(addr, dialCfg)
	if err == nil {
		t.Error("Dial should fail when server rejects")
	}

	s.Shutdown()
}

func TestServerStreamIDRouting(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	var publishCount, subscribeCount atomic.Int32

	s := &Server{
		Addr:   "127.0.0.1:0",
		Config: &cfg,
		HandleConnect: func(req ConnRequest) ConnType {
			if req.StreamID == "publish/test" {
				return Publish
			}
			if req.StreamID == "subscribe/test" {
				return Subscribe
			}
			return Reject
		},
		HandlePublish: func(conn *Conn) {
			publishCount.Add(1)
			buf := make([]byte, 1500)
			conn.Read(buf)
		},
		HandleSubscribe: func(conn *Conn) {
			subscribeCount.Add(1)
			buf := make([]byte, 1500)
			conn.Read(buf)
		},
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	addr := s.ln.Addr().String()
	go s.Serve()

	// Connect as publisher
	pubCfg := DefaultConfig()
	pubCfg.Latency = 20 * time.Millisecond
	pubCfg.StreamID = "publish/test"
	pubCfg.ConnTimeout = 2 * time.Second

	pubClient, err := Dial(addr, pubCfg)
	if err != nil {
		t.Fatalf("Dial publish: %v", err)
	}

	// Connect as subscriber
	subCfg := DefaultConfig()
	subCfg.Latency = 20 * time.Millisecond
	subCfg.StreamID = "subscribe/test"
	subCfg.ConnTimeout = 2 * time.Second

	subClient, err := Dial(addr, subCfg)
	if err != nil {
		t.Fatalf("Dial subscribe: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	if publishCount.Load() != 1 {
		t.Errorf("publishCount: got %d, want 1", publishCount.Load())
	}
	if subscribeCount.Load() != 1 {
		t.Errorf("subscribeCount: got %d, want 1", subscribeCount.Load())
	}

	pubClient.Close()
	subClient.Close()
	s.Shutdown()
}

func TestServerNoHandleConnect(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	s := &Server{
		Addr:   "127.0.0.1:0",
		Config: &cfg,
		// No HandleConnect — should reject all
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	addr := s.ln.Addr().String()
	go s.Serve()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 1 * time.Second

	_, err := Dial(addr, dialCfg)
	if err == nil {
		t.Error("Dial should fail when no HandleConnect is set")
	}

	s.Shutdown()
}

func TestServerShutdownWaitsForHandlers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Latency = 20 * time.Millisecond

	handlerDone := make(chan struct{})

	s := &Server{
		Addr:   "127.0.0.1:0",
		Config: &cfg,
		HandleConnect: func(req ConnRequest) ConnType {
			return Publish
		},
		HandlePublish: func(conn *Conn) {
			defer close(handlerDone)
			// Simulate work
			time.Sleep(100 * time.Millisecond)
		},
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	addr := s.ln.Addr().String()
	go s.Serve()

	dialCfg := DefaultConfig()
	dialCfg.Latency = 20 * time.Millisecond
	dialCfg.ConnTimeout = 2 * time.Second

	client, err := Dial(addr, dialCfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	// Give handler time to start
	time.Sleep(20 * time.Millisecond)

	// Shutdown should wait for the handler to complete
	var shutdownDone sync.WaitGroup
	shutdownDone.Add(1)
	go func() {
		defer shutdownDone.Done()
		s.Shutdown()
	}()

	// Handler should finish within 200ms
	select {
	case <-handlerDone:
		// expected
	case <-time.After(1 * time.Second):
		t.Error("handler did not complete in time")
	}

	shutdownDone.Wait()
}

func TestServerDefaultConfig(t *testing.T) {
	s := &Server{
		Addr: "127.0.0.1:0",
		// No Config — should use default
		HandleConnect: func(req ConnRequest) ConnType {
			return Publish
		},
		HandlePublish: func(conn *Conn) {
			buf := make([]byte, 1500)
			conn.Read(buf)
		},
	}

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	s.Shutdown()
}

func TestServerServeWithoutListen(t *testing.T) {
	s := &Server{}
	err := s.Serve()
	if err == nil {
		t.Error("Serve without Listen should fail")
	}
}

func TestConnTypeConstants(t *testing.T) {
	if Reject == Publish || Reject == Subscribe || Publish == Subscribe {
		t.Error("ConnType constants must be distinct")
	}
}
