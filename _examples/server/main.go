// Command server demonstrates the srt.Server framework with
// callback-based connection routing.
//
// Usage:
//
//	go run ./examples/server -addr :4200
//
// Connect a publisher:
//
//	srt-live-transmit udp://localhost:1234 srt://localhost:4200?streamid=#!::m=publish,r=live/test
//
// Connect a subscriber:
//
//	srt-live-transmit srt://localhost:4200?streamid=#!::r=live/test udp://localhost:5678
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	srt "github.com/zsiec/srtgo"
)

func main() {
	addr := flag.String("addr", ":4200", "listen address")
	flag.Parse()

	cfg := srt.DefaultConfig()
	cfg.Latency = 120 * time.Millisecond

	srv := &srt.Server{
		Addr:   *addr,
		Config: &cfg,
		HandleConnect: func(req srt.ConnRequest) srt.ConnType {
			log.Printf("connection from %s (streamID=%q)", req.RemoteAddr, req.StreamID)
			sid := req.StreamID
			if strings.Contains(sid, "m=publish") {
				return srt.Publish
			}
			if strings.HasPrefix(sid, "#!::r=") || strings.Contains(sid, "m=request") {
				return srt.Subscribe
			}
			// Accept unknown stream IDs as publishers by default.
			if sid != "" {
				return srt.Publish
			}
			log.Printf("rejecting connection with empty stream ID from %s", req.RemoteAddr)
			return srt.Reject
		},
		HandlePublish: func(conn *srt.Conn) {
			log.Printf("publisher started: %s (streamID=%q)", conn.RemoteAddr(), conn.StreamID())
			buf := make([]byte, 1456)
			var total uint64
			for {
				n, err := conn.Read(buf)
				if err != nil {
					log.Printf("publisher done: %s (%d bytes received, err=%v)",
						conn.RemoteAddr(), total, err)
					return
				}
				total += uint64(n)
				if total%(1024*1024) < uint64(n) {
					log.Printf("publisher %s: received %d MB", conn.StreamID(), total/(1024*1024))
				}
			}
		},
		HandleSubscribe: func(conn *srt.Conn) {
			log.Printf("subscriber started: %s (streamID=%q)", conn.RemoteAddr(), conn.StreamID())
			// Generate test data for the subscriber.
			payload := make([]byte, 1316)
			for i := range payload {
				payload[i] = byte(i % 256)
			}
			var total uint64
			for {
				_, err := conn.Write(payload)
				if err != nil {
					log.Printf("subscriber done: %s (%d bytes sent, err=%v)",
						conn.RemoteAddr(), total, err)
					return
				}
				total += uint64(len(payload))
				time.Sleep(time.Millisecond)
			}
		},
	}

	// Handle SIGINT for graceful shutdown.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		log.Println("shutting down...")
		srv.Shutdown()
	}()

	log.Printf("SRT server listening on %s", *addr)
	if err := srv.ListenAndServe(); err != nil && err != srt.ErrServerClosed {
		log.Fatal(err)
	}
	log.Println("server stopped")
}
