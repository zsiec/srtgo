// Command receiver listens for an SRT connection and writes received
// data to stdout.
//
// Usage:
//
//	go run ./examples/receiver -addr :4200 > output.ts
//	go run ./examples/receiver -addr :4200 -streamid live/test
package main

import (
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	srt "github.com/zsiec/srtgo"
)

func main() {
	addr := flag.String("addr", ":4200", "listen address")
	streamID := flag.String("streamid", "", "filter by stream ID (empty = accept all)")
	flag.Parse()

	cfg := srt.DefaultConfig()
	ln, err := srt.Listen(*addr, cfg)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	log.Printf("listening on %s", ln.Addr())

	if *streamID != "" {
		filter := *streamID
		ln.SetAcceptFunc(func(req srt.ConnRequest) bool {
			return req.StreamID == filter
		})
		log.Printf("filtering for streamID=%q", filter)
	}

	// Handle SIGINT for clean shutdown.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	connCh := make(chan *srt.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		connCh <- c
	}()

	var conn *srt.Conn
	select {
	case conn = <-connCh:
	case <-sig:
		log.Println("shutting down...")
		return
	}
	defer conn.Close()

	log.Printf("accepted connection from %s (streamID=%q)", conn.RemoteAddr(), conn.StreamID())

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1456)
		total := int64(0)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if _, werr := io.Copy(os.Stdout, io.LimitReader(
					readerFrom(buf[:n]), int64(n),
				)); werr != nil {
					log.Printf("write stdout: %v", werr)
					return
				}
				total += int64(n)
			}
			if err != nil {
				log.Printf("read: %v (total: %d bytes)", err, total)
				return
			}
		}
	}()

	select {
	case <-sig:
		log.Println("shutting down...")
	case <-done:
	}
}

// readerFrom wraps a byte slice as an io.Reader.
type byteReader struct {
	data []byte
	pos  int
}

func readerFrom(b []byte) io.Reader {
	return &byteReader{data: b}
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
