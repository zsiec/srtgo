// Command sender connects to an SRT receiver and sends data from stdin
// or a generated test pattern.
//
// Usage:
//
//	echo "hello" | go run ./examples/sender -addr 127.0.0.1:4200
//	go run ./examples/sender -addr 127.0.0.1:4200 -streamid live/test
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	srt "github.com/zsiec/srtgo"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4200", "SRT receiver address")
	streamID := flag.String("streamid", "", "SRT stream ID")
	latency := flag.Duration("latency", 120*time.Millisecond, "TSBPD latency")
	flag.Parse()

	cfg := srt.DefaultConfig()
	cfg.StreamID = *streamID
	cfg.Latency = *latency

	conn, err := srt.Dial(*addr, cfg)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	log.Printf("connected to %s (socket=%d)", conn.RemoteAddr(), conn.SocketID())

	// Handle SIGINT for clean shutdown.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		defer close(done)

		// Check if stdin has data (is not a terminal).
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			// Pipe mode: send stdin data in 1316-byte chunks.
			buf := make([]byte, 1316)
			for {
				n, err := os.Stdin.Read(buf)
				if n > 0 {
					if _, werr := conn.Write(buf[:n]); werr != nil {
						log.Printf("write: %v", werr)
						return
					}
				}
				if err == io.EOF {
					return
				}
				if err != nil {
					log.Printf("read stdin: %v", err)
					return
				}
			}
		}

		// Test pattern mode: send counter + timestamp.
		buf := make([]byte, 188)
		var counter uint64
		for {
			counter++
			binary.BigEndian.PutUint64(buf[0:8], counter)
			binary.BigEndian.PutUint64(buf[8:16], uint64(time.Now().UnixMicro()))
			if _, err := conn.Write(buf); err != nil {
				log.Printf("write: %v", err)
				return
			}
			if counter%1000 == 0 {
				fmt.Fprintf(os.Stderr, "\rsent %d packets", counter)
			}
			time.Sleep(time.Millisecond)
		}
	}()

	select {
	case <-sig:
		log.Println("shutting down...")
	case <-done:
	}
}
