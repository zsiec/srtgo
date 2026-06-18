// Command filetransfer demonstrates SRT file transfer mode.
//
// Send a file:
//
//	go run ./examples/filetransfer -mode send -addr 127.0.0.1:4200 -file data.bin
//
// Receive a file:
//
//	go run ./examples/filetransfer -mode recv -addr :4200 -file received.bin
package main

import (
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	srt "github.com/zsiec/srtgo"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4200", "address (send=remote, recv=listen)")
	mode := flag.String("mode", "", "send or recv")
	file := flag.String("file", "", "file path to send or receive")
	flag.Parse()

	if *mode == "" || *file == "" {
		flag.Usage()
		os.Exit(1)
	}

	switch *mode {
	case "send":
		sendFile(*addr, *file)
	case "recv":
		recvFile(*addr, *file)
	default:
		log.Fatalf("unknown mode %q (use send or recv)", *mode)
	}
}

func sendFile(addr, path string) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("open file: %v", err)
	}
	defer f.Close()

	info, _ := f.Stat()
	log.Printf("sending %s (%d bytes)", path, info.Size())

	cfg := srt.DefaultConfig()
	cfg.TransType = srt.TransTypeFile
	cfg.StreamID = "file/" + path

	conn, err := srt.Dial(addr, cfg)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 1456)
	var total int64
	start := time.Now()

	for {
		n, err := f.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				log.Fatalf("write: %v", werr)
			}
			total += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("read file: %v", err)
		}
	}

	elapsed := time.Since(start)
	mbps := float64(total*8) / elapsed.Seconds() / 1_000_000
	log.Printf("sent %d bytes in %v (%.1f Mbps)", total, elapsed.Round(time.Millisecond), mbps)
}

func recvFile(addr, path string) {
	cfg := srt.DefaultConfig()
	cfg.TransType = srt.TransTypeFile

	ln, err := srt.Listen(addr, cfg)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	log.Printf("listening on %s, waiting for sender...", ln.Addr())

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

	log.Printf("accepted from %s (streamID=%q)", conn.RemoteAddr(), conn.StreamID())

	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("create file: %v", err)
	}
	defer f.Close()

	buf := make([]byte, 1456)
	var total int64
	start := time.Now()

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				log.Fatalf("write file: %v", werr)
			}
			total += int64(n)
		}
		if err != nil {
			break
		}
	}

	elapsed := time.Since(start)
	mbps := float64(total*8) / elapsed.Seconds() / 1_000_000
	log.Printf("received %d bytes in %v (%.1f Mbps)", total, elapsed.Round(time.Millisecond), mbps)
}
