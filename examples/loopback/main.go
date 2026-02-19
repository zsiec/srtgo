// Command loopback is a zero-config demo that proves srtgo works.
//
// It starts a listener and dialer in the same process over localhost,
// transfers 10 MB of data using file mode (reliable delivery), verifies
// integrity with SHA-256, and prints connection statistics.
//
// Usage:
//
//	go run ./examples/loopback
package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	srt "github.com/zsiec/srtgo"
)

const (
	totalBytes = 10 * 1024 * 1024 // 10 MB
	chunkSize  = 1456             // file mode payload size
	progressMB = 1024 * 1024      // report every 1 MB
)

func main() {
	log.SetFlags(0)

	fmt.Fprintln(os.Stderr, "srtgo loopback demo")
	fmt.Fprintln(os.Stderr, "====================")
	fmt.Fprintln(os.Stderr)

	// --- Listener ---

	cfg := srt.DefaultConfig()
	cfg.TransType = srt.TransTypeFile   // reliable delivery, no packet drops
	cfg.MaxBW = 1_000_000_000 / 8       // 1 Gbps
	cfg.ConnTimeout = 5 * time.Second

	ln, err := srt.Listen("127.0.0.1:0", cfg)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	listenAddr := ln.Addr().String()
	fmt.Fprintf(os.Stderr, "Listener ready on %s\n", listenAddr)

	// Channel to pass receiver results back.
	type recvResult struct {
		hash  [sha256.Size]byte
		bytes uint64
		pkts  uint64
		stats srt.ConnStats
	}
	recvDone := make(chan recvResult, 1)

	// --- Receiver goroutine (Accept + Read) ---

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}

		h := sha256.New()
		buf := make([]byte, chunkSize*2)
		var totalRecv uint64
		var pktCount uint64

		for {
			n, err := conn.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
				totalRecv += uint64(n)
				pktCount++
			}
			if err != nil {
				break
			}
		}

		stats := conn.Stats(false)
		conn.Close()

		var hash [sha256.Size]byte
		copy(hash[:], h.Sum(nil))
		recvDone <- recvResult{hash: hash, bytes: totalRecv, pkts: pktCount, stats: stats}
	}()

	// --- Sender (Dial + Write) ---

	conn, err := srt.Dial(listenAddr, cfg)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}

	// Brief pause to let handshake settle and RTT stabilize.
	time.Sleep(50 * time.Millisecond)

	initStats := conn.Stats(false)
	fmt.Fprintf(os.Stderr, "Connected (RTT: %.2fms, mode: file)\n",
		float64(initStats.RTT.Microseconds())/1000.0)
	fmt.Fprintln(os.Stderr)

	fmt.Fprintf(os.Stderr, "Transferring %.1f MB...\n", float64(totalBytes)/(1024*1024))

	// Build the deterministic pattern: repeating 0x00-0xFF.
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	sendHash := sha256.New()
	var totalSent uint64
	var pktsSent uint64
	lastReport := uint64(0)
	start := time.Now()

	for totalSent < totalBytes {
		writeSize := chunkSize
		remaining := totalBytes - int(totalSent)
		if remaining < writeSize {
			writeSize = remaining
		}

		n, err := conn.Write(chunk[:writeSize])
		if err != nil {
			log.Fatalf("write: %v", err)
		}
		sendHash.Write(chunk[:n])
		totalSent += uint64(n)
		pktsSent++

		// Progress every 1 MB.
		if totalSent/progressMB > lastReport/progressMB {
			elapsed := time.Since(start).Seconds()
			mbSent := float64(totalSent) / (1024 * 1024)
			speed := float64(totalSent) / elapsed / (1024 * 1024)
			fmt.Fprintf(os.Stderr, "\r  %5.1f / %.1f MB  %3.0f%%  %6.1f MB/s",
				mbSent, float64(totalBytes)/(1024*1024),
				float64(totalSent)/float64(totalBytes)*100, speed)
			lastReport = totalSent
		}
	}

	elapsed := time.Since(start)
	speed := float64(totalSent) / elapsed.Seconds() / (1024 * 1024)
	fmt.Fprintf(os.Stderr, "\r  %5.1f / %.1f MB  100%%  %6.1f MB/s\n",
		float64(totalBytes)/(1024*1024), float64(totalBytes)/(1024*1024), speed)

	// Collect sender stats before closing.
	var sHash [sha256.Size]byte
	copy(sHash[:], sendHash.Sum(nil))
	sndStats := conn.Stats(false)

	// Close sender to signal EOF to receiver.
	conn.Close()

	// Wait for receiver.
	result := <-recvDone
	wg.Wait()

	matched := sHash == result.hash

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Transfer complete")
	fmt.Fprintf(os.Stderr, "  Duration:    %s\n", elapsed.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "  Throughput:  %.1f MB/s\n", speed)
	fmt.Fprintf(os.Stderr, "  Sent:        %d packets (%d bytes)\n", pktsSent, totalSent)
	fmt.Fprintf(os.Stderr, "  Received:    %d packets (%d bytes)\n", result.pkts, result.bytes)
	fmt.Fprintf(os.Stderr, "  Retransmits: %d\n", sndStats.Retransmits)
	fmt.Fprintf(os.Stderr, "  RTT:         %.2fms (variance: %.2fms)\n",
		float64(sndStats.RTT.Microseconds())/1000.0,
		float64(sndStats.RTTVar.Microseconds())/1000.0)

	if matched {
		fmt.Fprintln(os.Stderr, "  Integrity:   SHA-256 verified")
	} else {
		fmt.Fprintln(os.Stderr, "  Integrity:   SHA-256 MISMATCH")
		fmt.Fprintf(os.Stderr, "    Sent:     %x\n", sHash)
		fmt.Fprintf(os.Stderr, "    Received: %x\n", result.hash)
		os.Exit(1)
	}
}
