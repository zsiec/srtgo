// Command streaming is a self-contained demo that simulates live streaming
// with a real-time stats dashboard.
//
// It starts a listener and dialer in the same process over localhost,
// sends data at a configurable bitrate (default 5 Mbps) simulating live
// streaming, and shows a live-updating stats table that refreshes every second.
//
// Usage:
//
//	go run ./examples/streaming
//	go run ./examples/streaming -bitrate 10000000 -duration 10s -latency 200ms
package main

import (
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	srt "github.com/zsiec/srtgo"
)

func main() {
	// --- Flags ---

	bitrate := flag.Int("bitrate", 5_000_000, "target bitrate in bits per second")
	duration := flag.Duration("duration", 5*time.Second, "streaming duration")
	latency := flag.Duration("latency", 120*time.Millisecond, "SRT latency")
	flag.Parse()

	bitrateF := float64(*bitrate)
	payloadSize := 1316 // SRT live payload size

	fmt.Println("srtgo live streaming demo")
	fmt.Println("=========================")
	fmt.Println()
	fmt.Printf("Streaming at %.1f Mbps (live mode, latency: %s)\n", bitrateF/1_000_000, *latency)
	fmt.Println()

	// --- Listener ---

	cfg := srt.DefaultConfig()
	cfg.Latency = *latency
	cfg.ConnTimeout = 5 * time.Second

	ln, err := srt.Listen("127.0.0.1:0", cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	// --- Receiver goroutine ---

	type recvResult struct {
		bytes uint64
		pkts  uint64
		err   error
	}
	recvDone := make(chan recvResult, 1)
	recvConnCh := make(chan *srt.Conn, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			recvDone <- recvResult{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer conn.Close()

		// Share the receiver conn so the stats goroutine can query it.
		recvConnCh <- conn

		buf := make([]byte, payloadSize*2)
		var totalRecv uint64
		var pktCount uint64

		for {
			n, err := conn.Read(buf)
			if n > 0 {
				totalRecv += uint64(n)
				pktCount++
			}
			if err != nil {
				break
			}
		}

		recvDone <- recvResult{bytes: totalRecv, pkts: pktCount}
	}()

	// --- Sender (Dial + paced writes) ---

	senderConn, err := srt.Dial(ln.Addr().String(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		os.Exit(1)
	}

	// Wait for receiver conn to be available (Accept completes after Dial).
	recvConn := <-recvConnCh

	// Build a fixed payload buffer.
	chunk := make([]byte, payloadSize)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	// Calculate pacing interval per packet.
	// bytesPerSecond = bitrate / 8
	// interval = payloadSize / bytesPerSecond = payloadSize * 8 / bitrate
	bytesPerSec := bitrateF / 8.0
	sendInterval := time.Duration(float64(payloadSize) / bytesPerSec * float64(time.Second))

	// --- Stats dashboard goroutine ---

	stopStats := make(chan struct{})
	var statsDone sync.WaitGroup
	statsDone.Add(1)

	// Prime the interval counters so the first tick captures 1 second of data.
	senderConn.Stats(true)

	go func() {
		defer statsDone.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		elapsed := 0

		// Print header.
		fmt.Fprintf(os.Stderr, "%-6s  %10s  %10s  %8s  %6s  %8s  %9s\n",
			"Time", "Sent", "Recv", "RTT", "Loss", "Retrans", "BW Est")
		fmt.Fprintf(os.Stderr, "%-6s  %10s  %10s  %8s  %6s  %8s  %9s\n",
			"----", "----", "----", "---", "----", "-------", "------")

		for {
			select {
			case <-stopStats:
				return
			case <-ticker.C:
				elapsed++
				s := senderConn.Stats(true)

				// Cumulative sent bytes from sender, received bytes from receiver.
				sndCumul := senderConn.Stats(false)
				rcvCumul := recvConn.Stats(false)

				sentMB := float64(sndCumul.SentBytes) / (1024 * 1024)
				recvMB := float64(rcvCumul.RecvBytes) / (1024 * 1024)
				rttMS := float64(s.RTT.Microseconds()) / 1000.0
				lossRate := s.SendLossRate
				retrans := s.Retransmits

				// Bandwidth estimate from interval send rate or link capacity probe.
				var bwMbps float64
				if s.MbpsSendRate > 0 {
					bwMbps = s.MbpsSendRate
				} else if s.EstimatedBandwidth > 0 {
					bwMbps = float64(s.EstimatedBandwidth) * float64(payloadSize) * 8 / 1_000_000
				}

				fmt.Fprintf(os.Stderr, "%4ds  %7.1f MB  %7.1f MB  %6.2fms  %5.2f%%  %7d  %5.1f Mbps\n",
					elapsed, sentMB, recvMB, rttMS, lossRate, retrans, bwMbps)
			}
		}
	}()

	// --- Paced sending loop ---

	deadline := time.After(*duration)
	var totalSent uint64
	var pktsSent uint64

	nextSend := time.Now()

sendLoop:
	for {
		select {
		case <-deadline:
			break sendLoop
		default:
		}

		// Pace: wait until the next scheduled send time.
		now := time.Now()
		if sleepFor := nextSend.Sub(now); sleepFor > 0 {
			time.Sleep(sleepFor)
		}
		nextSend = nextSend.Add(sendInterval)

		// If we fell behind, reset to avoid burst-sending.
		if time.Now().After(nextSend.Add(sendInterval * 10)) {
			nextSend = time.Now().Add(sendInterval)
		}

		n, err := senderConn.Write(chunk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			break
		}
		totalSent += uint64(n)
		pktsSent++
	}

	// --- Shutdown ---

	// Grab cumulative stats before closing.
	finalStats := senderConn.Stats(false)

	senderConn.Close()

	// Wait for receiver to finish.
	result := <-recvDone

	// Stop the stats dashboard.
	close(stopStats)
	statsDone.Wait()

	if result.err != nil {
		fmt.Fprintf(os.Stderr, "receiver error: %v\n", result.err)
		os.Exit(1)
	}

	// --- Summary ---

	fmt.Println()
	fmt.Println("Stream complete")

	actualDuration := finalStats.Duration.Seconds()
	sentMB := float64(finalStats.SentBytes) / (1024 * 1024)
	recvMB := float64(result.bytes) / (1024 * 1024)

	var avgRate float64
	if actualDuration > 0 {
		avgRate = float64(finalStats.SentBytes) * 8 / 1_000_000 / actualDuration
	}

	var lossRate float64
	if finalStats.SentPackets > 0 {
		lossRate = float64(finalStats.LostPackets) / float64(finalStats.SentPackets) * 100
	}

	avgRTT := float64(finalStats.RTT.Microseconds()) / 1000.0

	fmt.Printf("  Duration:  %.1fs\n", actualDuration)
	fmt.Printf("  Total:     %.1f MB sent, %.1f MB received\n", sentMB, recvMB)
	fmt.Printf("  Avg rate:  %.1f Mbps\n", avgRate)
	fmt.Printf("  Packets:   %d sent, %d received, %d retransmitted\n",
		finalStats.SentPackets, result.pkts, finalStats.Retransmits)
	fmt.Printf("  Loss:      %.2f%%\n", lossRate)
	fmt.Printf("  Avg RTT:   %.2fms\n", avgRTT)

	wg.Wait()
}
