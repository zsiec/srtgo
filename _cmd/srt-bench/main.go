// Command srt-bench measures SRT throughput, latency, and resource usage.
//
// Modes:
//
//	loopback — both sides in one process (quick smoke test)
//	sender   — dial a listening peer and push data
//	receiver — listen, accept one connection, read and discard
//
// For accurate results use sender + receiver as separate OS processes.
// Loopback mode shares goroutine CPU which understates file-mode throughput.
//
// Output: JSON on stdout, progress on stderr.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"sync"
	"time"

	srt "github.com/zsiec/srtgo"
)

// ---------------------------------------------------------------------------
// Result is the JSON schema shared with the C benchmark tool (cbench).
// ---------------------------------------------------------------------------

type Result struct {
	Role       string  `json:"role"`
	TransType  string  `json:"trans_type"`
	DurationS  float64 `json:"duration_s"`
	Bytes      uint64  `json:"bytes"`
	Packets    uint64  `json:"packets"`
	MbpsSend   float64 `json:"mbps_send"`
	MbpsRecv   float64 `json:"mbps_recv"`
	RTTMs      float64 `json:"rtt_ms"`
	RTTVarMs   float64 `json:"rttvar_ms"`
	LossPct    float64 `json:"loss_pct"`
	Retransmit uint64  `json:"retransmits"`
	Drops      uint64  `json:"drops"`
	// Go-specific resource metrics (zero in cbench output).
	AllocMB   float64 `json:"alloc_mb,omitempty"`
	SysMB     float64 `json:"sys_mb,omitempty"`
	NumGC     uint32  `json:"num_gc,omitempty"`
	GoRoutine int     `json:"goroutines,omitempty"`
}

// ---------------------------------------------------------------------------
// SRT configuration — identical values used by cbench.c
// ---------------------------------------------------------------------------

func makeCfg(transType string) srt.Config {
	cfg := srt.DefaultConfig()
	cfg.Latency = 120 * time.Millisecond
	cfg.MaxBW = 10_000_000_000 / 8 // 10 Gbps
	cfg.ConnTimeout = 5 * time.Second
	cfg.FC = 25600
	cfg.SendBufSize = 8192
	cfg.RecvBufSize = 8192
	if transType == "file" {
		cfg.TransType = srt.TransTypeFile
	}
	return cfg
}

func payloadSize(transType string) int {
	if transType == "file" {
		return 1456
	}
	return 1316 // SRT_LIVE_DEF_PLSIZE
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	mode := flag.String("mode", "loopback", "loopback | sender | receiver")
	addr := flag.String("addr", "127.0.0.1:9001", "host:port")
	dur := flag.Duration("duration", 10*time.Second, "test duration")
	tt := flag.String("type", "live", "live | file")
	baseline := flag.String("baseline", "", "path to previous JSON for delta comparison")
	flag.Parse()

	var r Result
	switch *mode {
	case "loopback":
		if *tt == "file" {
			fmt.Fprintln(os.Stderr, "WARNING: loopback shares CPU between goroutines — file-mode numbers will be low.")
			fmt.Fprintln(os.Stderr, "         Use separate processes: -mode=receiver / -mode=sender")
		}
		r = runLoopback(*dur, *tt)
	case "sender":
		r = runSender(*addr, *dur, *tt)
	case "receiver":
		r = runReceiver(*addr, *dur, *tt)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", *mode)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)

	if *baseline != "" {
		printDelta(*baseline, r)
	}
}

// ---------------------------------------------------------------------------
// Loopback — listener + dialer in one process
// ---------------------------------------------------------------------------

func runLoopback(dur time.Duration, transType string) Result {
	cfg := makeCfg(transType)
	pSize := payloadSize(transType)

	ln, err := srt.Listen("127.0.0.1:0", cfg)
	if err != nil {
		fatal("listen: %v", err)
	}
	defer ln.Close()

	type recvResult struct {
		bytes uint64
		pkts  uint64
		stats srt.ConnStats
	}
	recvCh := make(chan recvResult, 1)

	runtime.GC()
	gcBefore := gcCount()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, pSize*2)
		var total uint64
		var pkts uint64
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				total += uint64(n)
				pkts++
			}
			if err != nil {
				break
			}
		}
		recvCh <- recvResult{total, pkts, conn.Stats(false)}
	}()

	conn, err := srt.Dial(ln.Addr().String(), cfg)
	if err != nil {
		fatal("dial: %v", err)
	}
	time.Sleep(20 * time.Millisecond) // let receiver settle

	chunk := makePayload(pSize)
	start := time.Now()
	deadline := start.Add(dur)
	var totalSent uint64
	var pktsSent uint64
	lastLog := start

	for time.Now().Before(deadline) {
		n, err := conn.Write(chunk)
		if err != nil {
			break
		}
		totalSent += uint64(n)
		pktsSent++
		logProgress(&lastLog, start, totalSent, pktsSent)
	}
	elapsed := time.Since(start)
	sndStats := conn.Stats(false)
	conn.Close()

	recv := <-recvCh
	wg.Wait()

	allocMB, sysMB, gcAfter := memStats()
	sendMbps := mbps(totalSent, elapsed)
	recvMbps := mbps(recv.bytes, elapsed)

	fmt.Fprintf(os.Stderr, "\nDone: %.1f Mbps send, %.1f Mbps recv, RTT=%.2fms, loss=%.3f%%\n",
		sendMbps, recvMbps,
		float64(sndStats.RTT.Microseconds())/1000.0,
		sndStats.SendLossRate)

	return Result{
		Role:       "loopback",
		TransType:  transType,
		DurationS:  elapsed.Seconds(),
		Bytes:      totalSent,
		Packets:    pktsSent,
		MbpsSend:   sendMbps,
		MbpsRecv:   recvMbps,
		RTTMs:      float64(sndStats.RTT.Microseconds()) / 1000.0,
		RTTVarMs:   float64(sndStats.RTTVar.Microseconds()) / 1000.0,
		LossPct:    sndStats.SendLossRate,
		Retransmit: sndStats.Retransmits,
		Drops:      sndStats.SentDropped + sndStats.RecvDropped,
		AllocMB:    allocMB,
		SysMB:      sysMB,
		NumGC:      gcAfter - gcBefore,
		GoRoutine:  runtime.NumGoroutine(),
	}
}

// ---------------------------------------------------------------------------
// Sender — dial and push data
// ---------------------------------------------------------------------------

func runSender(addr string, dur time.Duration, transType string) Result {
	cfg := makeCfg(transType)
	pSize := payloadSize(transType)

	fmt.Fprintf(os.Stderr, "Connecting to %s (%s)...\n", addr, transType)
	conn, err := srt.Dial(addr, cfg)
	if err != nil {
		fatal("dial: %v", err)
	}
	defer conn.Close()
	fmt.Fprintln(os.Stderr, "Connected.")
	time.Sleep(20 * time.Millisecond)

	runtime.GC()
	gcBefore := gcCount()

	chunk := makePayload(pSize)
	start := time.Now()
	deadline := start.Add(dur)
	var totalSent uint64
	var pktsSent uint64
	lastLog := start

	for time.Now().Before(deadline) {
		n, err := conn.Write(chunk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			break
		}
		totalSent += uint64(n)
		pktsSent++
		logProgress(&lastLog, start, totalSent, pktsSent)
	}
	elapsed := time.Since(start)
	stats := conn.Stats(false)
	allocMB, sysMB, gcAfter := memStats()
	sendMbps := mbps(totalSent, elapsed)

	fmt.Fprintf(os.Stderr, "\nSender done: %.1f Mbps, RTT=%.2fms, loss=%.3f%%\n",
		sendMbps, float64(stats.RTT.Microseconds())/1000.0, stats.SendLossRate)

	return Result{
		Role:       "sender",
		TransType:  transType,
		DurationS:  elapsed.Seconds(),
		Bytes:      totalSent,
		Packets:    pktsSent,
		MbpsSend:   sendMbps,
		RTTMs:      float64(stats.RTT.Microseconds()) / 1000.0,
		RTTVarMs:   float64(stats.RTTVar.Microseconds()) / 1000.0,
		LossPct:    stats.SendLossRate,
		Retransmit: stats.Retransmits,
		Drops:      stats.SentDropped + stats.RecvDropped,
		AllocMB:    allocMB,
		SysMB:      sysMB,
		NumGC:      gcAfter - gcBefore,
		GoRoutine:  runtime.NumGoroutine(),
	}
}

// ---------------------------------------------------------------------------
// Receiver — listen, accept, read
// ---------------------------------------------------------------------------

func runReceiver(addr string, dur time.Duration, transType string) Result {
	cfg := makeCfg(transType)
	pSize := payloadSize(transType)

	fmt.Fprintf(os.Stderr, "Listening on %s (%s)...\n", addr, transType)
	ln, err := srt.Listen(addr, cfg)
	if err != nil {
		fatal("listen: %v", err)
	}
	defer ln.Close()
	fmt.Fprintln(os.Stderr, "READY")

	conn, err := ln.Accept()
	if err != nil {
		fatal("accept: %v", err)
	}
	defer conn.Close()
	fmt.Fprintln(os.Stderr, "Accepted connection.")

	runtime.GC()
	gcBefore := gcCount()
	conn.SetReadDeadline(time.Now().Add(dur + 10*time.Second))

	buf := make([]byte, pSize*2)
	start := time.Now()
	lastLog := start
	var totalRecv uint64
	var pkts uint64

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			totalRecv += uint64(n)
			pkts++
		}
		logProgress(&lastLog, start, totalRecv, pkts)
		if err != nil {
			break
		}
	}
	elapsed := time.Since(start)
	stats := conn.Stats(false)
	allocMB, sysMB, gcAfter := memStats()
	recvMbps := mbps(totalRecv, elapsed)

	fmt.Fprintf(os.Stderr, "\nReceiver done: %.1f Mbps, %d packets\n", recvMbps, pkts)

	return Result{
		Role:       "receiver",
		TransType:  transType,
		DurationS:  elapsed.Seconds(),
		Bytes:      totalRecv,
		Packets:    pkts,
		MbpsRecv:   recvMbps,
		RTTMs:      float64(stats.RTT.Microseconds()) / 1000.0,
		RTTVarMs:   float64(stats.RTTVar.Microseconds()) / 1000.0,
		LossPct:    stats.RecvLossRate,
		Retransmit: stats.Retransmits,
		Drops:      stats.SentDropped + stats.RecvDropped,
		AllocMB:    allocMB,
		SysMB:      sysMB,
		NumGC:      gcAfter - gcBefore,
		GoRoutine:  runtime.NumGoroutine(),
	}
}

// ---------------------------------------------------------------------------
// Baseline delta comparison
// ---------------------------------------------------------------------------

func printDelta(path string, cur Result) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  baseline: %v\n", err)
		return
	}
	var prev Result
	if err := json.Unmarshal(data, &prev); err != nil {
		var arr []Result
		if err2 := json.Unmarshal(data, &arr); err2 != nil || len(arr) == 0 {
			fmt.Fprintf(os.Stderr, "  baseline: cannot parse %s\n", path)
			return
		}
		prev = arr[0]
	}

	tp := func(r Result) float64 {
		if r.MbpsSend > 0 {
			return r.MbpsSend
		}
		return r.MbpsRecv
	}

	fmt.Fprintf(os.Stderr, "\n  Delta vs baseline (%s):\n", path)
	fmt.Fprintf(os.Stderr, "  %-16s %12s %12s %10s\n", "Metric", "Baseline", "Current", "Delta")
	fmt.Fprintf(os.Stderr, "  %s\n", "────────────────────────────────────────────────────")

	row := func(name string, old, new float64, unit string, lowerBetter bool) {
		if old == 0 && new == 0 {
			return
		}
		delta := new - old
		pct := 0.0
		if old != 0 {
			pct = delta / math.Abs(old) * 100
		}
		good := !lowerBetter
		if delta < 0 {
			good = lowerBetter
		}
		marker := "  "
		if math.Abs(pct) > 5 {
			if good {
				marker = " ^"
			} else {
				marker = " !"
			}
		}
		fmt.Fprintf(os.Stderr, "  %-16s %10.2f%s %10.2f%s %+8.1f%%%s\n",
			name, old, unit, new, unit, pct, marker)
	}

	row("Throughput", tp(prev), tp(cur), " Mbps", false)
	row("RTT", prev.RTTMs, cur.RTTMs, " ms", true)
	row("Loss", prev.LossPct, cur.LossPct, " %", true)
	row("Retransmits", float64(prev.Retransmit), float64(cur.Retransmit), "", true)
	row("Drops", float64(prev.Drops), float64(cur.Drops), "", true)
	row("Go Heap", prev.AllocMB, cur.AllocMB, " MB", true)
	fmt.Fprintf(os.Stderr, "\n  ^ = improved (>5%%)   ! = regressed (>5%%)\n")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makePayload(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i % 256)
	}
	return b
}

func mbps(bytes uint64, d time.Duration) float64 {
	return float64(bytes) * 8 / 1e6 / d.Seconds()
}

func logProgress(lastLog *time.Time, start time.Time, bytes uint64, pkts uint64) {
	now := time.Now()
	if now.Sub(*lastLog) < 2*time.Second {
		return
	}
	elapsed := now.Sub(start).Seconds()
	fmt.Fprintf(os.Stderr, "  [%.0fs] %.1f Mbps (%d pkts)\n",
		elapsed, float64(bytes)*8/1e6/elapsed, pkts)
	*lastLog = now
}

func memStats() (allocMB, sysMB float64, numGC uint32) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.Alloc) / (1 << 20), float64(m.Sys) / (1 << 20), m.NumGC
}

func gcCount() uint32 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.NumGC
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
