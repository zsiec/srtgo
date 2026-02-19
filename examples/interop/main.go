// Command interop is an SRT media relay for interoperability testing with
// FFmpeg, VLC, ffplay, and other SRT implementations.
//
// It listens for SRT connections and routes streams by StreamID using the
// SRT access control format (#!::m=publish,r=live/test). One publisher
// can fan out to multiple subscribers per stream. A live ANSI terminal
// dashboard shows per-connection SRT stats refreshing every second.
//
// Usage:
//
//	go run ./examples/interop
//	go run ./examples/interop -addr :4200 -passphrase "mysecretpass10"
//	go run ./examples/interop -addr :4200 -latency 200
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	srt "github.com/zsiec/srtgo"
)

// streamInfo holds the publisher and subscribers for a single stream resource.
type streamInfo struct {
	mu         sync.RWMutex
	resource   string
	pub        *connInfo
	subs       []*connInfo
	pubClosed  chan struct{} // closed when publisher disconnects
	closedOnce sync.Once
}

// connInfo tracks a single connection (publisher or subscriber).
type connInfo struct {
	conn      *srt.Conn
	role      string // "publish" or "subscribe"
	resource  string
	startTime time.Time

	dataCh  chan []byte    // subscriber: incoming data channel
	dropped atomic.Int64  // subscriber: dropped packets (channel full)

	statsMu sync.RWMutex
	stats   srt.ConnStats
}

// relay manages all streams.
type relay struct {
	mu      sync.RWMutex
	streams map[string]*streamInfo
}

func newRelay() *relay {
	return &relay{streams: make(map[string]*streamInfo)}
}

// parseStreamID parses SRT access control format:
//
//	#!::m=publish,r=live/test   → mode=publish, resource=live/test
//	#!::r=live/test             → mode=subscribe (default), resource=live/test
//	live/test                   → mode=publish (legacy), resource=live/test
func parseStreamID(sid string) (mode, resource string) {
	if !strings.HasPrefix(sid, "#!::") {
		// Legacy plain string — treat as publisher.
		return "publish", sid
	}
	body := sid[4:]
	mode = "subscribe" // default if no m= key
	for _, kv := range strings.Split(body, ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "m":
			mode = parts[1]
		case "r":
			resource = parts[1]
		}
	}
	return mode, resource
}

// getOrCreateStream returns the stream for a resource, creating if needed.
func (r *relay) getOrCreateStream(resource string) *streamInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.streams[resource]
	if !ok {
		s = &streamInfo{
			resource:  resource,
			pubClosed: make(chan struct{}),
		}
		r.streams[resource] = s
	}
	return s
}

// removeStream removes a stream from the relay.
func (r *relay) removeStream(resource string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.streams, resource)
}

// removeSub removes a subscriber from a stream.
func (s *streamInfo) removeSub(ci *connInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, sub := range s.subs {
		if sub == ci {
			s.subs = append(s.subs[:i], s.subs[i+1:]...)
			return
		}
	}
}

// snapshot returns a copy of all streams and connections for dashboard rendering.
func (r *relay) snapshot() []streamSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []streamSnapshot
	for _, s := range r.streams {
		s.mu.RLock()
		snap := streamSnapshot{resource: s.resource}
		if s.pub != nil {
			snap.pub = s.pub.snapshot()
		}
		for _, sub := range s.subs {
			snap.subs = append(snap.subs, *sub.snapshot())
		}
		s.mu.RUnlock()
		out = append(out, snap)
	}
	return out
}

type streamSnapshot struct {
	resource string
	pub      *connSnapshot
	subs     []connSnapshot
}

type connSnapshot struct {
	addr      string
	role      string
	uptime    time.Duration
	stats     srt.ConnStats
	chDropped int64
}

func (ci *connInfo) snapshot() *connSnapshot {
	ci.statsMu.RLock()
	s := ci.stats
	ci.statsMu.RUnlock()
	return &connSnapshot{
		addr:      ci.conn.RemoteAddr().String(),
		role:      ci.role,
		uptime:    time.Since(ci.startTime),
		stats:     s,
		chDropped: ci.dropped.Load(),
	}
}

func main() {
	addr := flag.String("addr", ":4200", "listen address")
	passphrase := flag.String("passphrase", "", "encryption passphrase (10-80 chars)")
	latency := flag.Int("latency", 120, "TSBPD latency in milliseconds")
	maxbw := flag.Int64("maxbw", 0, "max bandwidth bytes/sec (0 = default)")
	statsInterval := flag.Duration("stats", 1*time.Second, "dashboard refresh interval")
	flag.Parse()

	cfg := srt.DefaultConfig()
	cfg.Latency = time.Duration(*latency) * time.Millisecond
	if *passphrase != "" {
		cfg.Passphrase = *passphrase
	}
	if *maxbw > 0 {
		cfg.MaxBW = *maxbw
	}

	ln, err := srt.Listen(*addr, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	r := newRelay()

	// Accept filter: parse StreamID, reject invalid, reject duplicate publishers.
	ln.SetAcceptRejectFunc(func(req srt.ConnRequest) srt.RejectReason {
		if req.StreamID == "" {
			return srt.RejXBadRequest
		}
		mode, resource := parseStreamID(req.StreamID)
		if resource == "" {
			return srt.RejXBadRequest
		}
		if mode == "publish" {
			r.mu.RLock()
			s, ok := r.streams[resource]
			r.mu.RUnlock()
			if ok {
				s.mu.RLock()
				hasPub := s.pub != nil
				s.mu.RUnlock()
				if hasPub {
					return srt.RejXConflict
				}
			}
		}
		return 0
	})

	// Print startup banner.
	encMode := "none"
	if *passphrase != "" {
		keyLen := cfg.KeyLength
		if keyLen == 0 {
			keyLen = 16
		}
		encMode = fmt.Sprintf("AES-%d", keyLen*8)
	}

	fmt.Println()
	fmt.Println("  srtgo Interop Relay")
	fmt.Println("  ====================")
	fmt.Println()
	fmt.Printf("  Listen: %s    Latency: %dms    Encryption: %s\n", ln.Addr(), *latency, encMode)
	fmt.Println()
	fmt.Println("  Test commands:")
	fmt.Println()
	fmt.Println("  1. Color bars (publisher):")
	fmt.Printf("     ffmpeg -re -f lavfi -i 'smptebars=rate=30:size=1280x720' \\\n")
	fmt.Printf("       -f lavfi -i 'sine=frequency=1000:sample_rate=48000' \\\n")
	fmt.Printf("       -c:v libx264 -preset ultrafast -tune zerolatency -b:v 4M \\\n")
	fmt.Printf("       -c:a aac -b:a 128k -f mpegts \\\n")
	if *passphrase != "" {
		fmt.Printf("       'srt://127.0.0.1%s?passphrase=%s&streamid=%%23!::m=publish,r=live/test'\n", *addr, *passphrase)
	} else {
		fmt.Printf("       'srt://127.0.0.1%s?streamid=%%23!::m=publish,r=live/test'\n", *addr)
	}
	fmt.Println()
	fmt.Println("  2. Subscriber (ffplay):")
	if *passphrase != "" {
		fmt.Printf("     ffplay 'srt://127.0.0.1%s?passphrase=%s&streamid=%%23!::r=live/test'\n", *addr, *passphrase)
	} else {
		fmt.Printf("     ffplay 'srt://127.0.0.1%s?streamid=%%23!::r=live/test'\n", *addr)
	}
	fmt.Println()
	fmt.Println("  3. Subscriber (VLC):")
	if *passphrase != "" {
		fmt.Printf("     vlc 'srt://127.0.0.1%s?passphrase=%s&streamid=%%23!::r=live/test'\n", *addr, *passphrase)
	} else {
		fmt.Printf("     vlc 'srt://127.0.0.1%s?streamid=%%23!::r=live/test'\n", *addr)
	}
	fmt.Println()
	fmt.Println("  Waiting for connections...")
	fmt.Println()

	// Handle Ctrl+C.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	// Accept loop in background.
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(r, conn)
		}
	}()

	// Dashboard loop.
	startTime := time.Now()
	ticker := time.NewTicker(*statsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			fmt.Print("\033[H\033[J") // clear screen
			fmt.Println("Shutting down...")
			ln.Close()
			<-acceptDone
			return
		case <-ticker.C:
			renderDashboard(r, startTime, ln.Addr().String(), encMode)
		}
	}
}

func handleConn(r *relay, conn *srt.Conn) {
	mode, resource := parseStreamID(conn.StreamID())

	ci := &connInfo{
		conn:      conn,
		role:      mode,
		resource:  resource,
		startTime: time.Now(),
	}

	// Register stats callback.
	conn.OnStats(1*time.Second, func(s srt.ConnStats) {
		ci.statsMu.Lock()
		ci.stats = s
		ci.statsMu.Unlock()
	})

	switch mode {
	case "publish":
		handlePublisher(r, ci)
	default:
		handleSubscriber(r, ci)
	}
}

func handlePublisher(r *relay, ci *connInfo) {
	s := r.getOrCreateStream(ci.resource)

	s.mu.Lock()
	s.pub = ci
	s.mu.Unlock()

	defer func() {
		ci.conn.Close()

		// Signal all subscribers that publisher is gone.
		s.closedOnce.Do(func() { close(s.pubClosed) })

		// Close all subscriber channels.
		s.mu.Lock()
		for _, sub := range s.subs {
			close(sub.dataCh)
		}
		s.pub = nil
		subs := s.subs
		s.subs = nil
		s.mu.Unlock()

		// Wait for subscriber connections to close.
		for _, sub := range subs {
			sub.conn.Close()
		}

		r.removeStream(ci.resource)
	}()

	buf := make([]byte, 1500)
	for {
		n, err := ci.conn.Read(buf)
		if n > 0 {
			// Copy before fanning out (buf is reused).
			data := make([]byte, n)
			copy(data, buf[:n])

			s.mu.RLock()
			for _, sub := range s.subs {
				select {
				case sub.dataCh <- data:
				default:
					sub.dropped.Add(1)
				}
			}
			s.mu.RUnlock()
		}
		if err != nil {
			return
		}
	}
}

func handleSubscriber(r *relay, ci *connInfo) {
	s := r.getOrCreateStream(ci.resource)

	ci.dataCh = make(chan []byte, 256)

	s.mu.Lock()
	s.subs = append(s.subs, ci)
	s.mu.Unlock()

	defer func() {
		ci.conn.Close()
		s.removeSub(ci)
	}()

	// Wait for publisher or write data.
	for {
		select {
		case data, ok := <-ci.dataCh:
			if !ok {
				// Publisher disconnected, channel closed.
				return
			}
			if _, err := ci.conn.Write(data); err != nil {
				return
			}
		case <-s.pubClosed:
			// Publisher gone before we got any data, or after channel drained.
			// Drain remaining data in channel.
			for {
				select {
				case data, ok := <-ci.dataCh:
					if !ok {
						return
					}
					if _, err := ci.conn.Write(data); err != nil {
						return
					}
				default:
					return
				}
			}
		}
	}
}

// renderDashboard draws the ANSI dashboard to stdout.
func renderDashboard(r *relay, startTime time.Time, listenAddr, encMode string) {
	snaps := r.snapshot()

	var totalPub, totalSub int
	for _, s := range snaps {
		if s.pub != nil {
			totalPub++
		}
		totalSub += len(s.subs)
	}

	var b strings.Builder

	// Cursor home + clear to end of screen — flicker-free.
	b.WriteString("\033[H\033[J")

	b.WriteString("              srtgo Interop Relay\n")
	b.WriteString("              ====================\n\n")

	uptime := time.Since(startTime)
	b.WriteString(fmt.Sprintf(" Uptime: %s    Listen: %s    Encryption: %s\n",
		fmtDuration(uptime), listenAddr, encMode))
	b.WriteString(fmt.Sprintf(" Streams: %d        Publishers: %d     Subscribers: %d\n\n",
		len(snaps), totalPub, totalSub))

	if len(snaps) == 0 {
		b.WriteString(" Waiting for connections...\n")
	}

	for _, s := range snaps {
		b.WriteString(fmt.Sprintf(" ---- Stream: %s ----\n\n", s.resource))

		if s.pub != nil {
			renderConn(&b, s.pub, "PUB", 0)
		} else {
			b.WriteString(" PUB  (none)\n\n")
		}

		for i, sub := range s.subs {
			renderConn(&b, &sub, fmt.Sprintf("SUB  #%d", i+1), 0)
		}
	}

	os.Stdout.WriteString(b.String())
}

// renderConn writes a single connection's stats block.
func renderConn(b *strings.Builder, c *connSnapshot, label string, _ int) {
	s := c.stats

	b.WriteString(fmt.Sprintf(" %s  %s  [%s]\n", label, c.addr, fmtDuration(c.uptime)))

	// Bitrate bar.
	isPub := c.role == "publish"
	var rateMbps float64
	if isPub {
		rateMbps = s.MbpsRecvRate
	} else {
		rateMbps = s.MbpsSendRate
	}
	maxBar := autoScaleMbps(rateMbps)
	bar := renderBar(rateMbps, maxBar, 30)
	b.WriteString(fmt.Sprintf("   Rate %s  %.2f Mbps / %.0f\n", bar, rateMbps, maxBar))

	// RTT.
	rttMs := float64(s.RTT.Microseconds()) / 1000.0
	rttVarMs := float64(s.RTTVar.Microseconds()) / 1000.0
	b.WriteString(fmt.Sprintf("   RTT    %.2fms +/- %.2fms\n", rttMs, rttVarMs))

	// Packet counts.
	if isPub {
		totalMB := float64(s.RecvBytes) / (1024 * 1024)
		var lossRate float64
		if s.RecvPackets > 0 {
			lossRate = float64(s.RecvLoss) / float64(s.RecvPackets) * 100
		}
		b.WriteString(fmt.Sprintf("   Recv   %d pkts   %.1f MB   Loss %.2f%%   Retrans %d\n",
			s.RecvPackets, totalMB, lossRate, s.RecvRetrans))
	} else {
		totalMB := float64(s.SentBytes) / (1024 * 1024)
		b.WriteString(fmt.Sprintf("   Sent   %d pkts   %.1f MB   Loss %.2f%%   Retrans %d\n",
			s.SentPackets, totalMB, s.SendLossRate, s.Retransmits))
	}

	// Drops, buffers, flight.
	b.WriteString(fmt.Sprintf("   Drops  %d snd / %d rcv   Buffer %d snd / %d rcv   Flight %d",
		s.SentDropped, s.RecvDropped,
		s.SendBufSize, s.RecvBufSize,
		s.FlightSize))

	if !isPub {
		b.WriteString(fmt.Sprintf("   ChDrop %d", c.chDropped))
	}
	b.WriteString("\n\n")
}

// renderBar draws an ASCII bar graph.
func renderBar(val, max float64, width int) string {
	if max <= 0 {
		max = 1
	}
	filled := int(val / max * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return "[" + strings.Repeat("=", filled) + strings.Repeat(" ", width-filled) + "]"
}

// autoScaleMbps rounds up to a nice scale for the bar graph max.
func autoScaleMbps(val float64) float64 {
	scales := []float64{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000}
	for _, s := range scales {
		if val <= s {
			return s
		}
	}
	// Above 1 Gbps — round up to nearest 100 Mbps.
	return math.Ceil(val/100) * 100
}

// fmtDuration formats a duration as M:SS or H:MM:SS.
func fmtDuration(d time.Duration) string {
	d = d.Truncate(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}
