# srtgo

A pure Go implementation of the [SRT (Secure Reliable Transport)](https://datatracker.ietf.org/doc/html/draft-sharabayko-srt) protocol.

[![Go Reference](https://pkg.go.dev/badge/github.com/zsiec/srtgo.svg)](https://pkg.go.dev/github.com/zsiec/srtgo)
[![CI](https://github.com/zsiec/srtgo/actions/workflows/ci.yml/badge.svg)](https://github.com/zsiec/srtgo/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/zsiec/srtgo)](https://goreportcard.com/report/github.com/zsiec/srtgo)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- **Live streaming** with Timestamp-Based Packet Delivery (TSBPD) and too-late packet drop
- **File transfer** with AIMD congestion control and reliable delivery
- **AES-128/192/256 encryption** with CTR and GCM cipher modes
- **Forward Error Correction** (row + column XOR-based FEC)
- **Rendezvous mode** for peer-to-peer NAT traversal connections
- **Connection bonding** with broadcast and backup failover groups
- **`net.Conn` compatible** interface for drop-in use with existing Go code
- **Zero external dependencies** -- stdlib only (plus `golang.org/x/crypto` for PBKDF2)
- **Server framework** with publish/subscribe routing and graceful shutdown

## Install

```bash
go get github.com/zsiec/srtgo
```

Requires Go 1.24 or later.

## Quick Start

### Receiver (server side)

```go
package main

import (
	"log"

	srt "github.com/zsiec/srtgo"
)

func main() {
	l, err := srt.Listen("0.0.0.0:6000", srt.DefaultConfig())
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	l.SetAcceptFunc(func(req srt.ConnRequest) bool {
		return req.StreamID == "live/stream"
	})

	conn, err := l.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Println("read error:", err)
			return
		}
		// Process buf[:n]
		_ = n
	}
}
```

### Sender (client side)

```go
package main

import (
	"log"

	srt "github.com/zsiec/srtgo"
)

func main() {
	cfg := srt.DefaultConfig()
	cfg.StreamID = "live/stream"

	conn, err := srt.Dial("server:6000", cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	payload := make([]byte, 1316) // typical MPEG-TS: 7 * 188
	for {
		if _, err := conn.Write(payload); err != nil {
			log.Println("write error:", err)
			return
		}
	}
}
```

## Configuration

Use `srt.DefaultConfig()` as a starting point and override fields as needed.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Latency` | `time.Duration` | `120ms` | TSBPD receive delay. Negotiated to `max(local, remote)`. Minimum 20ms. |
| `RecvLatency` | `time.Duration` | `0` (uses `Latency`) | TSBPD latency for receiving. Overrides `Latency` when set. |
| `PeerLatency` | `time.Duration` | `0` (uses `Latency`) | Minimum TSBPD latency requested of the peer. |
| `MSS` | `int` | `1500` | Maximum Segment Size. Range: 76--1500. |
| `FC` | `int` | `25600` | Flow control window in packets. |
| `MaxBW` | `int64` | `125000000` | Maximum send bandwidth (bytes/sec). 0 = auto from `InputBW`. |
| `OverheadBW` | `int` | `25` | Bandwidth overhead percentage for retransmissions (5--100). |
| `SendBufSize` | `int` | `8192` | Send buffer size in packets. |
| `RecvBufSize` | `int` | `8192` | Receive buffer size in packets. |
| `PayloadSize` | `int` | `0` (auto) | Max payload per packet. 0 = `MSS - 44`. Used for CC pacing. |
| `StreamID` | `string` | `""` | Stream identifier sent during handshake. Max 512 bytes. |
| `Passphrase` | `string` | `""` | Encryption passphrase. 10--80 bytes when set. |
| `KeyLength` | `int` | `16` | AES key size: 16 (AES-128), 24 (AES-192), or 32 (AES-256). |
| `CryptoMode` | `int` | `0` (auto) | Cipher mode: 0 = auto, 1 = AES-CTR, 2 = AES-GCM. |
| `TransType` | `TransType` | `TransTypeLive` | Transfer type: `TransTypeLive` or `TransTypeFile`. |
| `Congestion` | `CongestionType` | `"live"` | Congestion control: `CongestionLive` or `CongestionFile`. |
| `ConnTimeout` | `time.Duration` | `3s` | Handshake timeout. |
| `PeerIdleTimeout` | `time.Duration` | `5s` | Peer inactivity timeout. Minimum 1s. |
| `Linger` | `time.Duration` | `0` | Time `Close()` waits for send buffer to drain. Max 180s. |
| `PacketFilter` | `string` | `""` | FEC configuration string (e.g., `"fec,cols:10,rows:5,layout:staircase,arq:onreq"`). |
| `LossMaxTTL` | `int` | `0` | Reorder tolerance in packets. 0 = immediate NAK. |
| `SndDropDelay` | `int` | `0` | Extra sender drop delay (ms). -1 = disable sender-side drop. |
| `GroupConnect` | `bool` | `false` | Allow grouped connections on a listener. |
| `Logger` | `Logger` | `nil` | Diagnostic logger. Nil = zero overhead. |

See the full [Config documentation](https://pkg.go.dev/github.com/zsiec/srtgo#Config) for all fields.

## Modes

### Live Mode (default)

Live mode is optimized for real-time audio/video streaming:

- **TSBPD** (Timestamp-Based Packet Delivery) delays packets to smooth jitter
- **TLPKTDROP** (Too-Late Packet Drop) discards packets that arrive past the latency window
- **Fixed-rate pacing** via LiveCC prevents bursts from overwhelming the network
- **Message API** preserves packet boundaries (each `Write` maps to one `Read`)

```go
cfg := srt.DefaultConfig() // live mode by default
cfg.Latency = 200 * time.Millisecond
```

### File Mode

File mode is optimized for reliable bulk data transfer:

- **AIMD congestion control** (slow start + congestion avoidance) adapts to available bandwidth
- **No packet drop** -- all data is delivered reliably
- **Stream API** -- data is treated as a byte stream, no message boundaries
- **Linger** -- `Close()` waits up to 180s for the send buffer to drain

```go
cfg := srt.DefaultConfig()
cfg.TransType = srt.TransTypeFile
```

## Advanced Features

### Encryption

SRT supports AES encryption with key exchange over the handshake. Set a passphrase (10--80 characters) on both sides:

```go
cfg := srt.DefaultConfig()
cfg.Passphrase = "my-secret-passphrase"
cfg.KeyLength = 32       // AES-256 (default: 16 for AES-128)
cfg.CryptoMode = 2       // AES-GCM (default: 0 for auto/CTR)
```

Keys are derived via PBKDF2 and wrapped per RFC 3394. Key rotation occurs automatically every ~16.7M packets by default (configurable via `KMRefreshRate` and `KMPreAnnounce`).

### Forward Error Correction

FEC adds parity packets using XOR across rows and columns, allowing the receiver to recover lost packets without retransmission:

```go
cfg := srt.DefaultConfig()
cfg.PacketFilter = "fec,cols:10,rows:5,layout:staircase,arq:onreq"
```

Parameters:
- `cols` -- number of columns in the FEC matrix
- `rows` -- number of rows (0 = row FEC disabled)
- `layout` -- `staircase` (default) or `even`
- `arq` -- `always` (default), `onreq` (FEC first, retransmit on request), or `never`

### Rendezvous Mode

Rendezvous mode enables peer-to-peer connections where neither side acts as a traditional server. Both peers bind to a local port and connect to each other simultaneously:

```go
cfg := srt.DefaultConfig()
cfg.Passphrase = "shared-secret"

// Peer A (local :5000, remote peerB:5000)
conn, err := srt.DialRendezvous(":5000", "peerB:5000", cfg)

// Peer B (local :5000, remote peerA:5000)
conn, err := srt.DialRendezvous(":5000", "peerA:5000", cfg)
```

The handshake uses a cookie contest to assign INITIATOR/RESPONDER roles automatically.

### Connection Bonding

Groups manage multiple SRT connections for link redundancy. Two modes are supported:

**Broadcast** sends every packet on all links. The receiver deduplicates by sequence number:

```go
g := srt.NewGroup(srt.GroupBroadcast)
g.Connect("server1:4200", cfg, 1, 100) // token=1, weight=100
g.Connect("server2:4200", cfg, 2, 50)  // token=2, weight=50
defer g.Close()

g.Write(payload) // sent on both links
n, err := g.Read(buf) // deduplicated
```

**Backup** uses one active link with automatic failover to standby links:

```go
g := srt.NewGroup(srt.GroupBackup)
g.SetStabilityTimeout(2 * time.Second)
g.Connect("primary:4200", cfg, 1, 100)  // higher weight = preferred
g.Connect("fallback:4200", cfg, 2, 50)
defer g.Close()

g.Write(payload) // sent on active link only; buffered for failover
```

When the active link becomes unstable, the highest-weight standby is promoted and recent packets are replayed for seamless continuity.

### Server Framework

The `Server` type provides a high-level callback-based framework for building SRT applications:

```go
package main

import (
	"log"

	srt "github.com/zsiec/srtgo"
)

func main() {
	s := &srt.Server{
		Addr: ":6000",
		HandleConnect: func(req srt.ConnRequest) srt.ConnType {
			if req.StreamID == "live/feed" {
				return srt.Publish
			}
			if req.StreamID == "live/watch" {
				return srt.Subscribe
			}
			return srt.Reject
		},
		HandlePublish: func(conn *srt.Conn) {
			buf := make([]byte, 1500)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				log.Printf("received %d bytes from publisher", n)
			}
		},
		HandleSubscribe: func(conn *srt.Conn) {
			// Send data to subscriber
			for {
				if _, err := conn.Write([]byte("data")); err != nil {
					return
				}
			}
		},
	}

	log.Fatal(s.ListenAndServe())
}
```

Call `s.Shutdown()` from another goroutine for graceful shutdown. Each handler runs in its own goroutine and the connection is closed when the handler returns.

### Statistics

The `Stats` method on `*Conn` returns detailed connection metrics:

```go
stats := conn.Stats(false) // false = cumulative totals; true = interval since last call

log.Printf("RTT: %v, Loss: %.2f%%, Bandwidth: %d pkt/s",
	stats.RTT, stats.SendLossRate, stats.EstimatedBandwidth)
log.Printf("Sent: %d pkts (%d bytes), Retransmits: %d",
	stats.SentPackets, stats.SentBytes, stats.Retransmits)
log.Printf("Recv: %d pkts (%d bytes), Dropped: %d",
	stats.RecvPackets, stats.RecvBytes, stats.RecvDropped)
log.Printf("Flight: %d pkts, SendBuf: %d pkts, RecvBuf: %d pkts",
	stats.FlightSize, stats.SendBufSize, stats.RecvBufSize)
```

The `ConnStats` struct includes counters for packets, bytes, loss, retransmits, drops, RTT, buffer state, bitrates, and key management state. Groups expose aggregate stats via `g.Stats()`.

## Architecture

Each SRT connection runs exactly 3 goroutines:

| Goroutine | Role |
|-----------|------|
| **recvLoop** | Reads packets from the UDP mux, processes control packets (ACK, NAK, keepalive), inserts data packets into the receive buffer |
| **timerLoop** | 10ms ticker drives periodic events: Full ACK, periodic NAK, keepalive, TSBPD delivery, EXP timeout |
| **application** | User calls `Read` / `Write` on the connection |

All connections sharing a listener multiplex over a single UDP socket. Packets are dispatched by `DestinationSocketID` in a single read goroutine.

### Internal Package Layout

| Package | Description |
|---------|-------------|
| `internal/seq` | 31-bit wrapping sequence numbers with comparison and arithmetic |
| `internal/clock` | Type-safe `Microseconds` / `Timestamp` types, `Clock` interface (real + mock for testing) |
| `internal/packet` | Concrete `Packet` struct, SRT header marshal/unmarshal, CIF types for all control packets |
| `internal/crypto` | AES-CTR/GCM encryption, RFC 3394 key wrap, PBKDF2 key derivation |
| `internal/mux` | UDP multiplexer -- shared socket dispatching packets by socket ID |
| `internal/buffer` | O(1) sequence-indexed send/receive ring buffers using power-of-2 bitmask |
| `internal/tsbpd` | Timestamp-Based Packet Delivery with drift compensation and group synchronization |
| `internal/congestion` | LiveCC (fixed-rate pacer) and FileCC (AIMD adaptive congestion control) |
| `internal/handshake` | SYN cookie generation/validation, 4-step and rendezvous handshake builders |
| `internal/filter` | FEC packet filter with row/column XOR encoding and recovery |

## Performance

Benchmarks on Apple M1 Pro (single core):

| Operation | Time | Allocations |
|-----------|------|-------------|
| Packet parse | 58 ns | 1 alloc |
| Header marshal | 2.4 ns | 0 allocs |
| Sequence ops | ~2 ns | 0 allocs |
| Clock ops | ~2 ns | 0 allocs |
| Buffer push | 72 ns | 0 allocs |
| Buffer ACK | 14 ns | 0 allocs |
| Write throughput | 164 MB/s | 5 allocs/op |
| Dial + Accept | 523 us | 146 allocs |
| AES encrypt | 293 ns | 0 allocs |
| Key wrap | 352 ns | 0 allocs |

Hot-path allocations are minimized through `sync.Pool` for packet buffers and concrete types (no interfaces on hot paths).

## Examples

The [`examples/`](examples/) directory contains runnable demos:

| Example | Description | Run |
|---------|-------------|-----|
| [loopback](examples/loopback) | Zero-config self-test: transfers 10 MB over localhost, verifies SHA-256, prints stats | `go run ./examples/loopback` |
| [streaming](examples/streaming) | Simulates live streaming with a real-time stats dashboard (throughput, RTT, loss) | `go run ./examples/streaming` |
| [sender](examples/sender) | Sends stdin or a test pattern to an SRT receiver | `go run ./examples/sender -addr 127.0.0.1:4200` |
| [receiver](examples/receiver) | Listens for a connection and writes received data to stdout | `go run ./examples/receiver -addr :4200` |
| [filetransfer](examples/filetransfer) | Reliable file transfer using file mode | `go run ./examples/filetransfer -mode send -file data.bin` |
| [server](examples/server) | Server framework with publish/subscribe routing | `go run ./examples/server` |

Start with `loopback` to verify everything works — it requires no setup:

```bash
go run ./examples/loopback
```

```
srtgo loopback demo
====================

Listener ready on 127.0.0.1:53314
Connected (RTT: 0.08ms, mode: file)

Transferring 10.0 MB...
   10.0 / 10.0 MB  100%   105.8 MB/s

Transfer complete
  Duration:    94ms
  Throughput:  105.8 MB/s
  Sent:        7202 packets (10485760 bytes)
  Received:    7202 packets (10485760 bytes)
  Retransmits: 0
  Integrity:   SHA-256 verified
```

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
