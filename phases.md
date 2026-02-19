# SRT Go Implementation: Full Feature Parity Plan

## Current State

**56 of 104 features fully implemented (54%), 25 partial (24%), 25 missing (24%)**

The Go implementation covers the core live-streaming caller-listener path:
HSv5 handshake, AES encryption, TSBPD, full ACK/NAK/ACKACK reliability loop,
congestion-controlled pacing, and multiplexed UDP connections.

This plan closes the remaining 49 features (25 partial + 25 missing) to reach
100% parity with the C++ SRT reference implementation (`srt-reference/srtcore/`).

---

## Phase 1: Interop Hardening (fix all ⚠️ partial items)

**Goal:** Upgrade every partial implementation to full correctness. Highest ROI —
improves reliability for the already-working live streaming path.

**Estimated scope:** ~800 LOC changes across existing files

### 1a. NAK Interval Alignment
- Change periodic NAK interval from `4×RTT` to `RTT/2` to match C++ LiveCC
  (`congestion/live.cpp` uses `m_iNakReportAccel=2` → interval = RTT/NAKAccel)
- Keep 20ms floor (matches both implementations)
- File: `conn.go`

### 1b. Latency Option Split
- Split `Config.Latency` into `Config.RecvLatency` and `Config.PeerLatency`
  (maps to `SRTO_RCVLATENCY` and `SRTO_PEERLATENCY`)
- Keep `Config.Latency` as a convenience that sets both (matches `SRTO_LATENCY`)
- Use separate values in HSREQ `RecvTSBPDDelay` / `SendTSBPDDelay`
- Files: `config.go`, `dialer.go`, `listener.go`

### 1c. Flow Control: In-Flight Tracking
- Track in-flight packets separately: `inflight = nextSeq - lastACKSeq`
- Block sender when `inflight >= FC` (not just when send buffer is full)
- Matches C++ `core.cpp:6989` which checks `sndBuffersLeft() < required`
- Files: `conn.go`

### 1d. Bandwidth Estimation Improvement
- Use proper IIR filter for packet arrival rate (C++ `CPktTimeWindow`)
- Separate probe-pair bandwidth from overall delivery rate
- Report both `PacketsReceivingRate` and `EstimatedLinkCapacity` correctly in ACK
- Files: `internal/congestion/live.go`, `conn.go`

### 1e. HSv4 Fallback
- In `dialInduction`: if response has `Version=4` (no SRT magic), fall back to
  UDT-only CONCLUSION (no extensions). Already sends v4 induction.
- In `handleConclusion`: accept v4 CONCLUSION without extensions (reduced feature set)
- Files: `dialer.go`, `listener.go`

### 1f. Congestion Control Extension Negotiation
- Parse `ExtTypeCongestion` in handshake CONCLUSION
- Validate peer requests "live" CC (reject "file" until Phase 6)
- Send congestion control extension in HSREQ with value "live"
- Files: `internal/packet/cif.go`, `internal/handshake/handshake.go`

### 1g. Statistics Expansion (Quick Wins)
- Add unique vs. retransmitted packet breakdown to `ConnStats`
- Add header bytes to byte counters (or separate `SentPayloadBytes` / `SentTotalBytes`)
- Add loss rate percentage calculation
- Add buffer utilization percentage
- Files: `conn.go`

### Tests
- `TestNAKIntervalMatchesRTT` — verify NAK fires at RTT/2
- `TestSeparateLatencyNegotiation` — different recv/send latencies
- `TestInFlightFlowControl` — verify sender blocks at FC, not just buffer full
- `TestHSv4Fallback` — connect to a v4-only peer (simulated)

---

## Phase 2: Socket Options & Configuration Infrastructure

**Goal:** Runtime-settable options API matching `srt_setsockopt()` / `srt_getsockopt()`.
Needed as infrastructure for many later phases.

**Estimated scope:** ~600 LOC new, ~200 LOC changes

### 2a. Options API
- Add `Conn.SetOption(opt, value)` and `Conn.GetOption(opt)` methods
- Define `Option` type with constants for each option
- Pre-connection vs. post-connection settability (match C++ `m_bConnected` checks)
- Thread-safe option storage with atomic/mutex protection
- Files: new `options.go`, `conn.go`

### 2b. Missing Configuration Options
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `SRTO_MINVERSION` | `uint32` | 0 | Minimum peer SRT version to accept |
| `SRTO_LOSSMAXTTL` | `int` | 0 | Reorder tolerance (delay NAK by N packets) |
| `SRTO_SNDDROPDELAY` | `time.Duration` | 0 | Extra delay before TLPKTDROP triggers |
| `SRTO_LINGER` | `time.Duration` | 0 | Linger on close (drain send buffer) |
| `SRTO_NAKREPORT` | `bool` | true | Enable/disable periodic NAK |
| `SRTO_ENFORCEDENCRYPTION` | `bool` | true | Strict encryption enforcement toggle |
| `SRTO_PEERIDLETIMEO` | `time.Duration` | 5s | Peer idle timeout |

### 2c. Reorder Tolerance (LOSSMAXTTL)
- Add `FreshLoss` list to recv buffer: when a gap is detected, don't NAK
  immediately — wait until `LOSSMAXTTL` later packets have arrived
- If the missing packet arrives within TTL, remove from fresh loss (no NAK sent)
- If TTL expires, move to regular loss list and send NAK
- Dynamic reorder tolerance: increase on OOO delivery, decrease on in-order
- Reference: C++ `m_FreshLoss` deque, `m_iReorderTolerance`, `m_iConsecEarlyDelivery`
- Files: `internal/buffer/recv.go`, `conn.go`

### 2d. Send Drop Delay
- Add configurable delay before TLPKTDROP: `dropThreshold = tsbpdDelay + sndDropDelay`
- Currently drops at exactly `tsbpdDelay`; C++ adds `SRTO_SNDDROPDELAY` on top
- Files: `conn.go`, `config.go`

### 2e. Linger on Close
- When `Linger > 0`, `Close()` waits up to `Linger` for send buffer to drain
- Send remaining packets, wait for ACKs, then shut down
- Files: `conn.go`

### 2f. Extended Rejection Codes
- Add 1400+ range constants (`RejBadRequest`, `RejUnauthorized`, `RejForbidden`, etc.)
- Allow `AcceptFunc` to return specific rejection codes (change return type)
- Files: `errors.go`, `listener.go`

### Tests
- `TestSetOptionPreConnect` / `TestSetOptionPostConnect`
- `TestReorderTolerance` — OOO packets within TTL don't trigger NAK
- `TestSendDropDelay` — verify extended drop threshold
- `TestLingerOnClose` — verify send buffer drains before close
- `TestMinVersionRejection` — reject peers below minimum version

---

## Phase 3: Statistics Parity

**Goal:** Match C++ `SRT_TRACEBSTATS` (50+ fields), with trace/total/interval modes.

**Estimated scope:** ~500 LOC new

### 3a. Full Stats Structure
Expand `ConnStats` to include all fields from C++ `CBytePerfMon`:

**Send-side:**
- `SentUnique`, `SentRetransmitted` (separate from total)
- `SendLossRate` (percentage)
- `SndDropTotal` (too-late drops)
- `SndFilterExtra` (FEC overhead — placeholder until Phase 8)

**Receive-side:**
- `RecvLoss`, `RecvBelated`, `RecvDropped`, `RecvUndecrypted`
- `RecvLossRate` (percentage)
- `RcvFilterExtra`, `RcvFilterSupply` (FEC — placeholder)

**Connection:**
- `NegotiatedLatency`, `NegotiatedMSS`
- `FlightSize` (current in-flight packets)
- `SendBufferAvail`, `RecvBufferAvail` (bytes)
- `RTTFactor` (RTT relative to latency)
- `PktSentACK`, `PktRecvACK`, `PktSentNAK`, `PktRecvNAK` (control packet counts)

### 3b. Trace/Total/Interval Modes
- `Stats(clear bool)` — if `clear=true`, return interval stats since last call (trace mode)
- Maintain both cumulative (`total`) and since-last-reset (`trace`) counters
- Match `srt_bistats(sock, &perf, clear, instantaneous)` semantics
- Files: `conn.go`, `stats.go`

### 3c. Statistics Event Callback
- Add `Conn.OnStats(func(ConnStats))` callback invoked every N seconds
- Enables push-based monitoring without polling
- Files: `conn.go`

### Tests
- `TestStatsTraceMode` — verify interval reset
- `TestStatsAllFields` — verify all 50+ fields populated
- Benchmarks: verify stats collection doesn't measurably impact throughput

---

## Phase 4: Periodic Key Rotation

**Goal:** Automatic re-keying for long-running encrypted streams.

**Estimated scope:** ~300 LOC

### 4a. Configuration
- Add `Config.KMRefreshRate` (default: 2^24 packets) — trigger re-key after N packets
- Add `Config.KMPreAnnounce` (default: 2^12 packets) — announce new key N packets early
- Files: `config.go`

### 4b. Key Refresh Lifecycle
1. After `KMRefreshRate - KMPreAnnounce` packets sent, generate new SEK for the
   opposite key slot (if currently Even, prepare Odd)
2. Send KMREQ control message with new key material (both keys wrapped)
3. Receiver unwraps and installs both keys
4. After `KMPreAnnounce` more packets, sender switches `activeKey` to the new slot
5. Old key remains valid for decryption until next rotation

### 4c. Implementation
- Add packet counter to `Conn` tracking total encrypted packets sent
- In `timerLoop` or `Write()`: check counter against refresh/pre-announce thresholds
- Send KMREQ as a standalone control message (not in handshake)
- Handle incoming KMREQ/KMRSP as control packets (add to `handleControlPacket`)
- Reference: C++ `CCryptoControl::sendKeysToPeer()`, called from `checkTimers()`
- Files: `conn.go`, `internal/crypto/crypto.go`

### Tests
- `TestKeyRotation` — send many packets, verify keys rotate
- `TestKeyRotationContinuity` — no data loss during rotation
- `TestKeyRotationInterop` — verify against C++ SRT peer (integration test)

---

## Phase 5: Message Mode

**Goal:** Multi-packet messages with boundary preservation and reassembly.

**Estimated scope:** ~600 LOC

**Dependencies:** None (extends existing data path)

### 5a. Sender: Message Framing
- `WriteMessage(b []byte)` method that splits large payloads across packets
- Set PP flags: `PositionFirst` on first packet, `PositionMiddle` on middle,
  `PositionLast` on final, `PositionSingle` if fits in one packet
- Assign same `MessageNumber` (26-bit, wrapping) to all packets in a message
- Files: `conn.go`, `internal/packet/header.go`

### 5b. Receiver: Message Reassembly
- `ReadMessage(b []byte)` method that blocks until a complete message is available
- Track message boundaries in recv buffer using PP flags
- Only deliver when all packets for a message (First..Last) are present
- Handle TSBPD: deliver based on FIRST packet's timestamp
- Files: `conn.go`, `internal/buffer/recv.go`

### 5c. In-Order Delivery
- When `Order=true` (INORDER flag), messages must be delivered in message-number order
- Skip/drop incomplete messages that are past the TSBPD deadline
- Files: `conn.go`, `internal/buffer/recv.go`

### 5d. MESSAGEAPI Toggle
- `Config.MessageAPI` option — when true, use message boundaries
- When false (default for live mode), use stream-style byte delivery
- Files: `config.go`, `conn.go`

### Tests
- `TestMessageBoundaries` — send 3 messages, verify each received intact
- `TestLargeMessage` — message spanning multiple packets
- `TestMessageDrop` — incomplete message dropped after TSBPD timeout
- `TestMessageOrder` — in-order delivery with out-of-order packets

---

## Phase 6: File Transfer Mode

**Goal:** CUBIC-like congestion control and buffer-mode transfer for bulk data.

**Estimated scope:** ~1200 LOC

**Dependencies:** Phase 5 (message mode) for message-level ACK

### 6a. File Congestion Controller
- New `FileCC` in `internal/congestion/` implementing CUBIC-like CC:
  - Slow start phase (exponential CWND growth)
  - Congestion avoidance (CUBIC function)
  - Loss-reactive CWND reduction (multiplicative decrease)
  - Quick ACK on short messages
- Same `CC` interface as `LiveCC` but with CWND-based flow control
- Reference: C++ `congestion/file.cpp` (~600 LOC)
- Files: new `internal/congestion/file.go`

### 6b. Congestion Control Selection
- `Config.Congestion` option: `"live"` (default) or `"file"`
- Negotiate via congestion control handshake extension
- Create appropriate CC in `newConn()` based on selection
- Files: `config.go`, `conn.go`, `internal/handshake/handshake.go`

### 6c. Buffer Mode Read/Write
- When `Congestion="file"`: no TSBPD, no timestamp-based delivery
- Receive buffer delivers packets purely in-order (FIFO)
- Write path: no pacing (CC controls sending rate via CWND)
- `ReadFile(b []byte)` — stream-oriented read filling buffer completely
- Files: `conn.go`

### 6d. TransType Bundle
- `Config.TransType`: `TransTypeLive` (default) or `TransTypeFile`
- `TransTypeLive` sets: TSBPD=on, TLPKTDROP=on, LiveCC, NAK=periodic
- `TransTypeFile` sets: TSBPD=off, TLPKTDROP=off, FileCC, NAK=on-loss
- Files: `config.go`

### Tests
- `TestFileCCSSlowStart` — verify CWND grows exponentially
- `TestFileCCLossRecovery` — verify CWND reduces on loss
- `TestFileTransfer` — send large data, verify complete delivery
- `BenchmarkFileTransfer` — measure throughput vs live mode

---

## Phase 7: Rendezvous Mode

**Goal:** Simultaneous open for P2P / NAT traversal connections.

**Estimated scope:** ~800 LOC

**Dependencies:** None (parallel handshake path)

### 7a. Rendezvous Handshake State Machine
States: `IDLE → WAVEHAND → CONCLUSION → CONNECTED`
- Both peers send WAVEHAND simultaneously (HandshakeType=0x00000000)
- On receiving peer's WAVEHAND, transition to CONCLUSION
- Exchange CONCLUSION with extensions (same as caller-listener)
- On receiving peer's CONCLUSION, send AGREEMENT (0xFFFFFFFE) and transition to CONNECTED
- Cookie contest: if both peers have same cookie, use cookie comparison to break tie
  (determines who acts as "initiator" for extension ordering)
- Reference: C++ `handshake.cpp:181-194`, `core.cpp` rendezvous sections

### 7b. API
- `DialRendezvous(localAddr, remoteAddr string, cfg Config) (*Conn, error)`
- Both peers call `DialRendezvous` with each other's address
- Bind to `localAddr`, send to `remoteAddr`
- Files: new `rendezvous.go`

### 7c. Rendezvous with Extensions
- After cookie contest determines roles, exchange HSREQ/HSRSP and KMREQ/KMRSP
- "Initiator" sends HSREQ first, "responder" replies with HSRSP
- Same encryption negotiation as caller-listener
- Files: `rendezvous.go`, `internal/handshake/handshake.go`

### Tests
- `TestRendezvousBasic` — two goroutines connect to each other
- `TestRendezvousEncrypted` — with passphrase
- `TestRendezvousCookieContest` — verify tie-breaking
- `TestRendezvousTimeout` — one side doesn't connect

---

## Phase 8: Forward Error Correction

**Goal:** Proactive loss recovery without retransmission via XOR-based FEC.

**Estimated scope:** ~1500 LOC

**Dependencies:** Phase 2 (packet filter extension negotiation)

### 8a. Packet Filter Framework
- Define `PacketFilter` interface:
  ```go
  type PacketFilter interface {
      OnPacketSend(p *packet.Packet) []packet.Packet  // may produce extra packets
      OnPacketRecv(p *packet.Packet) []packet.Packet   // may recover lost packets
      Config() string                                    // negotiation string
  }
  ```
- Hook into send path (after encryption) and receive path (before recv buffer)
- Negotiate filter config via `ExtTypeFilter` handshake extension
- Files: new `internal/filter/filter.go`

### 8b. FEC Filter (XOR Column/Row)
- Column FEC: XOR every Nth packet; one FEC packet per column
- Row FEC: XOR consecutive N packets; one FEC packet per row
- 2D FEC: both column and row (higher overhead, better recovery)
- Recovery: when a data packet is lost but its FEC packet and all other data
  packets in the group are available, XOR-recover the lost packet
- Group tracking: maintain matrix of received packets per FEC group
- Reference: C++ `fec.cpp` (~2585 LOC)
- Files: new `internal/filter/fec.go`

### 8c. Configuration
- `Config.PacketFilter` string (e.g., `"fec,cols:10,rows:5"`)
- Parse filter config string into parameters
- Negotiate with peer during handshake
- Files: `config.go`, `internal/handshake/handshake.go`

### 8d. Stats Integration
- `RcvFilterExtra` — FEC packets received
- `RcvFilterSupply` — data packets recovered by FEC
- `SndFilterExtra` — FEC packets sent
- Files: `conn.go`

### Tests
- `TestFECColumnRecovery` — lose 1 packet per column, verify recovery
- `TestFECRowRecovery` — lose 1 packet per row, verify recovery
- `TestFEC2DRecovery` — 2D matrix recovery
- `TestFECNegotiation` — handshake filter extension
- `BenchmarkFECOverhead` — measure throughput impact

---

## Phase 9: Connection Bonding

**Goal:** Socket groups for link redundancy with broadcast/backup/balancing modes.

**Estimated scope:** ~2500 LOC

**Dependencies:** Phase 2 (group extension), Phase 7 (rendezvous is optional but helpful)

### 9a. Socket Group Infrastructure
- `Group` type managing multiple `Conn` instances
- Each member connection tracks: state, weight, activation time, stability
- Group-level read/write that dispatches across members
- Group extension in handshake (ExtTypeGroup)
- Reference: C++ `group.h` / `group.cpp` (~4424 LOC)
- Files: new `group.go`, `internal/packet/cif.go`

### 9b. Broadcast Mode
- Send every packet on ALL member connections simultaneously
- Receive from first connection to deliver each packet (deduplication by seqno)
- Highest reliability, highest bandwidth cost
- Files: `group.go`

### 9c. Backup Mode
- One "active" link, others in "standby"
- Monitor active link health (RTT stability, loss rate)
- On active link degradation: activate standby, send on both briefly, then deactivate old
- Stability detection: `SRTO_GROUPSTABTIMEO`
- Seamless failover with minimal packet loss
- Reference: C++ `group_backup.cpp`
- Files: `group.go`

### 9d. Balancing Mode
- Distribute packets across links based on weight/capacity
- Load-balance for maximum aggregate throughput
- Packet scheduling: round-robin weighted by link capacity
- Files: `group.go`

### 9e. Group API
```go
func NewGroup(mode GroupMode) *Group
func (g *Group) AddLink(addr string, cfg Config) error
func (g *Group) RemoveLink(addr string) error
func (g *Group) Read(b []byte) (int, error)   // net.Conn-compatible
func (g *Group) Write(b []byte) (int, error)
func (g *Group) Close() error
func (g *Group) Stats() GroupStats
```

### 9f. Accept-Side Group Support
- `Listener.AcceptGroup()` — accept grouped connections
- Match incoming connections to existing group by group ID
- Files: `listener.go`, `group.go`

### Tests
- `TestBroadcastMode` — send on 2 links, receive deduplicated
- `TestBackupFailover` — kill active link, verify seamless switch
- `TestBalancingThroughput` — verify aggregate > single link
- `TestGroupReconnect` — member link drops and reconnects

---

## Phase 10: Platform & Ecosystem

**Goal:** IPv6, OS integration, and final parity items.

**Estimated scope:** ~800 LOC

### 10a. IPv6 Support
- Dual-stack listener: accept both IPv4 and IPv6
- IPv6 address marshaling in handshake (16-byte PeerIP field already handles it)
- `Config.IPv6Only` option (maps to `SRTO_IPV6ONLY`)
- Ensure `net.ResolveUDPAddr` handles IPv6 addresses correctly
- Files: `listener.go`, `dialer.go`, `internal/handshake/handshake.go`

### 10b. OS Socket Options
- `Config.IPTTL` — set IP TTL on underlying UDP socket (`SRTO_IPTTL`)
- `Config.IPTOS` — set IP TOS/DSCP on underlying UDP socket (`SRTO_IPTOS`)
- `Config.BindToDevice` — bind to specific network interface (`SRTO_BINDTODEVICE`)
- Apply via `net.UDPConn.SyscallConn()` + `syscall.SetsockoptInt()`
- Platform-specific: Linux for BINDTODEVICE, cross-platform for TTL/TOS
- Files: `config.go`, `listener.go`, `dialer.go`, new `sockopt_linux.go` / `sockopt_other.go`

### 10c. Event System
- Go-native alternative to C++ epoll: `Watcher` type
- `NewWatcher(conns ...*Conn) *Watcher`
- `Watcher.Wait() (Event, error)` — returns next event (readable, writable, error)
- Internally uses `reflect.Select` on connection channels
- Not a direct epoll port, but provides equivalent functionality idiomatically
- Files: new `watcher.go`

### 10d. Logging Infrastructure
- Structured logging interface (pluggable logger)
- Log categories matching C++ `SRT_LOGFA_*`: general, control, data, tsbpd, etc.
- Configurable log levels per category
- Default: no logging (zero overhead)
- Files: new `log.go`

### Tests
- `TestIPv6Connection` — dial/accept over IPv6 loopback
- `TestDualStack` — IPv4 client to IPv6 listener
- `TestIPTTL` — verify TTL is set on socket
- `TestWatcher` — multiplex reads across multiple connections

---

## Dependency Graph

```
Phase 1 (Interop)
    ↓
Phase 2 (Socket Options) ← needed by Phases 4, 6, 8, 9
    ↓
Phase 3 (Statistics) ← independent, but enriched by later phases
    ↓
Phase 4 (Key Rotation) ← needs Phase 2 config options
    ↓
Phase 5 (Message Mode) ← needed by Phase 6
    ↓
Phase 6 (File Mode) ← needs Phase 5 message framing
    ↓
Phase 7 (Rendezvous) ← independent, can run in parallel with 5-6
    ↓
Phase 8 (FEC) ← needs Phase 2 filter extension negotiation
    ↓
Phase 9 (Bonding) ← needs Phase 2 group extension; benefits from Phase 7
    ↓
Phase 10 (Platform) ← final polish, independent
```

**Parallelizable:** Phases 7 and 8 can be developed in parallel with Phases 5-6.
Phase 3 can be incrementally expanded as new features add new metrics.

---

## Estimated Total Scope

| Phase | New LOC | Changed LOC | Key Files |
|-------|---------|-------------|-----------|
| 1. Interop | ~200 | ~600 | conn.go, config.go, dialer.go, listener.go |
| 2. Options | ~600 | ~200 | options.go, config.go, conn.go, buffer/recv.go |
| 3. Statistics | ~500 | ~100 | stats.go, conn.go |
| 4. Key Rotation | ~300 | ~100 | conn.go, crypto/crypto.go |
| 5. Message Mode | ~600 | ~200 | conn.go, buffer/recv.go |
| 6. File Mode | ~1200 | ~200 | congestion/file.go, conn.go, config.go |
| 7. Rendezvous | ~800 | ~100 | rendezvous.go, handshake/handshake.go |
| 8. FEC | ~1500 | ~200 | filter/fec.go, filter/filter.go, conn.go |
| 9. Bonding | ~2500 | ~300 | group.go, listener.go, packet/cif.go |
| 10. Platform | ~800 | ~200 | watcher.go, log.go, sockopt_*.go |
| **Total** | **~9000** | **~2200** | |

**Total estimated: ~11,200 LOC** to reach full parity with the C++ implementation's
~56,400 LOC — a ~5x reduction due to Go's standard library, garbage collection,
goroutines replacing manual thread management, and lack of C++ boilerplate.

---

## Verification Strategy

After each phase:
1. `go test ./...` — all existing + new tests pass
2. `go test -bench=. -benchmem` — no performance regression
3. `go test -race ./...` — no data races
4. `go test -fuzz=Fuzz -fuzztime=30s ./internal/packet/` — fuzz tests pass
5. Integration test against C++ `srt-live-transmit` (Phases 1, 4, 7+)
6. `golangci-lint run` — no new linter warnings
