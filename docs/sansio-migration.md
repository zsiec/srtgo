# Sans‑I/O migration plan

Status: **in progress** (branch `sansio-migration`). This document is the backbone for a
multi‑session refactor. Each phase ends with `make test` green so the migration can pause and
resume safely.

## Goal

Refactor the Go SRT implementation so its protocol logic lives in a pure, deterministic core —
no sockets, no goroutines, no real clock — matching the Sans‑I/O architecture already used in the
sibling implementations:

- `~/dev/ristrust` (Rust RIST)
- `~/dev/ristgo`  (Go RIST)   ← closest *language* reference
- `~/dev/srtrust` (Rust SRT)  ← closest *protocol* reference (near line‑for‑line template)

All three converge on the quinn/quiche "pull‑based" pattern. We replicate it here.

## The shared pattern

```
┌──────────────────────────────┐     inputs (time passed IN):
│  PURE CORE  (internal/core)  │       HandlePacket(now, pkt)
│  - no net, no time, no goroutines    HandleTimer(now, id)
│  - deterministic function of inputs  Write(now, payload)
└───────────┬──────────────────┘     outputs (pulled OUT):
            │                           PollOutput() -> SendPacket | SetTimer | ClearTimer
            │                           PollEvent()  -> Connected | DataReceived | Failed | Closed | KeyRefreshNeeded
            ▼
┌──────────────────────────────┐
│  I/O HOST  (internal/session)│  owns mux/socket + time.Timer + goroutines.
│  reads the real clock ONCE    │  Feeds the core, drains its queues, arms timers, executes sends.
│  per loop iteration           │
└──────────────────────────────┘
            ▲
            │  thin wrappers, public API unchanged (net.Conn semantics)
┌──────────────────────────────┐
│  PUBLIC API (srt.Conn, etc.) │  Read/Write/Close/Stats — byte‑for‑byte compatible.
└──────────────────────────────┘
```

The reference for the exact loop is `~/dev/srtrust/crates/srt/src/driver.rs` and
`~/dev/ristgo/internal/session/session.go` (`loop()` + `drain()`).

## Purity invariant (the gate)

The core is "Sans‑I/O" by **source discipline**, enforced mechanically:

- Source files under `internal/core/` (excluding `_test.go`) may **not** directly import `net` or
  `time`. Durations/timestamps use `internal/clock` value types (`clock.Timestamp`,
  `clock.Microseconds`); destination addresses are attached by the host.
- No `go` statements, no `time.Now/NewTimer/NewTicker/After`, no socket reads/writes in the core.

Enforced by `scripts/check-sansio.sh` and `TestNoForbiddenImports` (see `internal/core/gate_test.go`),
both wired into `make test` / `make sansio-check`. (Note: a `go list -deps` gate is *not* used —
`clock`/`packet` legitimately pull `time`/`net` transitively for their value types, exactly as in
ristgo's `flow` package.)

## Target package layout

```
internal/core/          NEW — pure state machines
   doc.go               package doc + invariant
   timer.go             TimerID enum (+ String)
   output.go            Output sealed iface: SendPacket | SetTimer | ClearTimer
   event.go             Event sealed iface: Connected | DataReceived | Failed | Closed | KeyRefreshNeeded
   conn.go              Connection state machine (the decision logic from the root conn.go)
   listener.go          Listener state machine (stateless SYN-cookie induction)
   gate_test.go         purity gate
internal/session/       NEW — I/O host: event loop, owns mux + time.Timer + goroutines
internal/clock          reuse as-is (value types + Real/Mock clock)
internal/packet         reuse as-is (pure marshal/parse; Header.Addr is a value)
internal/handshake      reuse as-is (pure; note: imports net only for net.Addr cookie input)
internal/{seq,buffer,congestion,tsbpd,crypto,filter}   reuse as-is (already pure algorithms)
internal/mux            stays in the I/O layer (owned by session)
conn.go / listener.go / dialer.go / rendezvous.go / group.go (root)   thin wrappers over session
```

## Core API (target)

```go
// Construction
func Dial(cfg Config, now clock.Timestamp, rng func([]byte)) *Conn          // caller; queues induction
func Accept(cfg Config, hs *handshake.Handshake, now clock.Timestamp) (*Conn, error) // from listener

// Inputs — every entry point takes `now`; the core never reads a clock.
func (c *Conn) HandlePacket(now clock.Timestamp, p packet.Packet)
func (c *Conn) HandleTimer(now clock.Timestamp, id TimerID)
func (c *Conn) Write(now clock.Timestamp, payload []byte) (int, error)       // enqueue app payload
func (c *Conn) CloseGraceful(now clock.Timestamp)

// Outputs — pulled by the host until empty.
func (c *Conn) PollOutput() (Output, bool)   // datagrams to send, timers to arm/clear
func (c *Conn) PollEvent()  (Event, bool)    // application-visible events
```

### Outputs

| Output       | Meaning                                                       |
|--------------|--------------------------------------------------------------|
| `SendPacket` | transmit this `packet.Packet` to the peer (host fills Addr)  |
| `SetTimer`   | arm/re-arm timer `ID` to fire at `Deadline` (clock.Timestamp)|
| `ClearTimer` | cancel timer `ID`                                            |

### Events

| Event              | Meaning                                              |
|--------------------|------------------------------------------------------|
| `Connected`        | handshake complete (negotiated params)               |
| `DataReceived`     | one in-order payload ready for Read                  |
| `Failed`           | handshake timeout / crypto mismatch / fatal error    |
| `Closed`           | peer sent SHUTDOWN                                    |
| `KeyRefreshNeeded` | key rotation due; host supplies new key material     |

### Timers (mirror of `srtrust` `TimerId`)

`Handshake, ACK, NAK, EXP (RTO), TSBPD, SndPacing, Linger, Keepalive, PeerIdle`.

These replace the root `conn.go` `timerLoop` 10ms ticker. The host keeps a `map[TimerID]clock.Timestamp`
and arms a single real `time.Timer` for the earliest deadline.

## What changes in the existing code

The current root `conn.go` (~2,940 lines) is split:

- **Decision logic → `internal/core/conn.go`**: `handlePacket`/`handleControlPacket`/`handleDataPacket`,
  ACK/NAK/ACKACK generation, retransmit selection, TSBPD scheduling, KM rotation, drop logic.
  Inline `c.m.Send(p)` calls become `c.outputs.push(SendPacket{p})`. Periodic work moves from the
  ticker into `HandleTimer` cases that re-arm via `SetTimer`.
- **Goroutines/socket/ticker → `internal/session`**: `recvLoop`, `timerLoop`, the `time.Ticker`,
  `mux` ownership, `readReady`/`writeReady` signaling, deadlines.
- **Atomics collapse to plain fields**: nearly every `atomic.*` in the `Conn` struct exists only
  because two goroutines touch it. The single-threaded core uses plain fields. Stats are surfaced
  to callers via a snapshot command through the loop (see ristgo `Stats()` / srtrust `stats()`).

## Phase plan

Each phase keeps the public API and `make test` green.

- **Phase 0 — scaffolding. ✅ DONE.** `internal/core` with `timer.go`, `output.go`, `event.go`,
  `doc.go`, `fifo.go`, and the purity gate (`gate_test.go` + `scripts/check-sansio.sh` +
  `make sansio-check`). No behavior change.
- **Phase 1 — vertical data path. 🚧 IN PROGRESS.**
  - ✅ `core.Conn` (`internal/core/conn.go`): established-connection engine — data send with pacing
    + flow control, in-order delivery, immediate + periodic NAK, retransmission, Full/Lite ACK,
    ACKACK-based RTT. Pure: no net/time/goroutines (gate-enforced).
  - ✅ `conn_sim_test.go`: deterministic two-core loss-recovery simulation over an in-memory lossy
    link in virtual time (400 payloads, 5 dropped seqnos recovered, in-order). No sockets.
  - ✅ **Perf canary answered** (`bench_test.go`, Apple M1 Pro): the Sans-I/O boundary's marginal
    cost is **1 alloc / ~112 B / ~32 ns per outgoing packet** from boxing the effect into the
    `Output` interface (`BenchmarkOutputBoxingInterface` 1 alloc vs `BenchmarkOutputUnion` 0 alloc).
    Full send path `BenchmarkCoreSendPath`: 408 ns/op, 3 allocs/op (upper bound — this micro-driver
    never ACKs, so pooled packet buffers don't recycle; with ACK feedback they Release back to the
    pool). Conclusion: negligible at live bitrates; removable via the tagged-union lever if ever
    needed. Decision: **proceed with the sealed-interface design.**
  - ✅ Token-bucket pacing in the core: a late `TimerSndPacing` fire sends a catch-up burst, so
    throughput isn't capped by OS timer resolution (the same idea as the repo's WASM burst-pacing).
  - ✅ `internal/session` driver (`session.go`): the I/O host — owns the mux, real clock, timer
    wheel (`map[TimerID]Timestamp` + one `time.Timer`), and the single event loop. Two goroutines
    per connection (mux read loop + event loop) vs three in the legacy design. `Write`/`Read`/`Close`
    public surface.
  - ✅ `session_test.go`: `TestSessionUDPLoopback` (500 payloads over real loopback UDP, in order)
    and `TestSessionUDPLossRecovery` (drops data packets on the socket; NAK/retransmit recovers all
    600). Both pass under `-race`.
  - ✅ TSBPD playout (`TimerTSBPD`): live-mode delivery holds each packet until its
    `timeBase + timestamp + delay` instant and drops empty head slots that become too late
    (relative to the next available packet across a gap). Time base is anchored from the first
    received packet; drift correction stays disabled until Phase 4. Added one additive helper
    `RecvBuffer.PeekNextAvailableTimestamp` for precise wake-up scheduling. Tests `TestTSBPDPlayout`
    (exact arrival+delay timing) and `TestTSBPDTooLateDrop`.
  - ⬜ TODO: wire the public `Conn` to delegate to a session driving a `core.Conn`; prove against
    `e2e_test.go` / `conn_test.go`; head-to-head `make bench` vs the current implementation.
- **Phase 2 — handshake & dialer. 🚧 caller HSv5 done.**
  - ✅ `core.Dial` (`internal/core/handshake.go`): caller-side HSv5 state machine — INDUCTION →
    CONCLUSION → `Connected`, retransmitting via `TimerHandshake`, surfacing `Failed` on error.
    Reuses the pure `handshake.Build*` builders (passing `addr=nil` keeps the core net-free; PeerIP
    is 0.0.0.0 and the host fills the destination). Shared `establish()` brings the connection into
    the data path from negotiated params.
  - ✅ `session.Dial`: generates the socket ID/ISN, drives the handshake, blocks until `Connected`
    (or timeout), returns a ready Session.
  - ✅ **Interop proven**: `TestInteropCallerToLegacyListener` — the new caller completes a real
    HSv5 handshake against the existing `srt.Listen` listener over UDP and streams 300 payloads it
    receives in order. Confirms wire compatibility of both handshake and data path.
  - ⬜ TODO: HSv4 fallback; rejection-code handling; populate `Connected` with full negotiated params.
- **Phase 3 — crypto & key rotation. 🚧 encrypted data path done.**
  - ✅ Encrypted data path in the core: `encrypt`/`decrypt` helpers (AES-CTR + AES-GCM code paths),
    encrypting *before* the send buffer so retransmissions resend identical ciphertext. The caller
    wraps its session key into the CONCLUSION KMREQ (`MarshalKM`); `Config`/`DialConfig` carry the
    crypto context (the host owns the entropy — `session.Dial` builds it — keeping the core
    deterministic). Conclusion fails on encryption mismatch (requested KM, none returned).
  - ✅ Proven both directions: `TestInteropEncryptedCallerToLegacyListener` (new caller's encrypt
    interops with the legacy listener over UDP, 300 AES-CTR payloads) and
    `TestSimEncryptedLossRecovery` (two cores share a context; encrypt+decrypt+retransmit recovery
    in virtual time).
  - ✅ Mid-stream key rotation (`internal/core/keyrotation.go`): driven by the encrypted-send count,
    the sender pre-announces the next-slot SEK via KMREQ (`GenerateSEK` on the host-created context —
    same entropy ownership as the initial keys), retries on `TimerKMRefresh` (1.5×RTT, capped) until
    the peer echoes a KMRSP, switches the active even/odd slot at the refresh boundary, then
    decommissions the old key (`ClearSEK`) a pre-announce window later. The receiver installs the
    announced key (`UnmarshalKM`) and echoes the KMRSP; a bad/absent secret returns an error KMRSP.
    KM state + sent/recv KM counts are in `core.Stats`. Encrypt-before-buffer means CTR/GCM retransmits
    resend stored ciphertext, so clearing the old SEK is safe. Test `TestNewStackKeyRotation` (300
    AES-CTR payloads over real UDP, ~12 rotations, every payload decrypts, 0 undecrypt).
  - ✅ AES-GCM end-to-end through the new stack: the listener now adopts the caller's cipher mode from
    its KMREQ (`hs.SRTKM.Cipher`) instead of hardcoding CTR — the crypto-context factory
    (`NewListener`'s `newCtx`) takes a `crypto.CipherMode`. Tests `TestNewStackEncryptedGCM` (GCM data
    path, 0 undecrypt) and `TestNewStackKeyRotationGCM` (GCM rotation under a low refresh rate).
  - ⬜ TODO: `KeyRefreshNeeded` host-entropy variant (current design keeps SEK generation in the
    crypto context, consistent with how the initial keys are made).
- **Phase 4 — TSBPD drift, FEC, stats. 🚧 drift + stats done.**
  - ✅ TSBPD drift correction enabled (the SRT default): `handleData` feeds `tsbpdTimer.OnACK` a
    drift sample per data arrival with the current RTT for one-way-delay compensation; the time base
    nudges ±5ms per 1000 samples. Exact-timing TSBPD tests still pass (no jitter → ~0 drift).
  - ✅ `core.Stats` snapshot (sent/recv packets+bytes, retrans, loss, drops, undecrypt, ACK/NAK
    counts, RTT/var, in-flight) surfaced through the loop via `Session.Stats()` (answered on the
    loop goroutine — no atomics). `TestStats` checks both ends.
  - ✅ FEC (`internal/filter`) integrated: the core feeds source packets to `FECSender` and emits
    repair packets (msgNo 0), routes incoming repair packets to `FECReceiver`, inserts recovered
    packets, and gates its own NAK by the ARQ level. Negotiated via the handshake filter extension
    (caller/listener `FilterConfig`). 1D (row) and 2D (row+column, staircase + even) all work
    end-to-end. Tests: `TestSimFECRecovery`, `TestSimFEC2DNoLoss`, `TestSimFEC2DRecovery`,
    `TestNewStackFEC`.
  - ✅ Encrypted FEC (the former deferred edge): the receiver now feeds the FEC engine the captured
    on-wire **ciphertext** of source packets (before in-place decryption) so it combines with the
    repair packets the sender computed over ciphertext; recovered packets carry the reconstructed
    encryption flag and are decrypted on insert. Test `TestSimEncryptedFECRecovery` (AES-CTR + row FEC,
    arq:never, every dropped packet recovered and decrypted, 0 undecrypt, 0 NAK).
  - ✅ **Fixed a pre-existing latent bug in `internal/filter`** (shared by the legacy code): staircase
    column (2D) FEC mis-mapped a column's series, poisoning the wrong column group and producing
    corrupt/spurious recoveries in no-loss 2D streams. The receiver now measures a column's series
    from its own staircase base offset. Regression-guarded by `fec_staircase_test.go`.
  - ✅ Delivery-rate / bandwidth stats fields (`PacketRecvRate`, `EstimatedBandwidth`,
    `PktSndPeriodMicros`) surfaced from the congestion controller (see the fuller-stats item below).
- **Handshake rejection codes. ✅** The listener rejects bad/unauthorized CONCLUSIONs with the
  proper SRT code (missing/old HSREQ → RejRogue; wrong passphrase → RejBadSecret; encryption
  required/unexpected → RejUnsecure) via an HSv5 rejection handshake; the caller surfaces it as a
  typed `core.RejectError{Code}` (and treats a SHUTDOWN during handshake as a refusal). Tests:
  `TestRejectWrongPassphrase`, `TestRejectEncryptionRequired`, `TestRejectUnexpectedEncryption`.

- **Phase 5 — listener & rendezvous. 🚧 listener + rendezvous done (unencrypted).**
  - ✅ `core.Listener` (`internal/core/listener.go`): stateless SYN-cookie induction (cookie =
    keyed hash of an opaque `PeerID`, keeping the core net-free — the host maps PeerID↔addr),
    CONCLUSION verify + accept, duplicate-CONCLUSION resend, `Accepted` event carrying a ready
    `*Conn`. Entropy (cookie secret, socket IDs, ISNs) is injected by the host. Outputs are
    `SendTo{Peer, Packet}` so responses target specific peers.
  - ✅ `session.Listen` / `Listener.Accept`: owns the mux, routes handshakes from `mux.Handshake`,
    registers each accepted socket ID, and returns a driven per-connection Session.
  - ✅ **Compatibility loop closed**: `TestInteropLegacyCallerToNewListener` (legacy `srt.Dial` →
    new listener) plus `TestNewStackEndToEnd` (new caller → new listener — the entire rebuilt stack,
    no legacy code in the path). All under `-race`.
  - ✅ Listener-side key material: the listener unwraps an encrypted caller's KMREQ (host injects a
    crypto-context factory; `UnmarshalKM` overwrites the random keys, so it's deterministic from the
    KMREQ + passphrase) and echoes a KMRSP. Proven by `TestNewStackEncryptedEndToEnd` (new↔new,
    AES-CTR) and `TestInteropLegacyEncryptedCallerToNewListener` (legacy encrypted caller → new
    listener). Encryption matrix now green in all directions.
  - ✅ Rendezvous (simultaneous-open) handshake, unencrypted (`internal/core/rendezvous.go`):
    `core.DialRendezvous` emits a WAVEHAND, a cookie contest (`rdvCookieContest`) assigns
    INITIATOR/RESPONDER, and a pure transition table (`rdvSwitchState`, ported from the legacy driver)
    drives WAVEHAND → CONCLUSION(HSREQ/HSRSP) → AGREEMENT to the shared `establish()`. `session.DialRendezvous`
    generates the entropy (socket ID/ISN/cookie) and merges the mux Handshake channel (peer WAVEHANDs,
    dest 0) with the registered socket channel. Tests: `TestSimRendezvous` (two cores, both connect +
    bidirectional data), `TestRdvCookieContestAntisymmetric`, `TestSessionRendezvousUDP` (real UDP,
    both peers dial at once + stream).
  - ⬜ TODO: encrypted rendezvous (KMREQ as initiator / KMRSP as responder); deferred-accept /
    stream-ID gating; lost-AGREEMENT robustness (matches legacy: responder retransmits until timeout).
- **Phase 6 — groups/bonding. 🚧 broadcast done.** SRT bonding is N full, independent connections
  (each its own handshake/ARQ/ACK/TSBPD/crypto) coordinated to share a sequence space and source
  timestamps, with dedup-by-sequence at delivery — an orchestration layer over multiple `core.Conn`s
  (matching how ristgo puts bonding in the host, not the pure flow). Unlike RIST 2022-7 (one flow,
  shared ring, dedup by `(seq,sourceTime)`).
  - ✅ `core.Group` (broadcast, `internal/core/group.go`): assigns a shared send sequence + source
    timestamp per payload and writes it on every member (`Conn.WriteCoordinated`); on receive,
    forwards each member's deliveries through a wrap-aware dedup waterline so each packet is
    delivered once from whichever link supplies it first. `DataReceived` now carries `Seq` for dedup.
  - ✅ `TestSimBroadcastBonding`: two links each *permanently* dropping a disjoint packet set; the
    receiver group still delivers all 300 payloads once, in order — seamless redundancy, no shared
    loss. Deterministic, no sockets.
  - ✅ Backup mode: weighted active/standby with failover. Per-member health is tracked from ACK
    progress (the send buffer advancing) against a dynamic stability timeout (`max(min, 2*RTT+4*RTTVar)`);
    when no healthy active member remains, the highest-weight standby is activated and the sender
    buffer is replayed onto it. The receiver side advances standby links to the active link's
    *receive* progress (ACK sequence, not playout waterline) so they accept failover packets without
    a spurious gap. `Conn.resetRecvTo` re-anchors a standby receiver. `Group.Monitor` re-qualifies
    health on a timer so failover fires during send pauses too.
  - ✅ `TestSimBackupFailover`: streams 200 payloads over a weighted backup group, kills the active
    link mid-stream (100 payloads written *after* the kill — deliverable only via failover), and the
    group delivers all 200 in order. Seamless failover, no data loss, deterministic.
  - ✅ Bonding session host (`internal/session/group.go`): owns one socket per member and drives a
    `core.Group` + all member `core.Conn`s from a single event loop (per-member reader goroutines
    fan into the loop; a unified timer wheel keyed by member+TimerID plus a group monitor).
    `NewEstablishedGroup`/`Write`/`Read`/`Close`. Real-UDP tests: `TestGroupBroadcastUDP` (one link
    permanently lossy → redundancy delivers all 400) and `TestGroupBackupUDP` (active link killed
    mid-stream → failover delivers all 300). Both green under `-race`, repeatably.
  - ✅ Two robustness fixes the session host surfaced: (1) **group TSBPD time-base sync** — all
    receiver members adopt one reference (`Group.syncTimebases` via `tsbpd.ApplyGroupTime`) so they
    play out each sequence in lockstep; (2) **group reorder buffer** — members deliver their own
    streams in order and the group merges them in sequence order, buffering out-of-merge-order
    deliveries and skipping a gap only once it is lost on every link (a bare waterline dropped a
    slower link's copy of a packet the faster link skipped when playout deadlines coalesced).
  - ⬜ TODO: group handshake extension / member discovery (needed for cutover & interop, and for
    handshake-based group dialing); balancing; sender-buffer prune refinement; idle/keepalive
    stability handling.
- **Phase 7 — cleanup.** Delete dead atomics/channels from the root files; deterministic seed-replay
  loss/jitter simulator test (template: ristgo `internal/simtest`).

## Public-API parity (the cutover gate)

The legacy public `srt.*` surface the new stack must eventually match: `Conn` (40+ methods —
net.Conn, message mode, `Stats`, 60+ socket options, group coordination), `Config` (~90 fields),
`ConnStats` (~60 fields), `Listener`/`ConnRequest`/deferred accept, `Server`, public `Group`,
`Watcher`, `MsgCtrl`, rejection codes. Tracked here as parity items are built on `internal/session`.

- ✅ net.Conn deadlines + non-blocking I/O on `session.Session`: `SetReadDeadline`/`SetWriteDeadline`/
  `SetDeadline` (zero clears), `SetReadBlocking`/`SetWriteBlocking` (SRTO_RCVSYN/SNDSYN); Read/Write
  return `ErrTimeout` (a `net.Error` with `Timeout()==true`) on deadline and `ErrWouldBlock` when
  non-blocking with nothing ready. Test `TestSessionReadDeadlineNonBlocking`.
- ✅ message-mode framing (`Config.Message` / SRTO_MESSAGEAPI). Send: `core.WriteMsg(now, payload,
  MsgOptions{SrcTime, InOrder})` and `session.WriteMsg(p, opts)` — a payload larger than one packet
  is fragmented into PB_FIRST..PB_LAST sharing one message number (all fragments share one pinned
  source timestamp); `SrcTime` overrides the wire timestamp, `InOrder` sets the Order bit. Receive:
  the core reassembles each complete message (via `RecvBuffer.ReadMessage`, in order or — for a clear
  Order bit — out of order) and surfaces it as one `DataReceived{Seq, MsgNo, Boundary}`; `session.ReadMsg(b)`
  returns `(n, MsgMetadata{Boundary, MsgNo, Seq})` — the read half of `ReadMsgCtrl`. Live mode still
  frames one packet per Write (TSBPD playout, never fragments here); stream mode (`!Live && !Message`)
  is unchanged. Tests: `TestSimMessageMode`, `TestWriteMsgSrcTime`, `TestWriteMsgInOrderBit` (core);
  `TestSessionMessageModeUDP` (session, real UDP + ARQ recovery of a dropped fragment). No send-path
  perf regression (`BenchmarkCoreSendPath` still 3 allocs/op).
- ✅ TLPKTDROP + per-message **TTL** (completes MsgCtrl). Sender side (`core.checkSendDrop` /
  `SendBuffer.DropTooLateSend`): abandons the contiguous run of head packets older than the drop
  threshold (live `Config.TLPktDrop`, threshold `max(TsbpdDelay,1s)+20ms + SndDropDelay`) **or** past
  their per-message TTL (`MsgOptions.TTL`, enforced independently of TLPktDrop), and emits a `DROPREQ`
  (`packet.CIFDropReq`) for the abandoned range; freeing the flow-control window. Driven from `pump`
  (Write/pacing) and a gated `TimerACK` heartbeat (so a fully-stalled sender still drops). Receiver
  side (`core.handleDropReq`): `RecvBuffer.Drop` skips the range, advancing the ACK point, dropping it
  from the loss list (stops spurious NAKs), and unblocking delivery behind the gap. Stats gain
  `SentDropped`/`SentDroppedBytes`. **Note:** wiring `DropTooLateSend`/TTL is also a latent fix —
  legacy `SendBuffer.DropExpiredTTL` was never called, so `MsgTTL` was a no-op there. Tests:
  `TestSendBufferDropTooLateSend*` (buffer), `TestSenderDropTLPKTDrop` + `TestSimMessageTTL` (core),
  `TestSessionMessageTTLUDP` (session, real UDP). Send path still 3 allocs/op (drop check is gated).
- ✅ Fuller stats (`core.Stats`, surfaced unchanged through `session.Stats`). Added unique
  packet/byte counts (sent/recv minus retransmits), received-retransmit counters, sender loss count
  (`LostPackets`, from received NAKs), ACKACK counters (sent/recv), and a live-level snapshot:
  flow window, effective congestion window, send/recv buffer occupancy + free slots, CC-estimated
  packet-receive rate / link bandwidth / inter-packet send period, and negotiated TSBPD latency.
  Test `TestStats` (extended). Still deferred (host-clock or unbuilt subsystems): wall-clock Mbps
  rates, total-with-header byte tallies, belated-arrival counters, KM state, reorder distance, and
  buffer time-span (MsSndBuf/MsRcvBuf).
- ✅ Liveness: dead-peer detection + keepalive (`Config.PeerIdleTimeout`, SRTO_PEERIDLETIMEO; 0 =
  off). Any received packet refreshes `lastRecvTime`; `TimerPeerIdle` fires a `Failed{ErrPeerIdle}`
  when nothing arrives within the timeout, and the session loop tears down so a blocked Read/Write
  returns instead of hanging. `TimerKeepalive` sends a KEEPALIVE when no data has been sent for 1s so
  an idle-but-alive connection stays up. Tests `TestPeerIdleTimeout`, `TestPeerIdleResetByPacket`,
  `TestIdleKeepalive` (core), `TestSessionPeerIdleUnblocksRead` (session, real UDP).
- ⬜ remaining parity: socket options (Get/Set); public `Conn`/`Listener`/`Server`/`Group` wrappers;
  `ConnRequest`/deferred accept; `Watcher`; then the public-API cutover.

## Open questions (resolve as phases land)

1. **Addressing in outputs.** `SendPacket` leaves `Header.Addr` nil; the host fills the peer addr.
   The *listener* core (Phase 5) needs per-response destinations — introduce an opaque address handle
   then, to keep `net` out of the core.
2. **Buffer ownership / pooling.** Today `mux.Send` pools marshal buffers. Decide whether the core
   emits `packet.Packet` (host marshals, keeps pooling) — current plan — vs. pre-marshalled bytes.
3. **Stats snapshot.** Mirror ristgo: a `Stats()` command handled in the loop returns a copy of the
   core's plain-field counters; no atomics.
4. **WASM.** Sans‑I/O should *simplify* the `*_js.go` burst-pacing path (no per-packet sleep); revisit
   in Phase 1/4.
