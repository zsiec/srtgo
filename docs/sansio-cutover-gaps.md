# Pre-cutover gap audit

Exhaustive audit of the legacy public `srt.*` surface + behavior vs. the new
Sans-I/O stack (`internal/core` + `internal/session`), done before swapping the
public API. Bottom line: **the cutover is materially bigger than "swap and
delete."** It splits into (A) genuine protocol/behavior gaps that live in the new
core and would silently break real streams or the legacy test suite — these
should be closed *before or during* cutover; (B) a large public-API façade to
build — this *is* the cutover; and (C) a strategic decision about the 5,500-line
`conn_test.go`. All findings below were verified against the source.

## A. Protocol / behavior gaps in the new core (fix these — they change behavior)

These are NOT API shape; they are missing/divergent protocol behavior. Several
will break real streams or the legacy suite.

| Gap | Severity | Detail |
|-----|----------|--------|
| ~~No RTO/EXP timer + no blind retransmit~~ | **DONE** | Implemented: `TimerEXP` armed at establish, self-rearming at the RTO (`rto() = rexmitCount·(RTT+4·RTTVar+2·SYN) + 10ms`, exponential-ish backoff). When data is in flight and no ACK has *advanced* within the RTO, `handleEXP` blind-retransmits all unacked (`SendBuffer.GetAllUnacked`) and calls `sendCC.OnTimeout()`. The RTO clock resets only on ACK **progress** (`ackd>0`), not on redundant periodic ACKs — without that distinction a stalled tail keeps EXP from ever firing. Test `TestSimTailLossRecovery` (tail dropped once, never a detected gap → 0 receiver NAKs → recovered only by RTO blind-retransmit). |
| ~~No file-mode congestion control (FileCC)~~ | **DONE** | `Congestion` now flows through to `establish` (`Config`/`DialConfig`/`ListenerConfig` → `establishParams`); `Congestion=="file"` selects `congestion.NewFileCC` (window-based AIMD slow start) instead of `NewLiveCC`. The core's `window()` already honors `CongestionWindow`, so FileCC's adaptive cwnd gates the send window. Test `TestSimFileModeCongestion` (initial cwnd 16 proves FileCC vs LiveCC; lossy transfer completes in order). **Caveat / follow-up:** `FileCC` gates its rate control on a real-clock 10ms interval (`time.Now()` in `internal/congestion/file.go`), so its cwnd does not grow under virtual time and file-mode CC is not a pure function of the injected `now`. It works in production (real clock) but should move to the injected clock (thread `now` through `Controller.OnACK`) for determinism + sans-I/O purity; that touches the shared congestion package + its ~21 test call sites + the legacy caller, so it's a separate change. Also still open: file-mode should disable periodic NAK + use FileCC's ACK cadence (see "Periodic NAK" row). |
| **No auto input-rate / input-BW estimation** | MED | Legacy samples the app's write rate and feeds `MaxBW=0` (auto) streams; the core has none of `updateInputRate`/`updateAutoInputBW`. Uncapped live streams run at LiveCC's default, not the encoder rate. `InputBW`/`MinInputBW`/`OverheadBW` are all unwired. |
| ~~No reorder tolerance / LossMaxTTL~~ | **DONE** | `LossMaxTTL` (plumbed through all configs) now defers the immediate NAK for a gap within that many packets of the received frontier (`reportGap`/`deferGap`). A reordered packet that arrives cancels its deferral (`deferredLoss` map); a deferred loss that falls beyond the window is NAKed (`flushDeferredLoss`). Tolerance 0 (default) keeps the immediate-NAK behavior. Test `TestReorderTolerance` (reordering absorbed / NAKed at 0 / genuine loss still reported). Periodic NAK + EXP remain the backstop for deferred losses at a stalled frontier. |
| ~~`EnforcedEncryption=false` fallback missing~~ | **DONE** | New `AllowUnencryptedFallback` (off by default = enforce) on `DialConfig`/`ListenerConfig`. With it set, an encrypted listener accepts an unencrypted caller (and a caller that requested encryption but got no KMRSP connects in the clear) instead of rejecting; a *wrong* passphrase is still rejected. Test `TestEnforcedEncryptionFallbackUDP` (fallback connects + streams; default rejects). |
| ~~Plaintext accepted on a secured connection~~ | **DONE** | `decrypt` now rejects (counts + drops) an `EncryptionNone` data packet when `cryptoCtx != nil` — all data is encrypted once a context is negotiated. Test `TestSecuredConnDropsPlaintext`. |
| ~~No linger / SHUTDOWN-on-close~~ | **DONE** | `core.Shutdown` emits a SHUTDOWN packet; `core.PendingSend` exposes the unacked count. `Session.Close` closes gracefully on the loop goroutine — it keeps running to flush queued writes and (with `SetLinger(d)>0`) drain in-flight data until the send buffer empties or the linger deadline passes, then sends SHUTDOWN. The receiver exits on the peer's SHUTDOWN so Read drains buffered data then returns io.EOF (no idle-timeout wait). Test `TestSessionLingerShutdownUDP`. |
| ~~Wire flags hardcoded to defaults~~ | **MOSTLY DONE** | The caller's CONCLUSION now advertises computed flags (`dialState.srtFlags()`): TSBPD in live mode, Crypt when encrypted, TLPKTDROP when set, periodic NAK except file mode, byte-stream flag for stream mode. Test `TestConclusionAdvertisesFlags`. Remaining: the *listener's* response flags + acting on the *peer's* advertised flags (e.g. peerNakReport→FASTREXMIT) — but the EXP blind-retransmit already covers the lost-NAK case the peer-flag would gate. Best finished in the façade. |
| **No OS socket options** | MED | `UDPSendBufSize`/`UDPRecvBufSize`/`IPTTL`/`IPTOS`/`BindToDevice`/`IPv6Only` — the session takes a pre-built `net.PacketConn` and never applies socket controls. The host (public layer) must pre-configure the socket. |
| **Stream-mode delivery is per-packet, not byte-coalesced** | MED | The core emits each in-order packet as one `DataReceived`; legacy `Read` coalesces bytes with a partial-remainder buffer. The public `Read` wrapper must do the byte-stream assembly. |
| **Peer error / `ErrPeerError` / PEERERROR** | LOW-MED | No send/handle of the PEERERROR control packet or peer-health one-shot. File-transfer error signaling is lost. |
| ~~Periodic NAK file-mode suppressed~~ | **DONE (file mode)** | `periodicNAK` is now off in file mode (`Congestion=="file"`) — the periodic-NAK timer is neither armed nor fired; file mode relies on reactive NAK + RTO retransmit. Test `TestPeriodicNAKModeGating`. (An explicit `NAKReport=false` toggle for *live* mode is a small façade-config addition; low value.) |
| ~~Drift sampled from data timestamps, not ACKACK/keepalive~~ | **DONE** | The drift feed (`tsbpdTimer.OnACK`) was removed from the data path (a data packet's timestamp is application source time, noisy) and added to `handleACKACK` (raw round-trip from that ACKACK pair, not the smoothed EWMA) and the keepalive case (no RTT sample), matching the legacy. Time-base anchoring + wrap tracking stay on the data path. `Stats.DriftMicros` now exposes the offset (also ConnStats parity). Test `TestDriftNotSampledFromData` (>1000 skewed data packets keep drift at 0). |
| **`MaxRexmitBW` retransmit shaper** | LOW | Retransmits are unthrottled; no token bucket. |
| **HSv4 *listener* accept** | LOW | Caller-side HSv4 fallback exists; the listener rejects HSv4 callers (requires HS extension). |
| **ACK/NAK out-of-range validation** | LOW | Legacy closes on an ACK/NAK referencing an unsent seq; the core doesn't validate (hardening). |

## B. Public-API façade to build — this *is* the cutover

The new stack consumes only `core.*Config` + pre-built `net.PacketConn`s and
exposes a narrow session API. The public `srt.*` surface the tests/consumers
expect is much larger. Ordered by effort/test-impact:

1. **Socket options (~60 tests).** `Conn.GetOption`/`SetOption` + the ~51-value
   `SockOpt` enum with read-only/type/range/pre-connect error contracts. The new
   stack has *none* of this (config is struct fields only); only `SndSyn`/`RcvSyn`
   are covered (via `SetReadBlocking`/`SetWriteBlocking`). Read-side values mostly
   exist in `core.Stats`/config; write-side needs runtime setters on the loop
   (MaxBW, InputBW, OverheadBW, Linger, SndDropDelay, LossMaxTTL).
2. **`ConnStats` parity (~50 tests).** Public `ConnStats` is ~80 fields with a
   `clear` (interval-vs-total) mode, `OnStats(interval, fn)` callback, and
   `ExtendedStats` (IIR buffer averages). `core.Stats` is ~45 packet-only counters
   with different names and **no** byte-with-header totals, Mbps rates, ms-buffer
   timings, reorder, belated, or FEC-filter-breakdown fields, and no clear/interval
   semantics. Needs a mapping + aggregation shim (host owns the wall clock).
3. **`srt.Group` public API (~90 tests).** Bonding *works* in `session.Group`
   (broadcast + backup, dial + `AcceptGroup`), but the public surface is missing:
   `Members()`/`MemberInfo`, `Stats()`/`GroupStats`, `Mode`/`GroupID`/`RTT`/
   `SetStabilityTimeout`, `Connect`/`AddConn(token,weight)`/`AddPendingConn`, and
   the `MemberStatus`/`BackupState` enums + `String()`s the unit tests assert.
4. **Listener accept/gating model.** No `SetAcceptFunc`/`SetAcceptRejectFunc`,
   `ConnRequest`, or the full `RejectReason` set; the core listener accepts
   unconditionally with three reject codes. This **blocks `srt.Server` and
   StreamID-based authorization**, and the MinVersion/message-mode/congestion/
   GroupConnect gating + reject codes.
5. **`srt.Server` (~25 tests).** A thin framework over Listener + accept callback;
   pure wrapper, but blocked on (4) and addr-string `Listen`.
6. **`srt.Watcher` (~35 tests).** Readiness/event multiplexer. Needs `Session` to
   expose read/write-ready + done/error signals (today it's blocking + deadline +
   `SetReadBlocking` only).
7. **Public `Config` façade.** `srt.Config` (~40 knobs) + `validate()`/defaulting +
   the `srtFlags()`/`tsbpdEnabled()`/... derivation helpers, mapping onto the three
   internal configs. Pervasive — every public constructor needs it.
8. **Top-level constructors.** `Dial(addr, Config)`, `Listen(addr, Config)`,
   `DialRendezvous(local, remote, Config)` + the `PacketConn` variants: addr-string
   resolution, `listenUDP` (with the OS socket options from A), and `Config →
   core.*Config` translation.
9. **`srt.Conn` method wrappers.** `Read`/`Write` restored to `(int, error)`;
   `WriteMessage`/`ReadMessage`/`WriteMsgCtrl`/`ReadMsgCtrl` + public `MsgCtrl`
   (`time.Time`/`time.Duration` ⇄ `core.MsgOptions`/`MsgMetadata`); accessors
   `StreamID`/`SocketID`/`PeerGroupID`/`SetMaxBW`/`SendRate`; deadline error-shape
   parity (`net.OpError`).
10. **`ParseStreamID`/`StreamIDInfo`** — pure helper, relocate verbatim (its
    *use* — accept-time gating — depends on (4)).

## C. The strategic decision: `conn_test.go` (~5,500 lines)

`conn_test.go` and `group_test.go` build `*srt.Conn` directly via internal
constructors (`newConn(ConnConfig{...})`, `testConnPair`, `newTestConn`) and poke
unexported fields/methods. They cannot run unmodified unless the cutover keeps a
`srt.Conn` that is **constructible and shaped the same way** (delegating
internally to session/core). Choices:
- **(i) Preserve `srt.Conn` shape** so the legacy suite runs as-is to drive parity
  — maximizes confidence, but constrains the public type to the legacy struct/
  constructor shape.
- **(ii) Rewrite the tests** against the new API — cleaner long-term, but loses the
  154KB of behavioral coverage as a parity oracle during the riskiest step.

This choice should be made before starting the cutover, because it dictates the
shape of the public `srt.Conn`.

## What's already fine — or better than legacy

- net.Conn data plane (Read/Write/Close/LocalAddr/RemoteAddr/all deadlines),
  blocking modes, `ErrTimeout`/`ErrWouldBlock`.
- `ReadMsg` returns **real** per-message metadata (Boundary/MsgNo/Seq); legacy
  `ReadMsgCtrl` stubbed it to zeros.
- KM state (`SndKmState`/`RcvKmState`) and the core encryption/key-rotation path
  (CTR + GCM) are present; FEC works (incl. encrypted).
- Listener-side `AcceptGroup` is arguably cleaner than legacy app-side assembly.
- Handshake rejection codes (RejRogue/RejBadSecret/RejUnsecure) + typed
  `RejectError` exist; the gating *callbacks* are what's missing.

## Recommended sequence

1. **Close the HIGH/MED protocol gaps in the core first** (RTO/EXP + blind
   retransmit, FileCC + input-rate, reorder tolerance, enforced-encryption
   fallback, plaintext-drop, linger/SHUTDOWN, wire flags). These are behavior, not
   API, and the legacy suite will fail without them regardless of the façade.
2. **Decide C** (preserve `srt.Conn` shape vs. rewrite tests).
3. **Build the façade B** incrementally (Config translation + constructors →
   Conn wrappers + Stats mapping → socket options → accept callbacks → Server/
   Group public API → Watcher), running the legacy suite as the parity oracle.
4. **Delete legacy internals last**, once the suite is green against the new stack.
