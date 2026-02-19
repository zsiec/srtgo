# SRT Performance Benchmark Results

**Date**: 2026-02-19
**Platform**: Apple M1 Pro (arm64), macOS Darwin 25.2.0
**Go**: 1.24.3 (srtgo) | **C++**: libsrt 1.5.4 (Homebrew)
**Test duration**: 10s per test, localhost `127.0.0.1`
**Config**: MaxBW=1 Gbps, Latency=120 ms, FC=25600, no encryption

## Methodology

Both Go and C++ use **purpose-built benchmark tools** with identical methodology:
- In-memory data generation (no pipe/relay overhead)
- Tight `srt_send`/`srt_recv` loop with the same SRT config
- JSON output with throughput, RTT, loss, retransmits, drops
- CPU/RSS measured via `/usr/bin/time -l` on both sides

The C benchmark (`cbench.c`) links directly against libsrt with the same
configuration as the Go tool. Both tools use MaxBW=1 Gbps, Latency=120 ms,
FC=25600, and 8192-slot send/recv buffers.

## Test Matrix

| # | Test | Description |
|---|------|-------------|
| 1 | Go loopback | Both sides in one process (quick smoke test) |
| 2 | Go separate | Sender + receiver as separate OS processes |
| 3 | C++ separate | Sender + receiver as separate OS processes |
| 4 | Go -> C++ | Go sender to C++ receiver (isolates Go sender) |
| 5 | C++ -> Go | C++ sender to Go receiver (isolates Go receiver) |

---

## 1. Throughput

### Live Mode

| Test | Throughput | RTT | Loss | Retransmits | Drops |
|------|----------:|-----:|-----:|------------:|------:|
| Go loopback | 85.6 Mbps | 0.69 ms | 3.39% | 2,753 | 88 |
| **Go separate** | **97.5 Mbps** | 0.32 ms | 0.00% | 2 | 87 |
| **C++ separate** | **1,056.4 Mbps** | 0.04 ms | 0.00% | 0 | 0 |
| Go -> C++ | 103.2 Mbps | 0.28 ms | 23.8% | 0 | 26,273 |
| C++ -> Go | 1,013.1 Mbps | 0.15 ms | 0.26% | 0 | 2,485 |

**Go is 10.8x slower than C++ in live mode (separate-process comparison).**

### File Mode

| Test | Throughput | RTT | Loss | Retransmits |
|------|----------:|-----:|-----:|------------:|
| Go loopback | 491.9 Mbps | 0.40 ms | 0.00% | 0 |
| **Go separate** | **778.1 Mbps** | 0.16 ms | 0.00% | 23 |
| **C++ separate** | **908.2 Mbps** | 0.18 ms | 0.00% | 31 |
| Go -> C++ | 529.4 Mbps | 0.06 ms | 0.00% | 0 |
| C++ -> Go | 688.7 Mbps | 0.09 ms | 0.00% | 0 |

**Go is 1.17x slower than C++ in file mode (separate-process comparison).**

File mode is nearly competitive — the Go implementation achieves 86% of C++
throughput.

---

## 2. Resource Usage

### Live Mode (sender + receiver combined)

| Test | CPU user | CPU sys | CPU total | RSS (peak) |
|------|--------:|-------:|----------:|-----------:|
| Go loopback | 0.56s | 1.73s | **2.29s** | 31.3 MB |
| Go separate | 0.78s | 1.89s | **2.67s** | 30.3 MB |
| C++ separate | 2.00s | 9.41s | **11.41s** | 17.9 MB |
| Go -> C++ | 0.21s | 0.88s | **1.09s** | 17.2 MB |
| C++ -> Go | 5.02s | 8.42s | **13.44s** | 36.3 MB |

### File Mode

| Test | CPU user | CPU sys | CPU total | RSS (peak) |
|------|--------:|-------:|----------:|-----------:|
| Go loopback | 3.55s | 8.77s | **12.32s** | 17.0 MB |
| Go separate | 5.48s | 15.28s | **20.76s** | 12.8 MB |
| C++ separate | 2.35s | 9.87s | **12.22s** | 16.0 MB |
| Go -> C++ | 1.83s | 5.69s | **7.52s** | 11.4 MB |
| C++ -> Go | 3.64s | 6.49s | **10.13s** | 12.0 MB |

---

## 3. CPU Efficiency (normalized)

| Test | Throughput | CPU / 10s | CPU-seconds per Gbps |
|------|----------:|----------:|---------------------:|
| Go separate (live) | 97.5 Mbps | 2.67s | **27.4** |
| C++ separate (live) | 1,056.4 Mbps | 11.41s | **10.8** |
| Go separate (file) | 778.1 Mbps | 20.76s | **26.7** |
| C++ separate (file) | 908.2 Mbps | 12.22s | **13.5** |

In live mode, Go uses much less total CPU (2.67s vs 11.41s) because the sender
spends most time sleeping in the pacer. But C++ moves 10x more data per CPU-second.

In file mode, Go uses more total CPU (20.76s vs 12.22s). The `sys` time dominates
(15.28s of 20.76s), indicating per-packet syscall overhead.

---

## 4. Cross-Test Analysis

The cross-tests isolate each Go component against the known-good C++ reference:

| Go component | Direction | Throughput | vs C++ baseline |
|-------------|-----------|----------:|----------------|
| **Go sender** | -> C++ recv (live) | 103.2 Mbps | 10% of C++ |
| **Go receiver** | <- C++ send (live) | 1,013.1 Mbps | **96% of C++** |
| **Go sender** | -> C++ recv (file) | 529.4 Mbps | 58% of C++ |
| **Go receiver** | <- C++ send (file) | 688.7 Mbps | 76% of C++ |

The Go **receiver in live mode is nearly as fast as C++** (1,013 vs 1,056 Mbps).
The Go **sender** is the primary bottleneck in both modes.

---

## 5. Memory

| Metric | Go | C++ | Ratio |
|--------|---:|----:|------:|
| Live mode RSS | 30.3 MB | 17.9 MB | Go uses **1.7x** more |
| File mode RSS | 12.8 MB | 16.0 MB | Go uses **0.8x** (less!) |

Go uses more memory in live mode (goroutine stacks, GC heap). In file mode,
Go is slightly more memory-efficient than C++.

---

## 6. Root Cause Analysis

### Live Mode Bottleneck: `time.Sleep` Granularity

The LiveCC pacer interval at MaxBW = 1 Gbps is **10.88 us per packet**.
Measured `time.Sleep` granularity on this machine:

```
Sleep( 1 us) -> actual   4 us  (4.1x overshoot)
Sleep( 5 us) -> actual  10 us  (1.9x overshoot)
Sleep(10 us) -> actual  16 us  (1.6x overshoot)
Sleep(50 us) -> actual  64 us  (1.3x overshoot)
```

The ~60% sleep overshoot alone would cap live throughput at ~625 Mbps. The
actual 97 Mbps is lower because the Go sender also has overhead from lock
contention and CC feedback processing.

### Go Sender Live: High Drop Rate

The Go -> C++ live test shows 24% loss / 26K drops. The sender pushes data
into the send buffer, but packets are dropped before delivery (too-late-to-send).
This indicates the LiveCC pacing allows bursts that overflow the send buffer,
then drops accumulate while the pacer sleeps.

### File Mode: Nearly Competitive

Go file mode at 778 Mbps vs C++ at 908 Mbps (86%) is a strong result.
The remaining gap is primarily syscall overhead: Go's `sys` time is 15.28s
vs C++ 9.87s. Each SRT packet requires a `sendmsg`/`recvmsg` syscall.
Batching via `sendmmsg`/`recvmmsg` (Linux-only) could close this gap.

---

## 7. Summary Table

| Metric | Live Mode | File Mode |
|--------|-----------|-----------
| Throughput delta | Go is **10.8x slower** | Go is **1.17x slower** |
| CPU efficiency (per Gbps) | Go uses **2.5x more** | Go uses **2.0x more** |
| Memory (RSS) | Go uses **1.7x more** | Go uses **0.8x less** |
| Go receiver | **96% of C++** | **76% of C++** |
| Go sender | **10% of C++** | **58% of C++** |

---

## 8. Optimization Opportunities (ranked by expected impact)

1. **Live pacer**: Replace `time.Sleep` with busy-wait spin loop for intervals
   under ~100 us. This is the single biggest win — the sender is the sole
   bottleneck (Go receiver handles 1,013 Mbps). The pacing code is in
   `conn.go:sendData()`.

2. **Sender send-buffer drops**: The 24% loss in Go -> C++ live suggests the
   pacing allows burst accumulation followed by mass drops. Smoother token-bucket
   pacing or a tighter credit system would reduce this.

3. **File mode syscall overhead**: Go's high `sys` CPU time (15.28s sys vs 5.48s
   user) indicates per-packet syscall overhead. `sendmmsg`/`recvmmsg` batching
   (Linux only) or larger MTU could reduce this.

4. **Lock contention**: The Go sender's 10.8x gap vs C++ is larger than sleep
   granularity alone would cause. Lock contention in the send path (send buffer
   lock, CC lock, mux write lock) adds latency per packet.

---

## Caveats

- **Single-machine**: All tests on localhost. Real network conditions (latency,
  jitter, loss) would change the picture — congestion control behavior differs
  under actual network conditions.

- **Go loopback mode**: The single-process loopback test has goroutine CPU
  contention. Always use separate-process tests for accurate comparison.

- **Run-to-run variance**: Results vary ~10-15% between runs due to system
  load and scheduling. Use multiple runs for stable conclusions.
