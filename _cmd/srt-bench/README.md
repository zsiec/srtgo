# srt-bench

Benchmark tools for measuring Go srtgo performance against C++ libsrt.

Both Go and C++ use purpose-built benchmark tools with identical methodology:
in-memory data generation, tight send/recv loop, same SRT config, JSON output.

## Quick Start

Run the full comparison suite (requires libsrt from Homebrew):

```bash
brew install srt          # if not already installed
bash scripts/benchmark.sh
```

This runs all 10 tests (5 configurations x 2 modes), takes ~3 minutes, and
prints a formatted report to stdout.

## Go Benchmark Tool (`srt-bench`)

### Loopback (both sides in one process)

```bash
go run ./cmd/srt-bench -mode=loopback -duration=10s -type=live
go run ./cmd/srt-bench -mode=loopback -duration=10s -type=file
```

Good for quick smoke tests. **Not accurate for file mode** due to goroutine
CPU contention — use separate processes instead.

### Separate Processes (recommended for accurate results)

```bash
# Terminal 1: receiver
go run ./cmd/srt-bench -mode=receiver -addr=127.0.0.1:9001 -duration=10s -type=live

# Terminal 2: sender (start after receiver prints READY)
go run ./cmd/srt-bench -mode=sender -addr=127.0.0.1:9001 -duration=10s -type=live
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-mode` | `loopback` | `sender`, `receiver`, or `loopback` |
| `-addr` | `127.0.0.1:9001` | SRT address (host:port) |
| `-duration` | `10s` | Test duration |
| `-type` | `live` | `live` (TSBPD + fixed-rate CC) or `file` (reliable + adaptive CC) |
| `-baseline` | `` | Path to previous JSON result for delta comparison |

## C++ Benchmark Tool (`cbench`)

The C benchmark tool (`cmd/srt-cbench/cbench.c`) links directly against libsrt
and mirrors the Go tool exactly. Build:

```bash
cc -O2 -o /tmp/srt-cbench cmd/srt-cbench/cbench.c $(pkg-config --cflags --libs srt)
```

Usage (note: space-separated flags, not `=`):

```bash
/tmp/srt-cbench -mode sender   -addr 127.0.0.1:9001 -duration 10 -type live
/tmp/srt-cbench -mode receiver -addr 127.0.0.1:9001 -duration 10 -type live
/tmp/srt-cbench -mode loopback -duration 10 -type live
```

### Cross-Testing

**Go sender -> C++ receiver:**
```bash
# Terminal 1: C++ receiver
/tmp/srt-cbench -mode receiver -addr 127.0.0.1:9001 -duration 15 -type live

# Terminal 2: Go sender
go run ./cmd/srt-bench -mode=sender -addr=127.0.0.1:9001 -duration=10s -type=live
```

**C++ sender -> Go receiver:**
```bash
# Terminal 1: Go receiver
go run ./cmd/srt-bench -mode=receiver -addr=127.0.0.1:9001 -duration=15s -type=live

# Terminal 2: C++ sender
/tmp/srt-cbench -mode sender -addr 127.0.0.1:9001 -duration 10 -type live
```

## Output

Both tools output JSON on stdout with the same schema:

```json
{
  "role": "sender",
  "trans_type": "live",
  "duration_s": 10.0,
  "bytes": 97619564,
  "packets": 74179,
  "mbps_send": 78.1,
  "rtt_ms": 0.283,
  "loss_pct": 2.64,
  "retransmits": 1959,
  "drops": 84
}
```

The Go tool also includes `alloc_mb`, `sys_mb`, `num_gc`, and `goroutines` fields.

## Comparing Against a Baseline

Save a baseline, make changes, then compare:

```bash
# Save baseline
go run ./cmd/srt-bench -mode=loopback -type=live > baseline.json 2>/dev/null

# ... make optimizations ...

# Compare
go run ./cmd/srt-bench -mode=loopback -type=live -baseline=baseline.json 2>/dev/null
```

The tool prints a delta table showing throughput, RTT, and loss changes.

## Full Orchestrated Suite

`scripts/benchmark.sh` automates all 10 tests with CPU/memory measurement via
`/usr/bin/time -l`. It requires:

- Go toolchain
- libsrt development files (from `brew install srt`)
- `pkg-config`
- Python 3 (for report generation)

The script:
1. Builds both Go and C++ benchmark tools
2. Runs 5 test configurations x 2 modes = 10 tests
3. Prints a formatted report with head-to-head comparison
4. Saves raw JSON data to `/tmp/srt-benchmark-results/report.json`

```bash
bash scripts/benchmark.sh                   # full suite
bash scripts/benchmark.sh --duration=5      # shorter test
bash scripts/benchmark.sh --mode=live       # live mode only
bash scripts/benchmark.sh --skip-cpp        # Go-only (no libsrt needed)
```

## Results

See [RESULTS.md](RESULTS.md) for the latest benchmark findings and analysis.
