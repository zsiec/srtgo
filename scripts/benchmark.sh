#!/usr/bin/env bash
#
# benchmark.sh — SRT performance comparison: Go (srtgo) vs C++ (libsrt).
#
# Runs 5 test configurations in both live and file modes (10 tests total):
#   1. Go loopback      — both sides in one process (smoke test)
#   2. Go ↔ Go separate — sender + receiver as separate OS processes
#   3. C++ ↔ C++ separate — baseline reference
#   4. Go → C++         — isolates Go sender performance
#   5. C++ → Go         — isolates Go receiver performance
#
# Both tools use identical methodology: in-memory data, tight send/recv loop,
# same SRT config (MaxBW=1Gbps, Latency=120ms, FC=25600), JSON output.
#
# Requirements: Go toolchain, libsrt (brew install srt), pkg-config, python3.
#
# Usage:
#   bash scripts/benchmark.sh                   # full suite (~3 min)
#   bash scripts/benchmark.sh --duration=5      # shorter tests
#   bash scripts/benchmark.sh --mode=live       # live mode only
#   bash scripts/benchmark.sh --skip-cpp        # Go-only (no libsrt needed)
#
set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────
DURATION=10
PORT=9001
GO_BENCH=/tmp/srt-bench
CPP_BENCH=/tmp/srt-cbench
RESULTS_DIR=/tmp/srt-benchmark-results
COOLDOWN=2
MODES="live file"
SKIP_CPP=false

# ── Parse flags ─────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --duration=*) DURATION="${arg#*=}" ;;
        --mode=*)     MODES="${arg#*=}" ;;
        --skip-cpp)   SKIP_CPP=true ;;
        --port=*)     PORT="${arg#*=}" ;;
        --help|-h)
            echo "Usage: $0 [--duration=N] [--mode=live|file] [--skip-cpp] [--port=N]"
            exit 0 ;;
    esac
done

rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

# ── Helpers ─────────────────────────────────────────────────────
CYAN='\033[0;36m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
log() { echo -e "${CYAN}==> $1${NC}" >&2; }
ok()  { echo -e "${GREEN}    $1${NC}" >&2; }

kill_port() {
    lsof -ti :"$1" 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 0.5
}

mbps_from_json() {
    python3 -c "
import json, sys
try:
    d = json.load(open('$1'))
    if isinstance(d, list): d = d[0]
    v = d.get('mbps_send', 0) or d.get('mbps_recv', 0)
    print(f'{v:.1f}')
except: print('?')
" 2>/dev/null
}

# Wait for a background receiver to print READY or accept a connection.
wait_for_listener() {
    local timefile="$1" timeout=10
    for _ in $(seq 1 $((timeout * 10))); do
        if [ -f "$timefile" ] && grep -q -e "READY" -e "Accepted" "$timefile" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    sleep 2  # fallback
}

# ── Test runners ────────────────────────────────────────────────

run_go_loopback() {
    local mode=$1 label="go_loopback_${1}"
    log "Go loopback ($mode, ${DURATION}s)"

    /usr/bin/time -l "$GO_BENCH" \
        -mode=loopback -duration="${DURATION}s" -type="$mode" \
        > "$RESULTS_DIR/${label}.json" \
        2> "$RESULTS_DIR/${label}.time" || true

    ok "Go loopback ($mode): $(mbps_from_json "$RESULTS_DIR/${label}.json") Mbps"
    sleep "$COOLDOWN"
}

run_go_separate() {
    local mode=$1 label="go_sep_${1}"
    log "Go ↔ Go separate ($mode, ${DURATION}s)"
    kill_port "$PORT"

    /usr/bin/time -l "$GO_BENCH" \
        -mode=receiver -addr="127.0.0.1:${PORT}" -duration="${DURATION}s" -type="$mode" \
        > "$RESULTS_DIR/${label}_recv.json" \
        2> "$RESULTS_DIR/${label}_recv.time" &
    local recv_pid=$!
    wait_for_listener "$RESULTS_DIR/${label}_recv.time"

    /usr/bin/time -l "$GO_BENCH" \
        -mode=sender -addr="127.0.0.1:${PORT}" -duration="${DURATION}s" -type="$mode" \
        > "$RESULTS_DIR/${label}_send.json" \
        2> "$RESULTS_DIR/${label}_send.time" || true

    wait $recv_pid 2>/dev/null || true
    kill_port "$PORT"

    ok "Go↔Go ($mode): $(mbps_from_json "$RESULTS_DIR/${label}_send.json") Mbps"
    sleep "$COOLDOWN"
}

run_cpp_separate() {
    local mode=$1 label="cpp_sep_${1}"
    log "C++ ↔ C++ separate ($mode, ${DURATION}s)"
    kill_port "$PORT"

    /usr/bin/time -l "$CPP_BENCH" \
        -mode receiver -addr "127.0.0.1:${PORT}" -duration "$DURATION" -type "$mode" \
        > "$RESULTS_DIR/${label}_recv.json" \
        2> "$RESULTS_DIR/${label}_recv.time" &
    local recv_pid=$!
    wait_for_listener "$RESULTS_DIR/${label}_recv.time"

    /usr/bin/time -l "$CPP_BENCH" \
        -mode sender -addr "127.0.0.1:${PORT}" -duration "$DURATION" -type "$mode" \
        > "$RESULTS_DIR/${label}_send.json" \
        2> "$RESULTS_DIR/${label}_send.time" || true

    wait $recv_pid 2>/dev/null || true
    kill_port "$PORT"

    ok "C++↔C++ ($mode): $(mbps_from_json "$RESULTS_DIR/${label}_send.json") Mbps"
    sleep "$COOLDOWN"
}

run_go_send_cpp_recv() {
    local mode=$1 label="go_cpp_${1}"
    log "Go → C++ ($mode, ${DURATION}s)"
    kill_port "$PORT"

    /usr/bin/time -l "$CPP_BENCH" \
        -mode receiver -addr "127.0.0.1:${PORT}" -duration "$DURATION" -type "$mode" \
        > "$RESULTS_DIR/${label}_recv.json" \
        2> "$RESULTS_DIR/${label}_recv.time" &
    local recv_pid=$!
    wait_for_listener "$RESULTS_DIR/${label}_recv.time"

    /usr/bin/time -l "$GO_BENCH" \
        -mode=sender -addr="127.0.0.1:${PORT}" -duration="${DURATION}s" -type="$mode" \
        > "$RESULTS_DIR/${label}_send.json" \
        2> "$RESULTS_DIR/${label}_send.time" || true

    wait $recv_pid 2>/dev/null || true
    kill_port "$PORT"

    ok "Go→C++ ($mode): $(mbps_from_json "$RESULTS_DIR/${label}_send.json") Mbps"
    sleep "$COOLDOWN"
}

run_cpp_send_go_recv() {
    local mode=$1 label="cpp_go_${1}"
    log "C++ → Go ($mode, ${DURATION}s)"
    kill_port "$PORT"

    /usr/bin/time -l "$GO_BENCH" \
        -mode=receiver -addr="127.0.0.1:${PORT}" -duration="${DURATION}s" -type="$mode" \
        > "$RESULTS_DIR/${label}_recv.json" \
        2> "$RESULTS_DIR/${label}_recv.time" &
    local recv_pid=$!
    wait_for_listener "$RESULTS_DIR/${label}_recv.time"

    /usr/bin/time -l "$CPP_BENCH" \
        -mode sender -addr "127.0.0.1:${PORT}" -duration "$DURATION" -type "$mode" \
        > "$RESULTS_DIR/${label}_send.json" \
        2> "$RESULTS_DIR/${label}_send.time" || true

    wait $recv_pid 2>/dev/null || true
    kill_port "$PORT"

    ok "C++→Go ($mode): $(mbps_from_json "$RESULTS_DIR/${label}_recv.json") Mbps"
    sleep "$COOLDOWN"
}

# ── Report generator ────────────────────────────────────────────

generate_report() {
    log "Generating report..."
    python3 << 'PYEOF'
import json, os, re, platform

R = "/tmp/srt-benchmark-results"

def parse_time(path):
    """Extract CPU/RSS from /usr/bin/time -l output."""
    try:
        t = open(path).read()
        m = re.search(r'([\d.]+)\s+real\s+([\d.]+)\s+user\s+([\d.]+)\s+sys', t)
        r, u, s = (float(m.group(i)) for i in (1,2,3)) if m else (0,0,0)
        rss_m = re.search(r'(\d+)\s+maximum resident', t)
        rss = int(rss_m.group(1)) / (1024*1024) if rss_m else 0
        return {"real": r, "user": u, "sys": s, "cpu": u+s, "rss": rss}
    except:
        return {"real":0, "user":0, "sys":0, "cpu":0, "rss":0}

def load_json(path):
    try:
        d = json.load(open(path))
        return d[0] if isinstance(d, list) else d
    except:
        return {}

def sf(d, k, dflt=0.0):
    try: return float(d.get(k, dflt))
    except: return dflt

def si(d, k, dflt=0):
    try: return int(d.get(k, dflt))
    except: return dflt

tests = {}

# Gather results from each test configuration
for mode in ["live", "file"]:
    # Go loopback
    g = load_json(f"{R}/go_loopback_{mode}.json")
    t = parse_time(f"{R}/go_loopback_{mode}.time")
    if g:
        tests[f"Go loopback ({mode})"] = {
            "mbps": sf(g,"mbps_send"), "rtt": sf(g,"rtt_ms"), "loss": sf(g,"loss_pct"),
            "retrans": si(g,"retransmits"), "drops": si(g,"drops"),
            "cpu": t["cpu"], "user": t["user"], "sys": t["sys"], "rss": t["rss"],
        }

    # Go separate
    gs = load_json(f"{R}/go_sep_{mode}_send.json")
    st = parse_time(f"{R}/go_sep_{mode}_send.time")
    rt = parse_time(f"{R}/go_sep_{mode}_recv.time")
    if gs:
        tests[f"Go separate ({mode})"] = {
            "mbps": sf(gs,"mbps_send"), "rtt": sf(gs,"rtt_ms"), "loss": sf(gs,"loss_pct"),
            "retrans": si(gs,"retransmits"), "drops": si(gs,"drops"),
            "cpu": st["cpu"]+rt["cpu"], "user": st["user"]+rt["user"],
            "sys": st["sys"]+rt["sys"], "rss": max(st["rss"],rt["rss"]),
        }

    # C++ separate
    cs = load_json(f"{R}/cpp_sep_{mode}_send.json")
    cst = parse_time(f"{R}/cpp_sep_{mode}_send.time")
    crt = parse_time(f"{R}/cpp_sep_{mode}_recv.time")
    if cs:
        tests[f"C++ separate ({mode})"] = {
            "mbps": sf(cs,"mbps_send"), "rtt": sf(cs,"rtt_ms"), "loss": sf(cs,"loss_pct"),
            "retrans": si(cs,"retransmits"), "drops": si(cs,"drops"),
            "cpu": cst["cpu"]+crt["cpu"], "user": cst["user"]+crt["user"],
            "sys": cst["sys"]+crt["sys"], "rss": max(cst["rss"],crt["rss"]),
        }

    # Go → C++
    gc = load_json(f"{R}/go_cpp_{mode}_send.json")
    gct = parse_time(f"{R}/go_cpp_{mode}_send.time")
    if gc:
        tests[f"Go→C++ ({mode})"] = {
            "mbps": sf(gc,"mbps_send"), "rtt": sf(gc,"rtt_ms"), "loss": sf(gc,"loss_pct"),
            "retrans": si(gc,"retransmits"), "drops": si(gc,"drops"),
            "cpu": gct["cpu"], "user": gct["user"], "sys": gct["sys"], "rss": gct["rss"],
        }

    # C++ → Go
    cg = load_json(f"{R}/cpp_go_{mode}_recv.json")
    cgt = parse_time(f"{R}/cpp_go_{mode}_recv.time")
    if cg:
        tests[f"C++→Go ({mode})"] = {
            "mbps": sf(cg,"mbps_recv"), "rtt": sf(cg,"rtt_ms"), "loss": sf(cg,"loss_pct"),
            "retrans": si(cg,"retransmits"), "drops": si(cg,"drops"),
            "cpu": cgt["cpu"], "user": cgt["user"], "sys": cgt["sys"], "rss": cgt["rss"],
        }

# ═══════════════ Print report ═══════════════
W = 95
print()
print("=" * W)
print("  SRT PERFORMANCE BENCHMARK REPORT")
print(f"  Go (srtgo) vs C++ (libsrt) | {platform.machine()}")
print("=" * W)

for mode in ["live", "file"]:
    M = mode.upper()
    print(f"\n  {M} MODE — Throughput")
    print(f"  {'─'*75}")
    print(f"  {'Test':<25} {'Mbps':>8} {'RTT ms':>9} {'Loss %':>8} {'Retrans':>9} {'Drops':>7}")
    print(f"  {'─'*75}")
    for label in [f"Go loopback ({mode})", f"Go separate ({mode})", f"C++ separate ({mode})",
                  f"Go→C++ ({mode})", f"C++→Go ({mode})"]:
        t = tests.get(label, {})
        if not t: continue
        short = label.replace(f" ({mode})", "")
        print(f"  {short:<25} {t['mbps']:>8.1f} {t['rtt']:>7.2f}ms {t['loss']:>7.3f}% {t['retrans']:>9} {t['drops']:>7}")

for mode in ["live", "file"]:
    M = mode.upper()
    print(f"\n  {M} MODE — Resources (sender + receiver combined)")
    print(f"  {'─'*75}")
    print(f"  {'Test':<25} {'CPU usr':>8} {'CPU sys':>8} {'CPU tot':>8} {'RSS MB':>8}")
    print(f"  {'─'*75}")
    for label in [f"Go loopback ({mode})", f"Go separate ({mode})", f"C++ separate ({mode})",
                  f"Go→C++ ({mode})", f"C++→Go ({mode})"]:
        t = tests.get(label, {})
        if not t: continue
        short = label.replace(f" ({mode})", "")
        print(f"  {short:<25} {t['user']:>6.2f}s {t['sys']:>6.2f}s {t['cpu']:>6.2f}s {t['rss']:>6.1f} MB")

# Head-to-head summary
print(f"\n  HEAD-TO-HEAD (Go separate vs C++ separate)")
print(f"  {'─'*75}")
for mode in ["live", "file"]:
    go = tests.get(f"Go separate ({mode})", {})
    cpp = tests.get(f"C++ separate ({mode})", {})
    if not go or not cpp: continue
    gm, cm = go["mbps"], cpp["mbps"]
    gc, cc = go["cpu"], cpp["cpu"]
    gr, cr = go["rss"], cpp["rss"]
    print(f"  {mode.upper()}:")
    if cm > 0:
        r = gm/cm
        d = "FASTER" if r >= 1 else "SLOWER"
        print(f"    Throughput: Go is {max(r,1/r):.1f}x {d}  ({gm:.1f} vs {cm:.1f} Mbps)")
    if cc > 0:
        r = gc/cc
        d = "MORE" if r > 1 else "LESS"
        print(f"    CPU total:  Go uses {max(r,1/r):.1f}x {d}  ({gc:.2f}s vs {cc:.2f}s)")
    if cr > 0:
        r = gr/cr
        d = "MORE" if r > 1 else "LESS"
        print(f"    Memory RSS: Go uses {r:.1f}x  ({gr:.1f} vs {cr:.1f} MB)")

    go2c = tests.get(f"Go→C++ ({mode})", {})
    c2go = tests.get(f"C++→Go ({mode})", {})
    if go2c and c2go:
        print(f"    Go sender isolated:   {go2c['mbps']:.1f} Mbps")
        print(f"    Go receiver isolated: {c2go['mbps']:.1f} Mbps")

print(f"\n{'='*W}")

# Save structured data
with open(f"{R}/report.json", "w") as f:
    json.dump(tests, f, indent=2)
print(f"  Raw data: {R}/report.json")
print()
PYEOF
}

# ── Main ────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}SRT Performance Benchmark${NC}"
echo -e "  Go: srtgo ($(go version | awk '{print $3}'))"
echo -e "  Duration: ${DURATION}s per test | $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)"
echo ""

# Build Go benchmark tool
log "Building Go benchmark tool..."
go build -o "$GO_BENCH" ./cmd/srt-bench/ 2>&1
ok "Built $GO_BENCH"

# Build C++ benchmark tool (requires libsrt)
HAS_CPP=false
if [ "$SKIP_CPP" = false ] && pkg-config --exists srt 2>/dev/null; then
    log "Building C++ benchmark tool (cbench)..."
    SRT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    cc -O2 -o "$CPP_BENCH" "$SRT_DIR/cmd/srt-cbench/cbench.c" \
        $(pkg-config --cflags --libs srt) 2>&1
    ok "Built $CPP_BENCH (libsrt $(pkg-config --modversion srt))"
    echo -e "  C++: libsrt $(pkg-config --modversion srt)"
    HAS_CPP=true
elif [ "$SKIP_CPP" = false ]; then
    echo -e "  C++: not available (install: brew install srt)"
fi
echo ""

kill_port "$PORT"

# Run test matrix
for mode in $MODES; do
    run_go_loopback "$mode"
    run_go_separate "$mode"

    if [ "$HAS_CPP" = true ]; then
        run_cpp_separate "$mode"
        run_go_send_cpp_recv "$mode"
        run_cpp_send_go_recv "$mode"
    fi
done

generate_report
echo -e "${GREEN}${BOLD}Benchmark complete.${NC}"
