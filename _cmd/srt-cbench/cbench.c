/*
 * cbench — C benchmark for libsrt, mirrors Go srt-bench exactly.
 *
 * Both tools use the same methodology: in-memory data generation, tight
 * send/recv loop, identical SRT configuration, and matching JSON output.
 * This ensures a fair apples-to-apples comparison.
 *
 * Build:
 *   cc -O2 -o /tmp/srt-cbench cbench.c $(pkg-config --cflags --libs srt)
 *
 * Usage:
 *   srt-cbench -mode sender   -addr 127.0.0.1:9001 -duration 10 -type live
 *   srt-cbench -mode receiver  -addr 127.0.0.1:9001 -duration 10 -type live
 *   srt-cbench -mode loopback  -duration 10 -type live
 */

#include <srt/srt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <pthread.h>

/* ── Helpers ────────────────────────────────────────────────── */

static double now_sec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

/* Create and configure an SRT socket with the same parameters as Go makeCfg(). */
static SRTSOCKET make_socket(const char *transtype)
{
    SRTSOCKET s = srt_create_socket();
    if (s == SRT_INVALID_SOCK) {
        fprintf(stderr, "srt_create_socket: %s\n", srt_getlasterror_str());
        exit(1);
    }

    int tt = strcmp(transtype, "file") == 0 ? SRTT_FILE : SRTT_LIVE;
    srt_setsockflag(s, SRTO_TRANSTYPE, &tt, sizeof(tt));

    int latency   = 120;              /* ms  */
    int64_t maxbw = (int64_t)10000000000 / 8; /* 10 Gbps */
    int fc        = 25600;
    int sndbuf    = 8192 * 1500;      /* SRT byte count = slots * ~pkt_size */
    int rcvbuf    = 8192 * 1500;
    int conntimeo = 5000;             /* ms  */

    srt_setsockflag(s, SRTO_LATENCY,   &latency,   sizeof(latency));
    srt_setsockflag(s, SRTO_MAXBW,     &maxbw,     sizeof(maxbw));
    srt_setsockflag(s, SRTO_FC,        &fc,        sizeof(fc));
    srt_setsockflag(s, SRTO_SNDBUF,    &sndbuf,    sizeof(sndbuf));
    srt_setsockflag(s, SRTO_RCVBUF,    &rcvbuf,    sizeof(rcvbuf));
    srt_setsockflag(s, SRTO_CONNTIMEO, &conntimeo, sizeof(conntimeo));

    return s;
}

static struct sockaddr_in parse_addr(const char *hostport)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;

    char host[256];
    int port = 9001;
    if (sscanf(hostport, "%255[^:]:%d", host, &port) < 1) {
        fprintf(stderr, "bad address: %s\n", hostport);
        exit(1);
    }
    sa.sin_port = htons(port);
    inet_pton(AF_INET, host, &sa.sin_addr);
    return sa;
}

static int payload_size(const char *transtype)
{
    return strcmp(transtype, "file") == 0 ? 1456 : 1316;
}

/* ── JSON output (matches Go Result struct) ────────────────── */

typedef struct {
    const char *role;
    const char *trans_type;
    double      duration_s;
    uint64_t    bytes;
    uint64_t    packets;
    double      mbps_send;
    double      mbps_recv;
    double      rtt_ms;
    double      rttvar_ms;
    double      loss_pct;
    uint64_t    retransmits;
    uint64_t    drops;
} Result;

static void print_json(const Result *r)
{
    printf("{\n");
    printf("  \"role\": \"%s\",\n",       r->role);
    printf("  \"trans_type\": \"%s\",\n",  r->trans_type);
    printf("  \"duration_s\": %.6f,\n",    r->duration_s);
    printf("  \"bytes\": %llu,\n",         (unsigned long long)r->bytes);
    printf("  \"packets\": %llu,\n",       (unsigned long long)r->packets);
    printf("  \"mbps_send\": %.6f,\n",     r->mbps_send);
    printf("  \"mbps_recv\": %.6f,\n",     r->mbps_recv);
    printf("  \"rtt_ms\": %.3f,\n",        r->rtt_ms);
    printf("  \"rttvar_ms\": %.3f,\n",     r->rttvar_ms);
    printf("  \"loss_pct\": %.6f,\n",      r->loss_pct);
    printf("  \"retransmits\": %llu,\n",   (unsigned long long)r->retransmits);
    printf("  \"drops\": %llu\n",          (unsigned long long)r->drops);
    printf("}\n");
}

/* ── Sender ────────────────────────────────────────────────── */

static Result run_sender(const char *addr, int duration, const char *transtype)
{
    struct sockaddr_in sa = parse_addr(addr);
    int psize = payload_size(transtype);

    SRTSOCKET s = make_socket(transtype);

    fprintf(stderr, "Connecting to %s (%s)...\n", addr, transtype);
    if (srt_connect(s, (struct sockaddr *)&sa, sizeof(sa)) == SRT_ERROR) {
        fprintf(stderr, "srt_connect: %s\n", srt_getlasterror_str());
        exit(1);
    }
    fprintf(stderr, "Connected.\n");
    usleep(20000); /* 20 ms settle, matching Go */

    char *chunk = calloc(psize, 1);
    for (int i = 0; i < psize; i++)
        chunk[i] = (char)(i % 256);

    double start    = now_sec();
    double deadline = start + duration;
    double last_log = start;
    uint64_t total  = 0;
    uint64_t pkts   = 0;

    while (now_sec() < deadline) {
        int n = srt_send(s, chunk, psize);
        if (n == SRT_ERROR) {
            fprintf(stderr, "srt_send: %s\n", srt_getlasterror_str());
            break;
        }
        total += n;
        pkts++;

        double now = now_sec();
        if (now - last_log >= 2.0) {
            double el = now - start;
            fprintf(stderr, "  [%.0fs] %.1f Mbps (%llu pkts)\n",
                    el, (double)total * 8 / 1e6 / el, (unsigned long long)pkts);
            last_log = now;
        }
    }

    double elapsed = now_sec() - start;
    SRT_TRACEBSTATS st;
    srt_bstats(s, &st, 0);
    srt_close(s);
    free(chunk);

    double send_mbps = (double)total * 8 / 1e6 / elapsed;
    double loss = 0;
    if (st.pktSentTotal > 0)
        loss = (double)st.pktRetransTotal / (double)st.pktSentTotal * 100.0;

    fprintf(stderr, "\nSender done: %.1f Mbps, RTT=%.2fms, loss=%.3f%%\n",
            send_mbps, st.msRTT, loss);

    return (Result){
        .role       = "sender",
        .trans_type = transtype,
        .duration_s = elapsed,
        .bytes      = total,
        .packets    = pkts,
        .mbps_send  = send_mbps,
        .rtt_ms     = st.msRTT,
        .loss_pct   = loss,
        .retransmits = st.pktRetransTotal,
        .drops      = st.pktSndDropTotal + st.pktRcvDropTotal,
    };
}

/* ── Receiver ──────────────────────────────────────────────── */

static Result run_receiver(const char *addr, int duration, const char *transtype)
{
    struct sockaddr_in sa = parse_addr(addr);
    int psize = payload_size(transtype);
    SRTSOCKET s = make_socket(transtype);

    fprintf(stderr, "Listening on %s (%s)...\n", addr, transtype);
    if (srt_bind(s, (struct sockaddr *)&sa, sizeof(sa)) == SRT_ERROR) {
        fprintf(stderr, "srt_bind: %s\n", srt_getlasterror_str());
        exit(1);
    }
    if (srt_listen(s, 1) == SRT_ERROR) {
        fprintf(stderr, "srt_listen: %s\n", srt_getlasterror_str());
        exit(1);
    }
    fprintf(stderr, "READY\n");

    struct sockaddr_in peer;
    int peerlen = sizeof(peer);
    SRTSOCKET cs = srt_accept(s, (struct sockaddr *)&peer, &peerlen);
    if (cs == SRT_INVALID_SOCK) {
        fprintf(stderr, "srt_accept: %s\n", srt_getlasterror_str());
        exit(1);
    }
    fprintf(stderr, "Accepted connection.\n");

    char *buf = calloc(psize * 2, 1);
    double start    = now_sec();
    double last_log = start;
    double timeout  = start + duration + 10;
    uint64_t total  = 0;
    uint64_t pkts   = 0;

    while (now_sec() < timeout) {
        int n = srt_recv(cs, buf, psize * 2);
        if (n == SRT_ERROR) {
            int err = srt_getlasterror(NULL);
            if (err == SRT_ECONNLOST || err == SRT_EINVSOCK)
                break;
            continue;
        }
        if (n > 0) {
            total += n;
            pkts++;
        }
        double now = now_sec();
        if (now - last_log >= 2.0) {
            double el = now - start;
            fprintf(stderr, "  [%.0fs] %.1f Mbps recv (%llu pkts)\n",
                    el, (double)total * 8 / 1e6 / el, (unsigned long long)pkts);
            last_log = now;
        }
    }

    double elapsed = now_sec() - start;
    SRT_TRACEBSTATS st;
    srt_bstats(cs, &st, 0);
    srt_close(cs);
    srt_close(s);
    free(buf);

    double recv_mbps = (double)total * 8 / 1e6 / elapsed;
    double loss = 0;
    if (st.pktRecvTotal > 0)
        loss = (double)st.pktRcvLossTotal / (double)st.pktRecvTotal * 100.0;

    fprintf(stderr, "\nReceiver done: %.1f Mbps, %llu packets\n",
            recv_mbps, (unsigned long long)pkts);

    return (Result){
        .role       = "receiver",
        .trans_type = transtype,
        .duration_s = elapsed,
        .bytes      = total,
        .packets    = pkts,
        .mbps_recv  = recv_mbps,
        .rtt_ms     = st.msRTT,
        .loss_pct   = loss,
        .retransmits = st.pktRetransTotal,
        .drops      = st.pktSndDropTotal + st.pktRcvDropTotal,
    };
}

/* ── Loopback (threads) ───────────────────────────────────── */

typedef struct {
    const char *addr;
    int         duration;
    const char *transtype;
    Result      result;
} ThreadArg;

static void *recv_thread(void *arg)
{
    ThreadArg *ta = (ThreadArg *)arg;
    ta->result = run_receiver(ta->addr, ta->duration, ta->transtype);
    return NULL;
}

static Result run_loopback(int duration, const char *transtype)
{
    const char *addr = "127.0.0.1:19876";

    if (strcmp(transtype, "file") == 0) {
        fprintf(stderr, "WARNING: loopback shares CPU between threads — "
                        "file-mode numbers may be low.\n\n");
    }

    ThreadArg rarg = { .addr = addr, .duration = duration, .transtype = transtype };
    pthread_t tid;
    pthread_create(&tid, NULL, recv_thread, &rarg);
    usleep(500000); /* 500 ms for listener to start */

    Result snd = run_sender(addr, duration, transtype);
    pthread_join(tid, NULL);

    snd.role      = "loopback";
    snd.mbps_recv = rarg.result.mbps_recv;
    snd.drops    += rarg.result.drops;
    return snd;
}

/* ── Main ──────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    const char *mode      = "loopback";
    const char *addr      = "127.0.0.1:9001";
    int         duration  = 10;
    const char *transtype = "live";

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "-mode")     && i+1 < argc) mode      = argv[++i];
        else if (!strcmp(argv[i], "-addr")     && i+1 < argc) addr      = argv[++i];
        else if (!strcmp(argv[i], "-duration") && i+1 < argc) duration  = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-type")     && i+1 < argc) transtype = argv[++i];
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            fprintf(stderr, "Usage: %s [-mode M] [-addr H:P] [-duration S] [-type T]\n", argv[0]);
            return 0;
        }
    }

    srt_startup();
    srt_setloglevel(LOG_CRIT);

    Result r;
    if      (!strcmp(mode, "sender"))   r = run_sender(addr, duration, transtype);
    else if (!strcmp(mode, "receiver")) r = run_receiver(addr, duration, transtype);
    else if (!strcmp(mode, "loopback")) r = run_loopback(duration, transtype);
    else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        srt_cleanup();
        return 1;
    }

    print_json(&r);
    srt_cleanup();
    return 0;
}
