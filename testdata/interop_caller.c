/* A real libsrt caller for Go listener interoperability regression tests. */
#include <srt/srt.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void fail(const char *op) {
    fprintf(stderr, "%s: %s\n", op, srt_getlasterror_str());
    exit(1);
}
static void option(SRTSOCKET s, SRT_SOCKOPT key, const void *value, int len) {
    if (srt_setsockflag(s, key, value, len) < 0) fail("setsockflag");
}
int main(int argc, char **argv) {
    if (argc != 6 && argc != 10) return 2; /* port, sync/async, send/recv, passphrase, key bytes */
    srt_startup();
    SRTSOCKET s = srt_create_socket();
    int timeout = 4000;
    option(s, SRTO_CONNTIMEO, &timeout, sizeof timeout);
    option(s, SRTO_RCVTIMEO, &timeout, sizeof timeout);
    option(s, SRTO_SNDTIMEO, &timeout, sizeof timeout);
    if (argv[4][0]) {
        int keylen = atoi(argv[5]);
        option(s, SRTO_PASSPHRASE, argv[4], (int)strlen(argv[4]));
        option(s, SRTO_PBKEYLEN, &keylen, sizeof keylen);
    }
    if (argc == 10) {
        int recv = atoi(argv[6]), peer = atoi(argv[7]);
        option(s, SRTO_RCVLATENCY, &recv, sizeof recv);
        option(s, SRTO_PEERLATENCY, &peer, sizeof peer);
    }
    bool async = strcmp(argv[2], "async") == 0;
    int eid = -1;
    if (async) {
        bool no = false;
        option(s, SRTO_RCVSYN, &no, sizeof no);
        eid = srt_epoll_create();
        int events = SRT_EPOLL_OUT | SRT_EPOLL_ERR;
        if (srt_epoll_add_usock(eid, s, &events) < 0) fail("epoll_add");
    }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[1]));
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (srt_connect(s, (struct sockaddr *)&addr, sizeof addr) < 0) fail("connect");
    if (async) {
        SRT_EPOLL_EVENT event;
        if (srt_epoll_uwait(eid, &event, 1, timeout) <= 0 || srt_getsockstate(s) != SRTS_CONNECTED)
            fail("async connect");
        bool yes = true;
        option(s, SRTO_RCVSYN, &yes, sizeof yes);
        srt_epoll_release(eid);
    }
    if (argc == 10) {
        int recv = 0, peer = 0, len = sizeof(int);
        if (srt_getsockflag(s, SRTO_RCVLATENCY, &recv, &len) < 0) fail("get rcvlatency");
        len = sizeof(int);
        if (srt_getsockflag(s, SRTO_PEERLATENCY, &peer, &len) < 0) fail("get peerlatency");
        if (recv != atoi(argv[8]) || peer != atoi(argv[9])) {
            fprintf(stderr, "negotiated local/peer latency %d/%d, expected %s/%s\n", recv, peer, argv[8], argv[9]);
            return 1;
        }
    }
    bool send = strcmp(argv[3], "send") == 0;
    unsigned char buf[1500];
    for (int i = 0; i < 20; i++) {
        if (send) {
            for (int j = 0; j < 1316; j++) buf[j] = (unsigned char)(i + j);
            if (srt_sendmsg(s, (char *)buf, 1316, -1, 1) != 1316) fail("sendmsg");
            usleep(5000);
        } else {
            int n = srt_recvmsg(s, (char *)buf, sizeof buf);
            if (n != 1316) fail("recvmsg length");
            for (int j = 0; j < n; j++) {
                if (buf[j] != (unsigned char)(i + j)) {
                    fprintf(stderr, "payload mismatch at message %d byte %d\n", i, j);
                    return 1;
                }
            }
        }
    }
    if (send) usleep(300000); /* Allow TSBPD delivery before SHUTDOWN. */
    srt_close(s);
    srt_cleanup();
    return 0;
}
