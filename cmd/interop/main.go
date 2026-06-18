// Command interop is a wire-interop harness: in -mode listen it receives and
// verifies a numbered stream; in -mode dial it sends one. Built from the public
// srt API only, so the identical source compiles on both the new branch and main
// (legacy), letting us run new↔legacy and new↔libsrt over real UDP.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"time"

	srt "github.com/zsiec/srtgo"
)

func main() {
	mode := flag.String("mode", "listen", "listen (receive+verify) or dial (send)")
	addr := flag.String("addr", "127.0.0.1:9000", "host:port")
	n := flag.Int("n", 200, "number of messages")
	size := flag.Int("size", 1200, "payload bytes")
	pass := flag.String("pass", "", "passphrase (enables encryption)")
	keylen := flag.Int("keylen", 16, "AES key bytes")
	gcm := flag.Bool("gcm", false, "use AES-GCM instead of CTR")
	fec := flag.String("fec", "", "packet filter (e.g. fec,cols:10,rows:5)")
	msgapi := flag.Bool("msgapi", false, "message API (file transfer) mode")
	latency := flag.Int("latency", 120, "TSBPD latency ms")
	raw := flag.Bool("raw", false, "raw byte-stream mode (for libsrt interop): copy stdin->conn (dial) or conn->stdout (listen)")
	flag.Parse()

	cfg := srt.DefaultConfig()
	cfg.Latency = time.Duration(*latency) * time.Millisecond
	cfg.ConnTimeout = 8 * time.Second
	if *pass != "" {
		cfg.Passphrase = *pass
		cfg.KeyLength = *keylen
		if *gcm {
			cfg.CryptoMode = 2
		}
	}
	if *fec != "" {
		cfg.PacketFilter = *fec
	}
	if *msgapi {
		b := true
		cfg.MessageAPI = &b
	}

	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", a...)
		os.Exit(1)
	}

	var conn *srt.Conn
	if *mode == "listen" {
		ln, err := srt.Listen(*addr, cfg)
		if err != nil {
			fail("listen: %v", err)
		}
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			fail("accept: %v", err)
		}
		conn = c
	} else {
		c, err := srt.Dial(*addr, cfg)
		if err != nil {
			fail("dial: %v", err)
		}
		conn = c
	}
	defer conn.Close()

	if *raw { // raw byte-stream mode for libsrt interop (stdin<->SRT<->stdout)
		if *mode == "dial" {
			in := make([]byte, *size)
			for {
				k, rerr := os.Stdin.Read(in)
				if k > 0 {
					if _, werr := conn.Write(in[:k]); werr != nil {
						fail("write: %v", werr)
					}
				}
				if rerr != nil {
					break
				}
			}
			time.Sleep(2 * time.Second)
			fmt.Fprintln(os.Stderr, "SENT (raw)")
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		total := 0
		buf := make([]byte, *size*2)
		for {
			m, rerr := conn.Read(buf)
			if m > 0 {
				os.Stdout.Write(buf[:m])
				total += m
			}
			if rerr != nil {
				break
			}
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		}
		fmt.Fprintf(os.Stderr, "RECV (raw) bytes=%d\n", total)
		return
	}

	if *mode == "dial" { // sender
		for i := 0; i < *n; i++ {
			p := make([]byte, *size)
			binary.BigEndian.PutUint32(p, uint32(i))
			for j := 4; j < *size; j++ {
				p[j] = byte(i + j)
			}
			if _, err := conn.Write(p); err != nil {
				fail("write %d: %v", i, err)
			}
		}
		time.Sleep(2 * time.Second) // let retransmits/flush complete before close
		fmt.Printf("SENT n=%d\n", *n)
		return
	}

	// receiver
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	buf := make([]byte, *size*2)
	for i := 0; i < *n; i++ {
		m, err := conn.Read(buf)
		if err != nil {
			fail("read %d: %v", i, err)
		}
		if got := binary.BigEndian.Uint32(buf[:m]); got != uint32(i) {
			fail("sequence at %d: got %d (n=%d)", i, got, m)
		}
	}
	fmt.Printf("RECV OK n=%d\n", *n)
}
