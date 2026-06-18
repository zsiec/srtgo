package legacy_test

import (
	"log"
	"strings"
	"time"

	srt "github.com/zsiec/srtgo/internal/legacy"
)

func ExampleDial() {
	cfg := srt.DefaultConfig()
	cfg.StreamID = "live/camera1"
	cfg.Latency = 120 * time.Millisecond

	conn, err := srt.Dial("127.0.0.1:4200", cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("hello SRT"))
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleListen() {
	cfg := srt.DefaultConfig()
	cfg.Latency = 120 * time.Millisecond

	ln, err := srt.Listen(":4200", cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	ln.SetAcceptFunc(func(req srt.ConnRequest) bool {
		return strings.HasPrefix(req.StreamID, "live/")
	})

	conn, err := ln.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 1456)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	_ = n
}

func ExampleServer() {
	cfg := srt.DefaultConfig()

	srv := &srt.Server{
		Addr:   ":4200",
		Config: &cfg,
		HandleConnect: func(req srt.ConnRequest) srt.ConnType {
			if strings.HasPrefix(req.StreamID, "#!::r=") {
				return srt.Subscribe
			}
			if strings.HasPrefix(req.StreamID, "#!::m=publish") {
				return srt.Publish
			}
			return srt.Reject
		},
		HandlePublish: func(conn *srt.Conn) {
			buf := make([]byte, 1456)
			for {
				_, err := conn.Read(buf)
				if err != nil {
					return
				}
			}
		},
		HandleSubscribe: func(conn *srt.Conn) {
			data := []byte("test payload")
			for {
				_, err := conn.Write(data)
				if err != nil {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		},
	}

	if err := srv.ListenAndServe(); err != nil && err != srt.ErrServerClosed {
		log.Fatal(err)
	}
}

func ExampleConfig() {
	// Basic live streaming configuration
	live := srt.DefaultConfig()
	live.Latency = 200 * time.Millisecond
	live.StreamID = "live/stream1"

	// Encrypted connection with AES-256
	encrypted := srt.DefaultConfig()
	encrypted.Passphrase = "my_secret_passphrase"
	encrypted.KeyLength = 32

	// File transfer mode
	file := srt.DefaultConfig()
	file.TransType = srt.TransTypeFile

	_ = live
	_ = encrypted
	_ = file
}

func ExampleDialRendezvous() {
	cfg := srt.DefaultConfig()
	cfg.StreamID = "p2p/session1"

	conn, err := srt.DialRendezvous(":5000", "192.168.1.100:5000", cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("peer-to-peer data"))
	if err != nil {
		log.Fatal(err)
	}
}
