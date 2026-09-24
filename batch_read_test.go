package srt_test

import (
	"bytes"
	"io"
	"testing"
	"time"

	srt "github.com/zsiec/srtgo"
)

func TestPublicReadBatch(t *testing.T) {
	cfg := srt.DefaultConfig()
	a, b := testConnectionPair(t, cfg, cfg)
	var want []byte
	for _, v := range []string{"alpha", "bravo", "charlie"} {
		a.Write([]byte(v))
		want = append(want, v...)
	}
	deadline := time.Now().Add(3 * time.Second)
	for b.Stats(false).AppReadQueue < 3 {
		if time.Now().After(deadline) {
			t.Fatal("deliveries not ready")
		}
		time.Sleep(time.Millisecond)
	}
	b.SetReadDeadline(deadline)
	got := make([]byte, 100)
	n, err := b.ReadBatch(got)
	if err != nil || !bytes.Equal(got[:n], want) {
		t.Fatalf("batch=%q,%v", got[:n], err)
	}
	a.Write([]byte("message"))
	if _, err := b.ReadMessage(make([]byte, 2)); err != io.ErrShortBuffer {
		t.Fatalf("small message buffer: %v", err)
	}
	n, err = b.ReadMessage(got)
	if err != nil || string(got[:n]) != "message" {
		t.Fatalf("retry=%q,%v", got[:n], err)
	}
}
