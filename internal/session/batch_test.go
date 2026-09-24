package session

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func queuedSession(messages ...string) *Session {
	s := readTestSession(newDeliveryQueue(2, 100, 1<<20))
	for i, v := range messages {
		s.deliveries.push(delivery{data: []byte(v), meta: MsgMetadata{MsgNo: uint32(i + 1), Seq: uint32(100 + i), Boundary: 3}}, false)
	}
	return s
}

func TestReadBatchCoalescesAndReturnsAvailable(t *testing.T) {
	s := queuedSession("one", "two", "three")
	s.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 100)
	n, err := s.ReadBatch(b)
	if err != nil || string(b[:n]) != "onetwothree" {
		t.Fatalf("batch=%q,%v", b[:n], err)
	}
	s.SetReadBlocking(false)
	if _, err := s.ReadBatch(b); !errors.Is(err, ErrWouldBlock) {
		t.Fatalf("empty batch: %v", err)
	}
}

func TestReadBatchPartialOrderingAndMetadata(t *testing.T) {
	s := queuedSession("ab", "cdef", "gh")
	b := make([]byte, 3)
	n, err := s.ReadBatch(b)
	if err != nil || string(b[:n]) != "abc" {
		t.Fatalf("first=%q,%v", b[:n], err)
	}
	if !s.ReadReady() {
		t.Fatal("partial payload not readable")
	}
	// The remainder stays ahead of later queued messages and retains metadata.
	n, meta, err := s.ReadMsg(b)
	if err != nil || string(b[:n]) != "def" || meta.MsgNo != 2 || meta.Seq != 101 {
		t.Fatalf("remainder=%q,%+v,%v", b[:n], meta, err)
	}
	n, err = s.ReadBatch(b)
	if err != nil || string(b[:n]) != "gh" {
		t.Fatalf("last=%q,%v", b[:n], err)
	}
	if s.pendingReady.Load() || s.pending.data != nil {
		t.Fatal("completed payload retained")
	}
}

func TestReadSmallBufferPreservesBytes(t *testing.T) {
	s := queuedSession("abcdef", "gh")
	close(s.loopDone)
	var got []byte
	for {
		b := make([]byte, 2)
		n, err := s.Read(b)
		got = append(got, b[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if string(got) != "abcdefgh" {
		t.Fatalf("read stream=%q", got)
	}
}

func TestReadMsgShortBufferIsRetryable(t *testing.T) {
	s := queuedSession("abcdef", "next")
	if _, _, err := s.ReadMsg(make([]byte, 2)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short message error=%v", err)
	}
	b := make([]byte, 10)
	n, meta, err := s.ReadMsg(b)
	if err != nil || string(b[:n]) != "abcdef" || meta.MsgNo != 1 {
		t.Fatalf("retried=%q,%+v,%v", b[:n], meta, err)
	}
	n, _, err = s.ReadMsg(b)
	if err != nil || string(b[:n]) != "next" {
		t.Fatalf("next=%q,%v", b[:n], err)
	}
}

func TestBatchZeroBufferAndDeadline(t *testing.T) {
	s := queuedSession("abcdef")
	if n, err := s.ReadBatch(nil); n != 0 || err != nil {
		t.Fatalf("zero read=%d,%v", n, err)
	}
	b := make([]byte, 2)
	s.ReadBatch(b)
	s.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := s.ReadBatch(b); !errors.Is(err, ErrTimeout) {
		t.Fatalf("pending deadline=%v", err)
	}
	s.SetReadDeadline(time.Time{})
	n, err := s.ReadBatch(b)
	if err != nil || string(b[:n]) != "cd" {
		t.Fatalf("after timeout=%q,%v", b[:n], err)
	}
}

func TestReadBatchCloseAndConcurrentReaders(t *testing.T) {
	s := queuedSession()
	want := make([]byte, 200)
	for i := range want {
		want[i] = byte(i)
	}
	s.deliveries = newDeliveryQueue(200, 0, 1<<20)
	for _, v := range want {
		s.deliveries.push(delivery{data: []byte{v}}, false)
	}
	close(s.loopDone)
	var wg sync.WaitGroup
	results := make(chan []byte, 200)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				b := make([]byte, 7)
				n, err := s.ReadBatch(b)
				if n > 0 {
					results <- b[:n]
				}
				if err == io.EOF {
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(results)
	counts := make([]byte, 200)
	for b := range results {
		for _, v := range b {
			counts[int(v)]++
		}
	}
	if !bytes.Equal(counts, bytes.Repeat([]byte{1}, 200)) {
		t.Fatal("concurrent reads lost or duplicated bytes")
	}
}
