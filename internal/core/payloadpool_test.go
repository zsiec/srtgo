package core

import (
	"bytes"
	"sync"
	"testing"
)

func emptyPayloadPool() {
	for {
		select {
		case <-payloadPool:
		default:
			return
		}
	}
}

func TestPayloadPoolRetentionBound(t *testing.T) {
	emptyPayloadPool()
	t.Cleanup(emptyPayloadPool)
	const n = payloadPoolMaxRetained + 100
	buffers := make([][]byte, n)
	for i := range buffers {
		buffers[i] = getPayload(100)
	}
	for _, b := range buffers {
		PutPayload(b)
	}
	if got := len(payloadPool); got != payloadPoolMaxRetained {
		t.Fatalf("retained %d buffers", got)
	}
	emptyPayloadPool()
	for _, b := range [][]byte{nil, make([]byte, 10), make([]byte, payloadClass+1)} {
		PutPayload(b)
	}
	if len(payloadPool) != 0 {
		t.Fatal("retained a different capacity class")
	}
	large := getPayload(payloadClass + 10)
	if len(large) != payloadClass+10 {
		t.Fatal("large allocation truncated")
	}
	PutPayload(large)
	if len(payloadPool) != 0 {
		t.Fatal("retained a reassembled message")
	}
}

func TestPayloadPoolConcurrentOwnership(t *testing.T) {
	var wg sync.WaitGroup
	for id := 1; id <= 32; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			want := bytes.Repeat([]byte{byte(id)}, payloadClass)
			for i := 0; i < 200; i++ {
				b := getPayload(payloadClass)
				copy(b, want)
				if !bytes.Equal(b, want) {
					t.Error("buffer reused while still owned")
					return
				}
				PutPayload(b)
			}
		}(id)
	}
	wg.Wait()
	if len(payloadPool) > payloadPoolMaxRetained {
		t.Fatal("retention limit exceeded")
	}
}
