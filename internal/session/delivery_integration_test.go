package session

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/mux"
	"github.com/zsiec/srtgo/internal/packet"
)

func TestSessionDeliveryOverflowPolicy(t *testing.T) {
	for _, live := range []bool{false, true} {
		udp, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		m := mux.New(udp, 1500)
		s := NewEstablished(m, m.Register(1), true, udp.LocalAddr(), core.Config{PeerSocketID: 2, Live: live, TsbpdDelay: 20 * clock.Millisecond, RecvISN: 100}, nil)
		s.onLoop(func() { s.deliveries = newDeliveryQueue(1, 2, 1<<20) })
		s.onLoop(func() {
			for i := 0; i < 4; i++ {
				p := packet.NewData(nil, uint32(100+i), 0, 2, []byte{byte(i)})
				s.core.HandlePacket(s.clk.Now(), p)
			}
		})
		deadline := time.Now().Add(3 * time.Second)
		for {
			st, _ := s.Stats()
			if st.AppReadDropped == 1 {
				break
			}
			if time.Now().After(deadline) {
				s.Close()
				t.Fatal("overflow did not reach stats")
			}
			time.Sleep(time.Millisecond)
		}
		if !live {
			select {
			case <-s.loopDone:
			case <-time.After(time.Second):
				t.Fatal("reliable overflow did not stop the loop")
			}
		}
		s.SetReadDeadline(time.Now().Add(3 * time.Second))
		for i := 0; i < 3; i++ {
			want := byte(i)
			if live {
				want++
			}
			b := make([]byte, 10)
			n, err := s.Read(b)
			if n != 1 || err != nil || b[0] != want {
				s.Close()
				t.Fatalf("live=%v read=%v,%v want %d", live, b[:n], err, want)
			}
		}
		if !live {
			if _, err := s.Read(make([]byte, 10)); !errors.Is(err, ErrReceiveOverflow) {
				t.Fatalf("overflow error=%v", err)
			}
		}
		s.Close()
	}
}
