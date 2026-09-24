package core

import (
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/packet"
)

func TestRetransmissionSendStats(t *testing.T) {
	c := NewEstablished(Config{SendISN: 100, RecvISN: 200, MaxBW: 125000000}, 1)
	c.Write(2, []byte("payload"))
	c.retransmitAll(1000000)
	nak := packet.NewControl(nil, packet.CtrlTypeNAK, 0, 0)
	if err := nak.MarshalCIF(&packet.CIFNAK{LossList: []uint32{100}}); err != nil {
		t.Fatal(err)
	}
	c.HandlePacket(2000000, nak)
	nak.Release()
	st := c.Stats()
	if st.RetransPackets != 2 || st.SentPackets != 3 || st.SentUniquePackets != 1 || st.SentBytes != 21 || st.SentUniqueBytes != 7 || st.RetransBytes != 14 {
		t.Fatalf("send counters: %+v", st)
	}
	// More retransmits than originals used to underflow the unsigned unique count.
	c.retransmitAll(3000000)
	if st := c.Stats(); st.SentUniquePackets != 1 || st.SentUniqueBytes != 7 {
		t.Fatalf("unique underflow: %+v", st)
	}
}

func TestRetransmissionReceiveStats(t *testing.T) {
	c := NewEstablished(Config{RecvISN: 100, SendISN: 200}, 1)
	for i, tc := range []struct {
		seq     uint32
		data    string
		retrans bool
	}{
		{101, "payload", true}, // original lost; recovered data is unique
		{101, "payload", true}, // duplicate buffered packet
		{100, "abc", false},    // unblocks delivery of both packets
		{100, "abc", false},    // belated original duplicate
	} {
		p := packet.NewData(nil, tc.seq, 0, 0, []byte(tc.data))
		p.Header.Retransmitted = tc.retrans
		c.HandlePacket(2+clock.Timestamp(i), p)
	}
	st := c.Stats()
	if st.RecvPackets != 4 || st.RecvUniquePackets != 2 || st.RecvRetrans != 2 || st.RecvBytes != 20 || st.RecvUniqueBytes != 10 || st.RecvRetransBytes != 14 {
		t.Fatalf("receive counters: %+v", st)
	}
}
