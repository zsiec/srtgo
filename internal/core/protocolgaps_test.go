package core_test

import (
	"testing"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/crypto"
	"github.com/zsiec/srtgo/internal/handshake"
	"github.com/zsiec/srtgo/internal/packet"
)

// TestSecuredConnDropsPlaintext proves a plaintext data packet is rejected on a
// secured connection (all data is encrypted once a crypto context is
// negotiated), rather than being delivered as-is.
func TestSecuredConnDropsPlaintext(t *testing.T) {
	base := clock.Timestamp(1_000_000)
	ctx, err := crypto.New(16)
	if err != nil {
		t.Fatal(err)
	}
	const rcvISN = 5000
	c := core.NewEstablished(core.Config{
		PeerSocketID: 1, PayloadSize: 1200, SendISN: 100, RecvISN: rcvISN, MaxBW: 1 << 34,
		CryptoCtx: ctx, ActiveKey: packet.EncryptionEven,
	}, base)
	drainOutputs(c)

	// A data packet with no encryption flag (plaintext) on a secured link.
	p := packet.NewData(nil, rcvISN, 0, 1, []byte("plaintext"))
	c.HandlePacket(base, p)

	for {
		e, ok := c.PollEvent()
		if !ok {
			break
		}
		if _, ok := e.(core.DataReceived); ok {
			t.Fatal("plaintext packet was delivered on a secured connection")
		}
	}
	if st := c.Stats(); st.RecvUndecrypt == 0 {
		t.Fatal("RecvUndecrypt = 0, want >= 1 (plaintext on a secured conn should be rejected)")
	}
}

// armsNAKTimer reports whether the connection armed the periodic-NAK timer at
// establish, draining its construction outputs.
func armsNAKTimer(c *core.Conn) bool {
	armed := false
	for {
		o, ok := c.PollOutput()
		if !ok {
			return armed
		}
		switch v := o.(type) {
		case core.SetTimer:
			if v.ID == core.TimerNAK {
				armed = true
			}
		case core.SendPacket:
			if v.Owned {
				v.Packet.Release()
			}
		}
	}
}

// TestPeriodicNAKModeGating proves periodic loss reporting is armed in live mode
// but suppressed in file mode (which relies on reactive NAK + RTO retransmit).
func TestPeriodicNAKModeGating(t *testing.T) {
	base := clock.Timestamp(1_000_000)
	live := core.NewEstablished(core.Config{
		PeerSocketID: 1, PayloadSize: 1200, SendISN: 100, RecvISN: 5000, MaxBW: 1 << 34, Live: true,
	}, base)
	if !armsNAKTimer(live) {
		t.Fatal("live mode did not arm the periodic-NAK timer")
	}
	file := core.NewEstablished(core.Config{
		PeerSocketID: 1, PayloadSize: 1200, SendISN: 100, RecvISN: 5000, MaxBW: 1 << 34, Congestion: "file",
	}, base)
	if armsNAKTimer(file) {
		t.Fatal("file mode armed the periodic-NAK timer; it should be suppressed")
	}
}

// concludeFlags drives a caller through induction so it emits its CONCLUSION,
// then returns the advertised SRT feature flags.
func concludeFlags(t *testing.T, dc core.DialConfig) uint32 {
	t.Helper()
	base := clock.Timestamp(1_000_000)
	dc.CallerSocketID = 7
	dc.CallerISN = 100
	c := core.Dial(dc, base)
	drainOutputs(c) // the induction request

	// Feed a minimal HSv5 induction response (magic + cookie).
	resp := packet.NewControl(nil, packet.CtrlTypeHandshake, 7, 0)
	if err := resp.MarshalCIF(&packet.CIFHandshake{
		Version: 5, ExtensionField: handshake.SRTMagic,
		HandshakeType: packet.HandshakeTypeInduction, SynCookie: 0x1234, SRTSocketID: 999,
	}); err != nil {
		t.Fatal(err)
	}
	c.HandlePacket(base, resp)

	for {
		o, ok := c.PollOutput()
		if !ok {
			break
		}
		sp, ok := o.(core.SendPacket)
		if !ok {
			continue
		}
		var flags uint32
		found := false
		if sp.Packet.Header.IsControl && sp.Packet.Header.ControlType == packet.CtrlTypeHandshake {
			var hs packet.CIFHandshake
			if err := sp.Packet.UnmarshalCIF(&hs); err == nil &&
				hs.HandshakeType == packet.HandshakeTypeConclusion && hs.SRTHS != nil {
				flags = hs.SRTHS.SRTFlags
				found = true
			}
		}
		if sp.Owned {
			sp.Packet.Release()
		}
		if found {
			return flags
		}
	}
	t.Fatal("no CONCLUSION emitted")
	return 0
}

// TestConclusionAdvertisesFlags proves the caller advertises feature flags that
// reflect its configuration (not a fixed default): a live caller advertises
// TSBPD + periodic NAK and not the byte-stream flag; a file/stream caller
// advertises the byte-stream flag and neither TSBPD nor periodic NAK.
func TestConclusionAdvertisesFlags(t *testing.T) {
	live := concludeFlags(t, core.DialConfig{Live: true})
	if live&packet.FlagTSBPDSend == 0 || live&packet.FlagTSBPDRecv == 0 {
		t.Errorf("live caller did not advertise TSBPD (flags=%#x)", live)
	}
	if live&packet.FlagPeriodicNAK == 0 {
		t.Errorf("live caller did not advertise periodic NAK (flags=%#x)", live)
	}
	if live&packet.FlagStream != 0 {
		t.Errorf("live caller advertised the byte-stream flag (flags=%#x)", live)
	}

	stream := concludeFlags(t, core.DialConfig{Congestion: "file"})
	if stream&packet.FlagStream == 0 {
		t.Errorf("stream caller did not advertise the byte-stream flag (flags=%#x)", stream)
	}
	if stream&packet.FlagTSBPDSend != 0 {
		t.Errorf("stream caller advertised TSBPD (flags=%#x)", stream)
	}
	if stream&packet.FlagPeriodicNAK != 0 {
		t.Errorf("file/stream caller advertised periodic NAK (flags=%#x)", stream)
	}
}
