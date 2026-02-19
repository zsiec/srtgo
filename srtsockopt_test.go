package srt

import (
	"errors"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/handshake"
)

func TestGetOption_MaxBW(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptMaxBW)
	if err != nil {
		t.Fatalf("GetOption(MaxBW): %v", err)
	}
	bw, ok := val.(int64)
	if !ok {
		t.Fatalf("MaxBW type = %T, want int64", val)
	}
	if bw <= 0 {
		t.Errorf("MaxBW = %d, want > 0", bw)
	}
}

func TestSetOption_MaxBW(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// Set to a specific value
	err := c.SetOption(SockOptMaxBW, int64(50_000_000))
	if err != nil {
		t.Fatalf("SetOption(MaxBW): %v", err)
	}

	// Verify it changed
	val, err := c.GetOption(SockOptMaxBW)
	if err != nil {
		t.Fatalf("GetOption(MaxBW) after set: %v", err)
	}
	bw := val.(int64)
	if bw != 50_000_000 {
		t.Errorf("MaxBW after set = %d, want 50000000", bw)
	}
}

func TestSetOption_MaxBW_Invalid(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// Wrong type
	err := c.SetOption(SockOptMaxBW, "not-an-int")
	if err == nil {
		t.Error("expected error for wrong type")
	}

	// Negative value
	err = c.SetOption(SockOptMaxBW, int64(-5))
	if err == nil {
		t.Error("expected error for negative value")
	}
}

func TestGetOption_PayloadSize(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptPayloadSize)
	if err != nil {
		t.Fatalf("GetOption(PayloadSize): %v", err)
	}
	ps, ok := val.(int)
	if !ok {
		t.Fatalf("PayloadSize type = %T, want int", val)
	}
	if ps != 1316 {
		t.Errorf("PayloadSize = %d, want 1316", ps)
	}
}

func TestGetOption_RcvLatency(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptRcvLatency)
	if err != nil {
		t.Fatalf("GetOption(RcvLatency): %v", err)
	}
	_, ok := val.(time.Duration)
	if !ok {
		t.Fatalf("RcvLatency type = %T, want time.Duration", val)
	}
}

func TestGetOption_State(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptState)
	if err != nil {
		t.Fatalf("GetOption(State): %v", err)
	}
	state, ok := val.(ConnState)
	if !ok {
		t.Fatalf("State type = %T, want ConnState", val)
	}
	if state != StateConnected {
		t.Errorf("State = %v, want StateConnected", state)
	}
}

func TestGetOption_StateAfterClose(t *testing.T) {
	c := newTestConn(t)
	c.Close()

	// After close, State should still be available (returns Closed/Broken)
	val, err := c.GetOption(SockOptState)
	if err != nil {
		t.Fatalf("GetOption(State) after close: %v", err)
	}
	state, ok := val.(ConnState)
	if !ok {
		t.Fatalf("State type = %T, want ConnState", val)
	}
	if state != StateClosed && state != StateBroken {
		t.Errorf("State after close = %v, want Closed or Broken", state)
	}

	// Other options should still return error after close
	_, err = c.GetOption(SockOptMaxBW)
	if err == nil {
		t.Error("expected error for non-State option after close")
	}
}

func TestGetOption_PeerVersion(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptPeerVersion)
	if err != nil {
		t.Fatalf("GetOption(PeerVersion): %v", err)
	}
	_, ok := val.(uint32)
	if !ok {
		t.Fatalf("PeerVersion type = %T, want uint32", val)
	}
}

func TestGetOption_StreamID(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptStreamID)
	if err != nil {
		t.Fatalf("GetOption(StreamID): %v", err)
	}
	_, ok := val.(string)
	if !ok {
		t.Fatalf("StreamID type = %T, want string", val)
	}
}

func TestSetOption_ReadOnly(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	readOnlyOpts := []SockOpt{
		SockOptPayloadSize,
		SockOptRcvLatency,
		SockOptSndLatency,
		SockOptState,
		SockOptPeerVersion,
		SockOptStreamID,
		SockOptMSS,
		SockOptFC,
	}

	for _, opt := range readOnlyOpts {
		err := c.SetOption(opt, 0)
		if err == nil {
			t.Errorf("SetOption(%d): expected error for read-only option", opt)
		}
		if !errors.Is(err, ErrReadOnlyOption) {
			t.Errorf("SetOption(%d): error = %v, want ErrReadOnlyOption", opt, err)
		}
	}
}

func TestGetOption_Invalid(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	_, err := c.GetOption(SockOpt(9999))
	if err == nil {
		t.Error("expected error for invalid option")
	}
	if !errors.Is(err, ErrInvalidOption) {
		t.Errorf("error = %v, want ErrInvalidOption", err)
	}
}

func TestConnState_String(t *testing.T) {
	tests := []struct {
		s    ConnState
		want string
	}{
		{StateInit, "init"},
		{StateOpened, "opened"},
		{StateListening, "listening"},
		{StateConnecting, "connecting"},
		{StateConnected, "connected"},
		{StateBroken, "broken"},
		{StateClosing, "closing"},
		{StateClosed, "closed"},
		{StateNonExist, "nonexist"},
		{ConnState(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("ConnState(%d).String() = %q, want %q", int(tt.s), got, tt.want)
		}
	}
}

func TestSetOption_InputBW(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	err := c.SetOption(SockOptInputBW, int64(10_000_000))
	if err != nil {
		t.Fatalf("SetOption(InputBW): %v", err)
	}

	val, err := c.GetOption(SockOptInputBW)
	if err != nil {
		t.Fatalf("GetOption(InputBW): %v", err)
	}
	bw := val.(int64)
	if bw != 10_000_000 {
		t.Errorf("InputBW = %d, want 10000000", bw)
	}
}

// ---- New socket option tests ----

func TestGetOption_ISN(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptISN)
	if err != nil {
		t.Fatalf("GetOption(ISN): %v", err)
	}
	isn, ok := val.(uint32)
	if !ok {
		t.Fatalf("ISN type = %T, want uint32", val)
	}
	// ISN should be 1 (set in newTestConn)
	if isn != 1 {
		t.Errorf("ISN = %d, want 1", isn)
	}
}

func TestGetOption_PeerISN(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptPeerISN)
	if err != nil {
		t.Fatalf("GetOption(PeerISN): %v", err)
	}
	_, ok := val.(uint32)
	if !ok {
		t.Fatalf("PeerISN type = %T, want uint32", val)
	}
}

func TestGetOption_KmStates(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// No encryption configured — should be 0 (unsecured)
	for _, opt := range []SockOpt{SockOptSndKmState, SockOptRcvKmState, SockOptKmState} {
		val, err := c.GetOption(opt)
		if err != nil {
			t.Fatalf("GetOption(%d): %v", opt, err)
		}
		state, ok := val.(int32)
		if !ok {
			t.Fatalf("KmState type = %T, want int32", val)
		}
		if state != 0 {
			t.Errorf("KmState(%d) = %d, want 0 (unsecured)", opt, state)
		}
	}
}

func TestGetOption_SndRcvData(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// Empty buffers
	val, err := c.GetOption(SockOptSndData)
	if err != nil {
		t.Fatalf("GetOption(SndData): %v", err)
	}
	if val.(int) != 0 {
		t.Errorf("SndData = %d, want 0", val.(int))
	}

	val, err = c.GetOption(SockOptRcvData)
	if err != nil {
		t.Fatalf("GetOption(RcvData): %v", err)
	}
	if val.(int) != 0 {
		t.Errorf("RcvData = %d, want 0", val.(int))
	}
}

func TestGetOption_BufferCapacities(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptSndBuf)
	if err != nil {
		t.Fatalf("GetOption(SndBuf): %v", err)
	}
	if val.(int) < 1024 {
		t.Errorf("SndBuf = %d, want >= 1024", val.(int))
	}

	val, err = c.GetOption(SockOptRcvBuf)
	if err != nil {
		t.Fatalf("GetOption(RcvBuf): %v", err)
	}
	// RecvBuffer reserves one slot, so capacity = power-of-2 - 1
	if val.(int) < 1023 {
		t.Errorf("RcvBuf = %d, want >= 1023", val.(int))
	}
}

func TestGetOption_FlightSize(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptFlightSize)
	if err != nil {
		t.Fatalf("GetOption(FlightSize): %v", err)
	}
	fs, ok := val.(int)
	if !ok {
		t.Fatalf("FlightSize type = %T, want int", val)
	}
	if fs != 0 {
		t.Errorf("FlightSize = %d, want 0", fs)
	}
}

func TestGetOption_RTT(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptRTT)
	if err != nil {
		t.Fatalf("GetOption(RTT): %v", err)
	}
	_, ok := val.(int64)
	if !ok {
		t.Fatalf("RTT type = %T, want int64", val)
	}

	val, err = c.GetOption(SockOptRTTVar)
	if err != nil {
		t.Fatalf("GetOption(RTTVar): %v", err)
	}
	_, ok = val.(int64)
	if !ok {
		t.Fatalf("RTTVar type = %T, want int64", val)
	}
}

func TestGetOption_Version(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptVersion)
	if err != nil {
		t.Fatalf("GetOption(Version): %v", err)
	}
	v, ok := val.(uint32)
	if !ok {
		t.Fatalf("Version type = %T, want uint32", val)
	}
	if v != handshake.SRTVersion {
		t.Errorf("Version = %#x, want %#x", v, handshake.SRTVersion)
	}
}

func TestGetOption_Congestion(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptCongestion)
	if err != nil {
		t.Fatalf("GetOption(Congestion): %v", err)
	}
	s, ok := val.(string)
	if !ok {
		t.Fatalf("Congestion type = %T, want string", val)
	}
	if s != "live" {
		t.Errorf("Congestion = %q, want %q", s, "live")
	}
}

func TestGetOption_TransType(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptTransType)
	if err != nil {
		t.Fatalf("GetOption(TransType): %v", err)
	}
	tt, ok := val.(TransType)
	if !ok {
		t.Fatalf("TransType type = %T, want TransType", val)
	}
	if tt != TransTypeLive {
		t.Errorf("TransType = %d, want %d (Live)", tt, TransTypeLive)
	}
}

func TestGetOption_ModeFlags(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	tests := []struct {
		opt  SockOpt
		name string
	}{
		{SockOptMessageAPI, "MessageAPI"},
		{SockOptTSBPDMode, "TSBPDMode"},
		{SockOptTLPktDrop, "TLPktDrop"},
		{SockOptNAKReport, "NAKReport"},
		{SockOptDriftTracer, "DriftTracer"},
	}

	for _, tt := range tests {
		val, err := c.GetOption(tt.opt)
		if err != nil {
			t.Fatalf("GetOption(%s): %v", tt.name, err)
		}
		_, ok := val.(bool)
		if !ok {
			t.Fatalf("%s type = %T, want bool", tt.name, val)
		}
	}
}

func TestGetOption_RetransmitAlgo(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptRetransmitAlgo)
	if err != nil {
		t.Fatalf("GetOption(RetransmitAlgo): %v", err)
	}
	_, ok := val.(int)
	if !ok {
		t.Fatalf("RetransmitAlgo type = %T, want int", val)
	}
}

func TestGetOption_PBKeyLen_NoCrypto(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptPBKeyLen)
	if err != nil {
		t.Fatalf("GetOption(PBKeyLen): %v", err)
	}
	kl, ok := val.(int)
	if !ok {
		t.Fatalf("PBKeyLen type = %T, want int", val)
	}
	if kl != 0 {
		t.Errorf("PBKeyLen = %d, want 0 (no crypto)", kl)
	}
}

func TestGetOption_CryptoMode_NoCrypto(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptCryptoMode)
	if err != nil {
		t.Fatalf("GetOption(CryptoMode): %v", err)
	}
	if val.(int) != 0 {
		t.Errorf("CryptoMode = %d, want 0 (no crypto)", val.(int))
	}
}

func TestGetOption_PeerIdleTimeout(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptPeerIdleTimeout)
	if err != nil {
		t.Fatalf("GetOption(PeerIdleTimeout): %v", err)
	}
	d, ok := val.(time.Duration)
	if !ok {
		t.Fatalf("PeerIdleTimeout type = %T, want time.Duration", val)
	}
	if d <= 0 {
		t.Errorf("PeerIdleTimeout = %v, want > 0", d)
	}
}

func TestGetOption_Event(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptEvent)
	if err != nil {
		t.Fatalf("GetOption(Event): %v", err)
	}
	flags, ok := val.(int)
	if !ok {
		t.Fatalf("Event type = %T, want int", val)
	}
	// Should have EventOut set (send buffer is empty = has space)
	if flags&EventOut == 0 {
		t.Errorf("Event flags = %d, expected EventOut set", flags)
	}
}

func TestGetOption_PacketFilter(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptPacketFilter)
	if err != nil {
		t.Fatalf("GetOption(PacketFilter): %v", err)
	}
	s, ok := val.(string)
	if !ok {
		t.Fatalf("PacketFilter type = %T, want string", val)
	}
	if s != "" {
		t.Errorf("PacketFilter = %q, want empty", s)
	}
}

func TestGetOption_MaxRexmitBW(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptMaxRexmitBW)
	if err != nil {
		t.Fatalf("GetOption(MaxRexmitBW): %v", err)
	}
	bw, ok := val.(int64)
	if !ok {
		t.Fatalf("MaxRexmitBW type = %T, want int64", val)
	}
	if bw != 0 {
		t.Errorf("MaxRexmitBW = %d, want 0 (unlimited)", bw)
	}
}

// ---- Writable option tests ----

func TestSetOption_OverheadBW(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// Valid range
	err := c.SetOption(SockOptOverheadBW, 30)
	if err != nil {
		t.Fatalf("SetOption(OverheadBW, 30): %v", err)
	}
	val, _ := c.GetOption(SockOptOverheadBW)
	if val.(int) != 30 {
		t.Errorf("OverheadBW = %d, want 30", val.(int))
	}

	// Below range
	err = c.SetOption(SockOptOverheadBW, 2)
	if err == nil {
		t.Error("expected error for OverheadBW < 5")
	}

	// Above range
	err = c.SetOption(SockOptOverheadBW, 200)
	if err == nil {
		t.Error("expected error for OverheadBW > 100")
	}

	// Wrong type
	err = c.SetOption(SockOptOverheadBW, "abc")
	if err == nil {
		t.Error("expected error for wrong type")
	}
}

func TestSetOption_MinInputBW(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	err := c.SetOption(SockOptMinInputBW, int64(5_000_000))
	if err != nil {
		t.Fatalf("SetOption(MinInputBW): %v", err)
	}
	val, _ := c.GetOption(SockOptMinInputBW)
	if val.(int64) != 5_000_000 {
		t.Errorf("MinInputBW = %d, want 5000000", val.(int64))
	}
}

func TestSetOption_SndDropDelay(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	err := c.SetOption(SockOptSndDropDelay, 100)
	if err != nil {
		t.Fatalf("SetOption(SndDropDelay): %v", err)
	}
	val, _ := c.GetOption(SockOptSndDropDelay)
	if val.(int) != 100 {
		t.Errorf("SndDropDelay = %d, want 100", val.(int))
	}

	// -1 disables
	err = c.SetOption(SockOptSndDropDelay, -1)
	if err != nil {
		t.Fatalf("SetOption(SndDropDelay, -1): %v", err)
	}
	val, _ = c.GetOption(SockOptSndDropDelay)
	if val.(int) != -1 {
		t.Errorf("SndDropDelay = %d, want -1", val.(int))
	}
}

func TestSetOption_LossMaxTTL(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	err := c.SetOption(SockOptLossMaxTTL, 10)
	if err != nil {
		t.Fatalf("SetOption(LossMaxTTL): %v", err)
	}
	val, _ := c.GetOption(SockOptLossMaxTTL)
	if val.(int) != 10 {
		t.Errorf("LossMaxTTL = %d, want 10", val.(int))
	}

	// Negative clamped to 0
	err = c.SetOption(SockOptLossMaxTTL, -5)
	if err != nil {
		t.Fatalf("SetOption(LossMaxTTL, -5): %v", err)
	}
	val, _ = c.GetOption(SockOptLossMaxTTL)
	if val.(int) != 0 {
		t.Errorf("LossMaxTTL = %d, want 0", val.(int))
	}
}

func TestSetOption_SndRcvSyn(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// Set to true
	err := c.SetOption(SockOptSndSyn, true)
	if err != nil {
		t.Fatalf("SetOption(SndSyn, true): %v", err)
	}
	val, _ := c.GetOption(SockOptSndSyn)
	if val.(bool) != true {
		t.Error("SndSyn should be true after set")
	}

	// Set to false
	err = c.SetOption(SockOptSndSyn, false)
	if err != nil {
		t.Fatalf("SetOption(SndSyn, false): %v", err)
	}
	val, _ = c.GetOption(SockOptSndSyn)
	if val.(bool) != false {
		t.Error("SndSyn should be false after set")
	}

	// Same for RcvSyn
	err = c.SetOption(SockOptRcvSyn, true)
	if err != nil {
		t.Fatalf("SetOption(RcvSyn, true): %v", err)
	}
	val, _ = c.GetOption(SockOptRcvSyn)
	if val.(bool) != true {
		t.Error("RcvSyn should be true after set")
	}

	err = c.SetOption(SockOptRcvSyn, false)
	if err != nil {
		t.Fatalf("SetOption(RcvSyn, false): %v", err)
	}
	val, _ = c.GetOption(SockOptRcvSyn)
	if val.(bool) != false {
		t.Error("RcvSyn should be false after set")
	}

	// Wrong type
	err = c.SetOption(SockOptSndSyn, "abc")
	if err == nil {
		t.Error("expected error for wrong type")
	}
}

func TestSetOption_Linger(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	err := c.SetOption(SockOptLinger, 5*time.Second)
	if err != nil {
		t.Fatalf("SetOption(Linger): %v", err)
	}
	val, _ := c.GetOption(SockOptLinger)
	if val.(time.Duration) != 5*time.Second {
		t.Errorf("Linger = %v, want 5s", val)
	}

	// Negative clamped to 0
	err = c.SetOption(SockOptLinger, -1*time.Second)
	if err != nil {
		t.Fatalf("SetOption(Linger, -1s): %v", err)
	}
	val, _ = c.GetOption(SockOptLinger)
	if val.(time.Duration) != 0 {
		t.Errorf("Linger = %v, want 0", val)
	}

	// Exceeds max clamped
	err = c.SetOption(SockOptLinger, 10*time.Minute)
	if err != nil {
		t.Fatalf("SetOption(Linger, 10m): %v", err)
	}
	val, _ = c.GetOption(SockOptLinger)
	if val.(time.Duration) != MaxLinger {
		t.Errorf("Linger = %v, want %v (capped)", val, MaxLinger)
	}
}

func TestSetOption_SndRcvTimeo(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	err := c.SetOption(SockOptSndTimeo, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("SetOption(SndTimeo): %v", err)
	}
	val, _ := c.GetOption(SockOptSndTimeo)
	if val.(time.Duration) != 500*time.Millisecond {
		t.Errorf("SndTimeo = %v, want 500ms", val)
	}

	err = c.SetOption(SockOptRcvTimeo, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("SetOption(RcvTimeo): %v", err)
	}
	val, _ = c.GetOption(SockOptRcvTimeo)
	if val.(time.Duration) != 200*time.Millisecond {
		t.Errorf("RcvTimeo = %v, want 200ms", val)
	}
}

func TestSetOption_ReadOnlyExpanded(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	readOnlyOpts := []SockOpt{
		SockOptISN,
		SockOptPeerISN,
		SockOptSndKmState,
		SockOptRcvKmState,
		SockOptKmState,
		SockOptSndData,
		SockOptRcvData,
		SockOptSndBuf,
		SockOptRcvBuf,
		SockOptFlightSize,
		SockOptRTT,
		SockOptRTTVar,
		SockOptVersion,
		SockOptCongestion,
		SockOptTransType,
		SockOptMessageAPI,
		SockOptTSBPDMode,
		SockOptTLPktDrop,
		SockOptNAKReport,
		SockOptRetransmitAlgo,
		SockOptPBKeyLen,
		SockOptCryptoMode,
		SockOptPeerIdleTimeout,
		SockOptEvent,
		SockOptDriftTracer,
		SockOptPacketFilter,
		SockOptMinVersion,
		SockOptEnforcedEncryption,
		SockOptGroupConnect,
		SockOptMaxRexmitBW,
	}

	for _, opt := range readOnlyOpts {
		err := c.SetOption(opt, 0)
		if err == nil {
			t.Errorf("SetOption(%d): expected error for read-only option", opt)
		}
		if !errors.Is(err, ErrReadOnlyOption) {
			t.Errorf("SetOption(%d): error = %v, want ErrReadOnlyOption", opt, err)
		}
	}
}

func TestOptionTableCompleteness(t *testing.T) {
	// Every SockOpt that GetOption handles should have a table entry
	allOpts := []SockOpt{
		SockOptMaxBW, SockOptPayloadSize, SockOptRcvLatency, SockOptSndLatency,
		SockOptState, SockOptPeerVersion, SockOptStreamID, SockOptMSS, SockOptFC,
		SockOptInputBW, SockOptISN, SockOptPeerISN, SockOptSndKmState,
		SockOptRcvKmState, SockOptKmState, SockOptSndData, SockOptRcvData,
		SockOptSndBuf, SockOptRcvBuf, SockOptFlightSize, SockOptRTT, SockOptRTTVar,
		SockOptVersion, SockOptCongestion, SockOptTransType, SockOptMessageAPI,
		SockOptTSBPDMode, SockOptTLPktDrop, SockOptNAKReport, SockOptRetransmitAlgo,
		SockOptPBKeyLen, SockOptCryptoMode, SockOptPeerIdleTimeout, SockOptLinger,
		SockOptEvent, SockOptDriftTracer, SockOptPacketFilter, SockOptMinVersion,
		SockOptEnforcedEncryption, SockOptGroupConnect, SockOptMaxRexmitBW,
		SockOptOverheadBW, SockOptMinInputBW, SockOptSndDropDelay, SockOptLossMaxTTL,
		SockOptSndSyn, SockOptRcvSyn, SockOptSndTimeo, SockOptRcvTimeo,
	}

	for _, opt := range allOpts {
		if _, ok := optionTable[opt]; !ok {
			t.Errorf("SockOpt %d missing from optionTable", opt)
		}
	}
}

func TestGetOption_ConfigDerivedOptions(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// MinVersion
	val, err := c.GetOption(SockOptMinVersion)
	if err != nil {
		t.Fatalf("GetOption(MinVersion): %v", err)
	}
	if _, ok := val.(uint32); !ok {
		t.Fatalf("MinVersion type = %T, want uint32", val)
	}

	// EnforcedEncryption
	val, err = c.GetOption(SockOptEnforcedEncryption)
	if err != nil {
		t.Fatalf("GetOption(EnforcedEncryption): %v", err)
	}
	if _, ok := val.(bool); !ok {
		t.Fatalf("EnforcedEncryption type = %T, want bool", val)
	}

	// GroupConnect
	val, err = c.GetOption(SockOptGroupConnect)
	if err != nil {
		t.Fatalf("GetOption(GroupConnect): %v", err)
	}
	if _, ok := val.(bool); !ok {
		t.Fatalf("GroupConnect type = %T, want bool", val)
	}
}

func TestErrPreConnectOnly(t *testing.T) {
	// Verify the error exists and wraps correctly
	if ErrPreConnectOnly == nil {
		t.Fatal("ErrPreConnectOnly is nil")
	}
	if ErrPreConnectOnly.Error() != "srt: socket option can only be set before connecting" {
		t.Errorf("ErrPreConnectOnly = %q", ErrPreConnectOnly.Error())
	}
}

func TestPollEvents(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	flags := c.pollEvents()

	// Send buffer should have space (EventOut)
	if flags&EventOut == 0 {
		t.Error("expected EventOut to be set for empty send buffer")
	}

	// No data available (EventIn should not be set)
	if flags&EventIn != 0 {
		t.Error("expected EventIn to not be set for empty recv buffer")
	}

	// Not broken (EventErr should not be set)
	if flags&EventErr != 0 {
		t.Error("expected EventErr to not be set for healthy connection")
	}
}

func TestPollEvents_AfterClose(t *testing.T) {
	c := newTestConn(t)
	c.Close()

	flags := c.pollEvents()
	if flags&EventErr == 0 {
		t.Error("expected EventErr to be set after close")
	}
}

func TestConnStateString(t *testing.T) {
	tests := []struct {
		state ConnState
		want  string
	}{
		{StateInit, "init"},
		{StateOpened, "opened"},
		{StateListening, "listening"},
		{StateConnecting, "connecting"},
		{StateConnected, "connected"},
		{StateBroken, "broken"},
		{StateClosing, "closing"},
		{StateClosed, "closed"},
		{StateNonExist, "nonexist"},
		{ConnState(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.want {
			t.Errorf("ConnState(%d).String(): got %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestSetOption_InvalidOption(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	err := c.SetOption(SockOpt(9999), 42)
	if err == nil {
		t.Error("expected error for invalid option on SetOption")
	}
	if !errors.Is(err, ErrInvalidOption) {
		t.Errorf("error = %v, want ErrInvalidOption", err)
	}
}

func TestSetOption_InputBW_Invalid(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// Wrong type
	err := c.SetOption(SockOptInputBW, "not-int64")
	if err == nil {
		t.Error("expected error for wrong type")
	}

	// Negative value
	err = c.SetOption(SockOptInputBW, int64(-1))
	if err == nil {
		t.Error("expected error for negative value")
	}
}

func TestSetOption_MinInputBW_Invalid(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// Wrong type
	err := c.SetOption(SockOptMinInputBW, "wrong")
	if err == nil {
		t.Error("expected error for wrong type")
	}

	// Negative value
	err = c.SetOption(SockOptMinInputBW, int64(-1))
	if err == nil {
		t.Error("expected error for negative value")
	}
}

func TestSetOption_SndDropDelay_Invalid(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// Wrong type
	err := c.SetOption(SockOptSndDropDelay, "wrong")
	if err == nil {
		t.Error("expected error for wrong type")
	}
}

func TestSetOption_SndDropDelay_Clamp(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// Very negative value should clamp to -1
	err := c.SetOption(SockOptSndDropDelay, -10)
	if err != nil {
		t.Fatalf("SetOption(SndDropDelay, -10): %v", err)
	}
	val, _ := c.GetOption(SockOptSndDropDelay)
	if val.(int) != -1 {
		t.Errorf("SndDropDelay = %d, want -1 (clamped)", val.(int))
	}
}

func TestSetOption_LossMaxTTL_Invalid(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// Wrong type
	err := c.SetOption(SockOptLossMaxTTL, "wrong")
	if err == nil {
		t.Error("expected error for wrong type")
	}
}

func TestSetOption_RcvSyn_Invalid(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	err := c.SetOption(SockOptRcvSyn, "wrong")
	if err == nil {
		t.Error("expected error for wrong type")
	}
}

func TestSetOption_Linger_Invalid(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	err := c.SetOption(SockOptLinger, "wrong")
	if err == nil {
		t.Error("expected error for wrong type")
	}
}

func TestSetOption_SndTimeo_Invalid(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	err := c.SetOption(SockOptSndTimeo, "wrong")
	if err == nil {
		t.Error("expected error for wrong type")
	}
}

func TestSetOption_RcvTimeo_Invalid(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	err := c.SetOption(SockOptRcvTimeo, "wrong")
	if err == nil {
		t.Error("expected error for wrong type")
	}
}

func TestSetOption_SndTimeo_ClampNeg(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	err := c.SetOption(SockOptSndTimeo, -1*time.Second)
	if err != nil {
		t.Fatalf("SetOption(SndTimeo, -1s): %v", err)
	}
	val, _ := c.GetOption(SockOptSndTimeo)
	if val.(time.Duration) != 0 {
		t.Errorf("SndTimeo = %v, want 0 (clamped)", val)
	}
}

func TestSetOption_RcvTimeo_ClampNeg(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	err := c.SetOption(SockOptRcvTimeo, -1*time.Second)
	if err != nil {
		t.Fatalf("SetOption(RcvTimeo, -1s): %v", err)
	}
	val, _ := c.GetOption(SockOptRcvTimeo)
	if val.(time.Duration) != 0 {
		t.Errorf("RcvTimeo = %v, want 0 (clamped)", val)
	}
}

func TestSetOption_MaxBW_Zero(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// Zero should be treated as DefaultMaxBW
	err := c.SetOption(SockOptMaxBW, int64(0))
	if err != nil {
		t.Fatalf("SetOption(MaxBW, 0): %v", err)
	}
	val, _ := c.GetOption(SockOptMaxBW)
	if val.(int64) != DefaultMaxBW {
		t.Errorf("MaxBW = %d, want %d (DefaultMaxBW)", val.(int64), DefaultMaxBW)
	}
}

func TestSetOption_AfterClose(t *testing.T) {
	c := newTestConn(t)
	c.Close()

	err := c.SetOption(SockOptMaxBW, int64(100))
	if err == nil {
		t.Error("expected error for SetOption after Close")
	}
}

func TestGetOption_SndLatency(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptSndLatency)
	if err != nil {
		t.Fatalf("GetOption(SndLatency): %v", err)
	}
	_, ok := val.(time.Duration)
	if !ok {
		t.Fatalf("SndLatency type = %T, want time.Duration", val)
	}
}

func TestGetOption_Linger(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	val, err := c.GetOption(SockOptLinger)
	if err != nil {
		t.Fatalf("GetOption(Linger): %v", err)
	}
	_, ok := val.(time.Duration)
	if !ok {
		t.Fatalf("Linger type = %T, want time.Duration", val)
	}
}

func TestGetOption_KmState_Server(t *testing.T) {
	c := newTestConn(t)
	defer c.Close()

	// newTestConn creates a server-side conn (isServer=true)
	val, err := c.GetOption(SockOptKmState)
	if err != nil {
		t.Fatalf("GetOption(KmState): %v", err)
	}
	// For server, KmState uses rcvKmState
	if _, ok := val.(int32); !ok {
		t.Fatalf("KmState type = %T, want int32", val)
	}
}

func TestGetOption_TransType_File(t *testing.T) {
	// Create a file-mode conn
	c := newTestConn(t)
	defer c.Close()

	c.congestionType = "file"
	val, err := c.GetOption(SockOptTransType)
	if err != nil {
		t.Fatalf("GetOption(TransType): %v", err)
	}
	tt, ok := val.(TransType)
	if !ok {
		t.Fatalf("TransType type = %T, want TransType", val)
	}
	if tt != TransTypeFile {
		t.Errorf("TransType = %d, want TransTypeFile", tt)
	}
}
