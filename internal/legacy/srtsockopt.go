package legacy

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/handshake"
)

// SockOpt identifies a runtime socket option.
type SockOpt int

const (
	// SockOptMaxBW is the maximum sending bandwidth in bytes/sec.
	// Get returns int64. Set accepts int64. 0 = auto (DefaultMaxBW).
	SockOptMaxBW SockOpt = iota

	// SockOptPayloadSize is the negotiated maximum payload per packet.
	// Get only; returns int.
	SockOptPayloadSize

	// SockOptRcvLatency is the negotiated receive TSBPD latency.
	// Get only; returns time.Duration.
	SockOptRcvLatency

	// SockOptSndLatency is the peer's TSBPD latency used for sender-side drop.
	// Get only; returns time.Duration.
	SockOptSndLatency

	// SockOptState is the connection state. Get only; returns ConnState.
	SockOptState

	// SockOptPeerVersion is the peer's SRT version from the handshake.
	// Get only; returns uint32 (e.g., 0x010500 = v1.5.0).
	SockOptPeerVersion

	// SockOptStreamID is the stream identifier negotiated during handshake.
	// Get only; returns string.
	SockOptStreamID

	// SockOptMSS is the negotiated Maximum Segment Size.
	// Get only; returns int.
	SockOptMSS

	// SockOptFC is the negotiated flow control window in packets.
	// Get only; returns int.
	SockOptFC

	// SockOptInputBW is the estimated input bandwidth in bytes/sec.
	// Get/Set; accepts int64. When MaxBW=0, InputBW * (1 + overhead) is used.
	SockOptInputBW

	// --- New read-only options ---

	// SockOptISN is the local initial sequence number. Get only; returns uint32.
	SockOptISN

	// SockOptPeerISN is the peer's initial sequence number. Get only; returns uint32.
	SockOptPeerISN

	// SockOptSndKmState is the send-side key material state.
	// Get only; returns int32 (0=unsecured, 1=securing, 2=secured, 3=nosecret, 4=badsecret, 5=badcryptomode).
	SockOptSndKmState

	// SockOptRcvKmState is the recv-side key material state.
	// Get only; returns int32.
	SockOptRcvKmState

	// SockOptKmState is the combined key material state.
	// For senders returns SndKmState, for receivers returns RcvKmState.
	// Get only; returns int32.
	SockOptKmState

	// SockOptSndData is the number of unacknowledged packets in the send buffer.
	// Get only; returns int.
	SockOptSndData

	// SockOptRcvData is the number of available packets in the receive buffer.
	// Get only; returns int.
	SockOptRcvData

	// SockOptSndBuf is the send buffer capacity in packets.
	// Get only; returns int.
	SockOptSndBuf

	// SockOptRcvBuf is the receive buffer capacity in packets.
	// Get only; returns int.
	SockOptRcvBuf

	// SockOptFlightSize is the number of in-flight (unacknowledged) packets.
	// Get only; returns int.
	SockOptFlightSize

	// SockOptRTT is the smoothed round-trip time in microseconds.
	// Get only; returns int64.
	SockOptRTT

	// SockOptRTTVar is the RTT variance in microseconds.
	// Get only; returns int64.
	SockOptRTTVar

	// SockOptVersion is the local SRT version. Get only; returns uint32.
	SockOptVersion

	// SockOptCongestion is the congestion control type ("live" or "file").
	// Get only; returns string.
	SockOptCongestion

	// SockOptTransType is the transfer type. Get only; returns TransType.
	SockOptTransType

	// SockOptMessageAPI indicates whether message API mode is enabled.
	// Get only; returns bool.
	SockOptMessageAPI

	// SockOptTSBPDMode indicates whether TSBPD is enabled.
	// Get only; returns bool.
	SockOptTSBPDMode

	// SockOptTLPktDrop indicates whether too-late packet drop is enabled.
	// Get only; returns bool.
	SockOptTLPktDrop

	// SockOptNAKReport indicates whether periodic NAK reports are enabled.
	// Get only; returns bool.
	SockOptNAKReport

	// SockOptRetransmitAlgo is the retransmission algorithm (0=immediate, 1=timing gate).
	// Get only; returns int.
	SockOptRetransmitAlgo

	// SockOptPBKeyLen is the encryption key length in bytes (0, 16, 24, or 32).
	// Get only; returns int.
	SockOptPBKeyLen

	// SockOptCryptoMode is the encryption cipher mode (0=auto, 1=CTR, 2=GCM).
	// Get only; returns int.
	SockOptCryptoMode

	// SockOptPeerIdleTimeout is the peer inactivity timeout.
	// Get only; returns time.Duration.
	SockOptPeerIdleTimeout

	// SockOptLinger is the maximum time Close waits for send buffer drain.
	// Get/Set; accepts time.Duration.
	SockOptLinger

	// SockOptEvent returns poll-like event flags (SRT_EPOLL_IN/OUT/ERR).
	// Get only; returns int.
	SockOptEvent

	// SockOptDriftTracer indicates whether TSBPD drift correction is enabled.
	// Get only; returns bool.
	SockOptDriftTracer

	// SockOptPacketFilter is the negotiated FEC filter configuration string.
	// Get only; returns string.
	SockOptPacketFilter

	// SockOptMinVersion is the minimum SRT version required of the peer.
	// Get only (pre-connect option); returns uint32.
	SockOptMinVersion

	// SockOptEnforcedEncryption indicates whether encryption is enforced.
	// Get only (pre-connect option); returns bool.
	SockOptEnforcedEncryption

	// SockOptGroupConnect indicates whether the listener accepts grouped connections.
	// Get only (pre-connect option); returns bool.
	SockOptGroupConnect

	// SockOptMaxRexmitBW is the maximum retransmission bandwidth in bytes/sec.
	// Get only; returns int64.
	SockOptMaxRexmitBW

	// --- New writable options ---

	// SockOptOverheadBW is the bandwidth overhead percentage for retransmissions.
	// Get/Set; accepts int (range 5-100).
	SockOptOverheadBW

	// SockOptMinInputBW is the minimum input bandwidth floor in bytes/sec.
	// Get/Set; accepts int64.
	SockOptMinInputBW

	// SockOptSndDropDelay is the extra sender drop delay in milliseconds.
	// Get/Set; accepts int. -1 disables sender drop.
	SockOptSndDropDelay

	// SockOptLossMaxTTL is the maximum reorder tolerance in packets.
	// Get/Set; accepts int.
	SockOptLossMaxTTL

	// SockOptSndSyn controls blocking mode for Write.
	// Get/Set; accepts bool. true = blocking (default).
	SockOptSndSyn

	// SockOptRcvSyn controls blocking mode for Read.
	// Get/Set; accepts bool. true = blocking (default).
	SockOptRcvSyn

	// SockOptSndTimeo is the send timeout for non-blocking mode.
	// Get/Set; accepts time.Duration.
	SockOptSndTimeo

	// SockOptRcvTimeo is the receive timeout for non-blocking mode.
	// Get/Set; accepts time.Duration.
	SockOptRcvTimeo
)

// Poll event flags for SockOptEvent.
const (
	EventIn  = 0x1 // data available for reading
	EventOut = 0x4 // send buffer has space
	EventErr = 0x8 // connection error/broken
)

// BindingTime describes when an option may be changed.
type BindingTime int

const (
	// BindPreBind means the option cannot change after the socket is bound.
	BindPreBind BindingTime = iota
	// BindPre means the option cannot change after connect/listen.
	BindPre
	// BindPost means the option can change while connected.
	BindPost
)

// optionMeta describes the metadata for a socket option.
type optionMeta struct {
	binding  BindingTime
	readonly bool   // true = get only
	typ      string // "int", "int64", "bool", "string", "time.Duration", "uint32", "ConnState", "TransType"
}

// optionTable maps each SockOpt to its metadata.
var optionTable = map[SockOpt]optionMeta{
	// Existing options
	SockOptMaxBW:       {binding: BindPost, readonly: false, typ: "int64"},
	SockOptPayloadSize: {binding: BindPre, readonly: true, typ: "int"},
	SockOptRcvLatency:  {binding: BindPre, readonly: true, typ: "time.Duration"},
	SockOptSndLatency:  {binding: BindPre, readonly: true, typ: "time.Duration"},
	SockOptState:       {binding: BindPost, readonly: true, typ: "ConnState"},
	SockOptPeerVersion: {binding: BindPost, readonly: true, typ: "uint32"},
	SockOptStreamID:    {binding: BindPre, readonly: true, typ: "string"},
	SockOptMSS:         {binding: BindPre, readonly: true, typ: "int"},
	SockOptFC:          {binding: BindPre, readonly: true, typ: "int"},
	SockOptInputBW:     {binding: BindPost, readonly: false, typ: "int64"},

	// New read-only options
	SockOptISN:                {binding: BindPost, readonly: true, typ: "uint32"},
	SockOptPeerISN:            {binding: BindPost, readonly: true, typ: "uint32"},
	SockOptSndKmState:         {binding: BindPost, readonly: true, typ: "int32"},
	SockOptRcvKmState:         {binding: BindPost, readonly: true, typ: "int32"},
	SockOptKmState:            {binding: BindPost, readonly: true, typ: "int32"},
	SockOptSndData:            {binding: BindPost, readonly: true, typ: "int"},
	SockOptRcvData:            {binding: BindPost, readonly: true, typ: "int"},
	SockOptSndBuf:             {binding: BindPre, readonly: true, typ: "int"},
	SockOptRcvBuf:             {binding: BindPre, readonly: true, typ: "int"},
	SockOptFlightSize:         {binding: BindPost, readonly: true, typ: "int"},
	SockOptRTT:                {binding: BindPost, readonly: true, typ: "int64"},
	SockOptRTTVar:             {binding: BindPost, readonly: true, typ: "int64"},
	SockOptVersion:            {binding: BindPost, readonly: true, typ: "uint32"},
	SockOptCongestion:         {binding: BindPre, readonly: true, typ: "string"},
	SockOptTransType:          {binding: BindPre, readonly: true, typ: "TransType"},
	SockOptMessageAPI:         {binding: BindPre, readonly: true, typ: "bool"},
	SockOptTSBPDMode:          {binding: BindPre, readonly: true, typ: "bool"},
	SockOptTLPktDrop:          {binding: BindPre, readonly: true, typ: "bool"},
	SockOptNAKReport:          {binding: BindPre, readonly: true, typ: "bool"},
	SockOptRetransmitAlgo:     {binding: BindPre, readonly: true, typ: "int"},
	SockOptPBKeyLen:           {binding: BindPre, readonly: true, typ: "int"},
	SockOptCryptoMode:         {binding: BindPre, readonly: true, typ: "int"},
	SockOptPeerIdleTimeout:    {binding: BindPre, readonly: true, typ: "time.Duration"},
	SockOptLinger:             {binding: BindPost, readonly: false, typ: "time.Duration"},
	SockOptEvent:              {binding: BindPost, readonly: true, typ: "int"},
	SockOptDriftTracer:        {binding: BindPre, readonly: true, typ: "bool"},
	SockOptPacketFilter:       {binding: BindPre, readonly: true, typ: "string"},
	SockOptMinVersion:         {binding: BindPre, readonly: true, typ: "uint32"},
	SockOptEnforcedEncryption: {binding: BindPre, readonly: true, typ: "bool"},
	SockOptGroupConnect:       {binding: BindPre, readonly: true, typ: "bool"},
	SockOptMaxRexmitBW:        {binding: BindPost, readonly: true, typ: "int64"},

	// New writable options
	SockOptOverheadBW:   {binding: BindPost, readonly: false, typ: "int"},
	SockOptMinInputBW:   {binding: BindPost, readonly: false, typ: "int64"},
	SockOptSndDropDelay: {binding: BindPost, readonly: false, typ: "int"},
	SockOptLossMaxTTL:   {binding: BindPost, readonly: false, typ: "int"},
	SockOptSndSyn:       {binding: BindPost, readonly: false, typ: "bool"},
	SockOptRcvSyn:       {binding: BindPost, readonly: false, typ: "bool"},
	SockOptSndTimeo:     {binding: BindPost, readonly: false, typ: "time.Duration"},
	SockOptRcvTimeo:     {binding: BindPost, readonly: false, typ: "time.Duration"},
}

// ConnState represents the state of an SRT connection.
// Values start at 1.
type ConnState int

const (
	StateInit       ConnState = 1 // initial, unbound
	StateOpened     ConnState = 2 // bound but not listening/connecting
	StateListening  ConnState = 3 // listening for connections
	StateConnecting ConnState = 4 // connection in progress
	StateConnected  ConnState = 5 // established
	StateBroken     ConnState = 6 // broken (timeout, error)
	StateClosing    ConnState = 7 // draining
	StateClosed     ConnState = 8 // cleanly closed
	StateNonExist   ConnState = 9 // socket removed
)

// String returns a human-readable name for the connection state.
func (s ConnState) String() string {
	switch s {
	case StateInit:
		return "init"
	case StateOpened:
		return "opened"
	case StateListening:
		return "listening"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateBroken:
		return "broken"
	case StateClosing:
		return "closing"
	case StateClosed:
		return "closed"
	case StateNonExist:
		return "nonexist"
	default:
		return "unknown"
	}
}

// ErrInvalidOption is returned when an unsupported SockOpt is used.
var ErrInvalidOption = errors.New("srt: invalid socket option")

// ErrReadOnlyOption is returned when trying to Set a read-only option.
var ErrReadOnlyOption = errors.New("srt: socket option is read-only")

// ErrPreConnectOnly is returned when trying to Set a pre-connect-only option on a live connection.
var ErrPreConnectOnly = errors.New("srt: socket option can only be set before connecting")

// GetOption retrieves the current value of a runtime socket option.
// The returned value type depends on the option (see SockOpt documentation).
func (c *Conn) GetOption(opt SockOpt) (any, error) {
	select {
	case <-c.done:
		// SockOptState is allowed even after close
		if opt == SockOptState {
			return c.connState(), nil
		}
		return nil, c.getShutdownErr()
	default:
	}

	switch opt {
	case SockOptMaxBW:
		return c.sendCC.MaxBandwidth(), nil

	case SockOptPayloadSize:
		return c.payloadSize, nil

	case SockOptRcvLatency:
		return c.tsbpdDelay.Duration(), nil

	case SockOptSndLatency:
		return c.peerTsbpdDelay.Duration(), nil

	case SockOptState:
		return c.connState(), nil

	case SockOptPeerVersion:
		return c.peerSRTVersion, nil

	case SockOptStreamID:
		return c.streamID, nil

	case SockOptMSS:
		return c.payloadSize + headerOverhead, nil

	case SockOptFC:
		return c.fc, nil

	case SockOptInputBW:
		return c.inputRateBps.Load(), nil

	case SockOptISN:
		return c.sendISN.Value(), nil

	case SockOptPeerISN:
		return c.recvISN.Value(), nil

	case SockOptSndKmState:
		return c.sndKmState.Load(), nil

	case SockOptRcvKmState:
		return c.rcvKmState.Load(), nil

	case SockOptKmState:
		// For sender side, use sndKmState; for receiver side, use rcvKmState.
		// By convention, server connections are typically receivers.
		if c.isServer {
			return c.rcvKmState.Load(), nil
		}
		return c.sndKmState.Load(), nil

	case SockOptSndData:
		return c.sendBuf.Size(), nil

	case SockOptRcvData:
		return c.recvBuf.Size(), nil

	case SockOptSndBuf:
		return c.sendBuf.Capacity(), nil

	case SockOptRcvBuf:
		return c.recvBuf.Capacity(), nil

	case SockOptFlightSize:
		return c.sendBuf.Size(), nil

	case SockOptRTT:
		return c.rtt.Load(), nil

	case SockOptRTTVar:
		return c.rttVar.Load(), nil

	case SockOptVersion:
		return handshake.SRTVersion, nil

	case SockOptCongestion:
		return c.congestionType, nil

	case SockOptTransType:
		if c.congestionType == "file" {
			return TransTypeFile, nil
		}
		return TransTypeLive, nil

	case SockOptMessageAPI:
		return c.messageAPI, nil

	case SockOptTSBPDMode:
		return c.tsbpdEnabled.Load(), nil

	case SockOptTLPktDrop:
		return c.tlpktdropEnabled.Load(), nil

	case SockOptNAKReport:
		return c.periodicNAK, nil

	case SockOptRetransmitAlgo:
		return c.retransmitAlgo, nil

	case SockOptPBKeyLen:
		if c.cryptoCtx != nil {
			return c.cryptoCtx.KeyLength(), nil
		}
		return 0, nil

	case SockOptCryptoMode:
		if c.cryptoCtx != nil {
			return int(c.cryptoCtx.Mode()), nil
		}
		return 0, nil

	case SockOptPeerIdleTimeout:
		return c.peerIdleTimeout, nil

	case SockOptLinger:
		return c.linger, nil

	case SockOptEvent:
		return c.pollEvents(), nil

	case SockOptDriftTracer:
		return c.driftTracer, nil

	case SockOptPacketFilter:
		return c.packetFilter, nil

	case SockOptMinVersion:
		return c.minVersion, nil

	case SockOptEnforcedEncryption:
		return c.enforcedEncryption, nil

	case SockOptGroupConnect:
		return c.groupConnect, nil

	case SockOptMaxRexmitBW:
		if c.rexmitShaper != nil {
			return c.rexmitShaper.maxBytesPerSec, nil
		}
		return int64(0), nil

	case SockOptOverheadBW:
		return c.inputRateOverhead, nil

	case SockOptMinInputBW:
		return c.inputRateMinBW, nil

	case SockOptSndDropDelay:
		return c.sndDropDelay, nil

	case SockOptLossMaxTTL:
		return int(c.lossMaxTTL.Load()), nil

	case SockOptSndSyn:
		return c.sndSynFlag.Load(), nil

	case SockOptRcvSyn:
		return c.rcvSynFlag.Load(), nil

	case SockOptSndTimeo:
		ns := c.sndTimeout.Load()
		return time.Duration(ns), nil

	case SockOptRcvTimeo:
		ns := c.rcvTimeout.Load()
		return time.Duration(ns), nil

	default:
		return nil, fmt.Errorf("%w: %d", ErrInvalidOption, opt)
	}
}

// SetOption changes the value of a runtime socket option on a live connection.
// Only certain options support runtime changes (see SockOpt documentation).
func (c *Conn) SetOption(opt SockOpt, val any) error {
	select {
	case <-c.done:
		return c.getShutdownErr()
	default:
	}

	// Check metadata for read-only and binding restrictions
	if meta, ok := optionTable[opt]; ok {
		if meta.readonly {
			return fmt.Errorf("%w: %d", ErrReadOnlyOption, opt)
		}
	}

	switch opt {
	case SockOptMaxBW:
		bw, ok := val.(int64)
		if !ok {
			return fmt.Errorf("srt: SockOptMaxBW requires int64, got %T", val)
		}
		if bw < 0 {
			return fmt.Errorf("srt: SockOptMaxBW must be >= 0, got %d", bw)
		}
		if bw == 0 {
			bw = DefaultMaxBW
		}
		c.sendCC.SetMaxBandwidth(bw)
		return nil

	case SockOptInputBW:
		bw, ok := val.(int64)
		if !ok {
			return fmt.Errorf("srt: SockOptInputBW requires int64, got %T", val)
		}
		if bw < 0 {
			return fmt.Errorf("srt: SockOptInputBW must be >= 0, got %d", bw)
		}
		c.inputRateBps.Store(bw)
		return nil

	case SockOptOverheadBW:
		pct, ok := val.(int)
		if !ok {
			return fmt.Errorf("srt: SockOptOverheadBW requires int, got %T", val)
		}
		if pct < 5 || pct > 100 {
			return fmt.Errorf("srt: SockOptOverheadBW must be 5-100, got %d", pct)
		}
		c.inputRateOverhead = pct
		c.sendCC.SetOverhead(pct)
		return nil

	case SockOptMinInputBW:
		bw, ok := val.(int64)
		if !ok {
			return fmt.Errorf("srt: SockOptMinInputBW requires int64, got %T", val)
		}
		if bw < 0 {
			return fmt.Errorf("srt: SockOptMinInputBW must be >= 0, got %d", bw)
		}
		c.inputRateMinBW = bw
		return nil

	case SockOptSndDropDelay:
		delay, ok := val.(int)
		if !ok {
			return fmt.Errorf("srt: SockOptSndDropDelay requires int, got %T", val)
		}
		if delay < -1 {
			delay = -1
		}
		c.sndDropDelay = delay
		c.recomputeSendDropThresh()
		return nil

	case SockOptLossMaxTTL:
		ttl, ok := val.(int)
		if !ok {
			return fmt.Errorf("srt: SockOptLossMaxTTL requires int, got %T", val)
		}
		if ttl < 0 {
			ttl = 0
		}
		c.lossMaxTTL.Store(int32(ttl))
		return nil

	case SockOptSndSyn:
		v, ok := val.(bool)
		if !ok {
			return fmt.Errorf("srt: SockOptSndSyn requires bool, got %T", val)
		}
		c.sndSynFlag.Store(v)
		return nil

	case SockOptRcvSyn:
		v, ok := val.(bool)
		if !ok {
			return fmt.Errorf("srt: SockOptRcvSyn requires bool, got %T", val)
		}
		c.rcvSynFlag.Store(v)
		return nil

	case SockOptLinger:
		d, ok := val.(time.Duration)
		if !ok {
			return fmt.Errorf("srt: SockOptLinger requires time.Duration, got %T", val)
		}
		if d < 0 {
			d = 0
		}
		if d > MaxLinger {
			d = MaxLinger
		}
		c.linger = d
		return nil

	case SockOptSndTimeo:
		d, ok := val.(time.Duration)
		if !ok {
			return fmt.Errorf("srt: SockOptSndTimeo requires time.Duration, got %T", val)
		}
		if d < 0 {
			d = 0
		}
		c.sndTimeout.Store(int64(d))
		return nil

	case SockOptRcvTimeo:
		d, ok := val.(time.Duration)
		if !ok {
			return fmt.Errorf("srt: SockOptRcvTimeo requires time.Duration, got %T", val)
		}
		if d < 0 {
			d = 0
		}
		c.rcvTimeout.Store(int64(d))
		return nil

	default:
		return fmt.Errorf("%w: %d", ErrInvalidOption, opt)
	}
}

// pollEvents computes the current poll event flags.
func (c *Conn) pollEvents() int {
	var flags int

	// Check for error/broken
	select {
	case <-c.done:
		flags |= EventErr
		return flags
	default:
	}

	// Check for data available to read
	if c.recvBuf.Size() > 0 {
		flags |= EventIn
	}

	// Check for send buffer space
	if c.sendBuf.Available() > 0 {
		flags |= EventOut
	}

	return flags
}

// connState returns the current connection state.
func (c *Conn) connState() ConnState {
	select {
	case <-c.done:
		if err := c.getShutdownErr(); err != nil {
			errMsg := err.Error()
			if errMsg == "srt: connection timeout" ||
				errMsg == "srt: connection broken" {
				return StateBroken
			}
		}
		return StateClosed
	default:
		return StateConnected
	}
}

// recomputeSendDropThresh recalculates the sender drop threshold
// from the current TSBPD delay and sndDropDelay values.
func (c *Conn) recomputeSendDropThresh() {
	if !c.tsbpdEnabled.Load() || c.sndDropDelay == -1 {
		c.sendDropThresh = 0
		return
	}

	peerDelay := c.peerTsbpdDelay
	if peerDelay <= 0 {
		peerDelay = c.tsbpdDelay
	}

	extraDelay := clock.Microseconds(c.sndDropDelay) * clock.Millisecond
	thresh := peerDelay + extraDelay
	if thresh < 1*clock.Second {
		thresh = 1 * clock.Second
	}
	thresh += 20 * clock.Millisecond
	c.sendDropThresh = thresh
}

// Ensure atomic.Bool satisfies what we need (compile-time check).
var _ = (*atomic.Bool)(nil)
