package srt

import (
	"errors"
	"fmt"
	"time"

	"github.com/zsiec/srtgo/internal/handshake"
)

// SockOpt identifies a runtime socket option.
type SockOpt int

const (
	SockOptMaxBW       SockOpt = iota // int64: max sending bandwidth bytes/sec (0=auto)
	SockOptPayloadSize                // int (get): negotiated payload per packet
	SockOptRcvLatency                 // time.Duration (get): negotiated receive TSBPD latency
	SockOptSndLatency                 // time.Duration (get): peer's TSBPD latency
	SockOptState                      // ConnState (get)
	SockOptPeerVersion                // uint32 (get): peer SRT version
	SockOptStreamID                   // string (get)
	SockOptMSS                        // int (get)
	SockOptFC                         // int (get): flow window
	SockOptInputBW                    // int64: estimated input bandwidth bytes/sec

	SockOptISN            // uint32 (get): local initial sequence number
	SockOptPeerISN        // uint32 (get): peer initial sequence number
	SockOptSndKmState     // int32 (get)
	SockOptRcvKmState     // int32 (get)
	SockOptKmState        // int32 (get)
	SockOptSndData        // int (get): unacked packets in send buffer
	SockOptRcvData        // int (get): available packets in receive buffer
	SockOptSndBuf         // int (get): send buffer capacity
	SockOptRcvBuf         // int (get): receive buffer capacity
	SockOptFlightSize     // int (get): in-flight packets
	SockOptRTT            // int64 (get): smoothed RTT microseconds
	SockOptRTTVar         // int64 (get): RTT variance microseconds
	SockOptVersion        // uint32 (get): local SRT version
	SockOptCongestion     // string (get): "live"/"file"
	SockOptTransType      // TransType (get)
	SockOptMessageAPI     // bool (get)
	SockOptTSBPDMode      // bool (get)
	SockOptTLPktDrop      // bool (get)
	SockOptNAKReport      // bool (get)
	SockOptRetransmitAlgo // int (get)
	SockOptPBKeyLen       // int (get): encryption key length
	SockOptCryptoMode     // int (get): cipher mode
	SockOptPeerIdleTimeout
	SockOptLinger             // time.Duration: Close drain timeout
	SockOptEvent              // int (get): poll event flags
	SockOptDriftTracer        // bool (get)
	SockOptPacketFilter       // string (get): negotiated FEC filter
	SockOptMinVersion         // uint32 (get)
	SockOptEnforcedEncryption // bool (get)
	SockOptGroupConnect       // bool (get)
	SockOptMaxRexmitBW        // int64 (get)
	SockOptOverheadBW         // int: retransmit overhead %
	SockOptMinInputBW         // int64: min input bandwidth floor
	SockOptSndDropDelay       // int: extra sender drop delay ms
	SockOptLossMaxTTL         // int: reorder tolerance packets
	SockOptSndSyn             // bool: blocking Write
	SockOptRcvSyn             // bool: blocking Read
	SockOptSndTimeo           // time.Duration: send timeout (non-blocking)
	SockOptRcvTimeo           // time.Duration: receive timeout (non-blocking)
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
	BindPreBind BindingTime = iota // cannot change after bind
	BindPre                        // cannot change after connect/listen
	BindPost                       // can change while connected
)

type optionMeta struct {
	binding  BindingTime
	readonly bool
}

var optionTable = map[SockOpt]optionMeta{
	SockOptMaxBW:              {BindPost, false},
	SockOptPayloadSize:        {BindPre, true},
	SockOptRcvLatency:         {BindPre, true},
	SockOptSndLatency:         {BindPre, true},
	SockOptState:              {BindPost, true},
	SockOptPeerVersion:        {BindPost, true},
	SockOptStreamID:           {BindPre, true},
	SockOptMSS:                {BindPre, true},
	SockOptFC:                 {BindPre, true},
	SockOptInputBW:            {BindPost, false},
	SockOptISN:                {BindPost, true},
	SockOptPeerISN:            {BindPost, true},
	SockOptSndKmState:         {BindPost, true},
	SockOptRcvKmState:         {BindPost, true},
	SockOptKmState:            {BindPost, true},
	SockOptSndData:            {BindPost, true},
	SockOptRcvData:            {BindPost, true},
	SockOptSndBuf:             {BindPre, true},
	SockOptRcvBuf:             {BindPre, true},
	SockOptFlightSize:         {BindPost, true},
	SockOptRTT:                {BindPost, true},
	SockOptRTTVar:             {BindPost, true},
	SockOptVersion:            {BindPost, true},
	SockOptCongestion:         {BindPre, true},
	SockOptTransType:          {BindPre, true},
	SockOptMessageAPI:         {BindPre, true},
	SockOptTSBPDMode:          {BindPre, true},
	SockOptTLPktDrop:          {BindPre, true},
	SockOptNAKReport:          {BindPre, true},
	SockOptRetransmitAlgo:     {BindPre, true},
	SockOptPBKeyLen:           {BindPre, true},
	SockOptCryptoMode:         {BindPre, true},
	SockOptPeerIdleTimeout:    {BindPre, true},
	SockOptLinger:             {BindPost, false},
	SockOptEvent:              {BindPost, true},
	SockOptDriftTracer:        {BindPre, true},
	SockOptPacketFilter:       {BindPre, true},
	SockOptMinVersion:         {BindPre, true},
	SockOptEnforcedEncryption: {BindPre, true},
	SockOptGroupConnect:       {BindPre, true},
	SockOptMaxRexmitBW:        {BindPost, true},
	SockOptOverheadBW:         {BindPost, false},
	SockOptMinInputBW:         {BindPost, false},
	SockOptSndDropDelay:       {BindPost, false},
	SockOptLossMaxTTL:         {BindPost, false},
	SockOptSndSyn:             {BindPost, false},
	SockOptRcvSyn:             {BindPost, false},
	SockOptSndTimeo:           {BindPost, false},
	SockOptRcvTimeo:           {BindPost, false},
}

// ConnState represents the state of an SRT connection. Values start at 1.
type ConnState int

const (
	StateInit       ConnState = 1
	StateOpened     ConnState = 2
	StateListening  ConnState = 3
	StateConnecting ConnState = 4
	StateConnected  ConnState = 5
	StateBroken     ConnState = 6
	StateClosing    ConnState = 7
	StateClosed     ConnState = 8
	StateNonExist   ConnState = 9
)

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

// GetOption retrieves the current value of a socket option. The returned type
// depends on the option (see the SockOpt constants).
func (c *Conn) GetOption(opt SockOpt) (any, error) {
	st, statsErr := c.s.Stats()
	switch opt {
	case SockOptState:
		if statsErr != nil {
			return StateClosed, nil
		}
		return StateConnected, nil
	case SockOptStreamID:
		return c.s.StreamID(), nil
	case SockOptMaxBW:
		return c.cfg.MaxBW, nil
	case SockOptInputBW:
		return c.cfg.InputBW, nil
	case SockOptMinInputBW:
		return c.cfg.MinInputBW, nil
	case SockOptMaxRexmitBW:
		return c.cfg.MaxRexmitBW, nil
	case SockOptOverheadBW:
		return c.cfg.OverheadBW, nil
	case SockOptPayloadSize:
		if c.cfg.PayloadSize > 0 {
			return c.cfg.PayloadSize, nil
		}
		return c.cfg.MSS - 44, nil
	case SockOptMSS:
		return c.cfg.MSS, nil
	case SockOptSndBuf:
		return c.cfg.SendBufSize, nil
	case SockOptRcvBuf:
		return c.cfg.RecvBufSize, nil
	case SockOptRcvLatency:
		return c.cfg.RecvLatency, nil
	case SockOptSndLatency:
		return c.cfg.PeerLatency, nil
	case SockOptPeerIdleTimeout:
		return c.cfg.PeerIdleTimeout, nil
	case SockOptLinger:
		return c.cfg.Linger, nil
	case SockOptCongestion:
		return string(c.cfg.Congestion), nil
	case SockOptTransType:
		if c.cfg.Congestion == CongestionFile {
			return TransTypeFile, nil
		}
		return TransTypeLive, nil
	case SockOptMessageAPI:
		return c.cfg.messageAPIEnabled(), nil
	case SockOptTSBPDMode:
		return c.cfg.tsbpdEnabled(), nil
	case SockOptTLPktDrop:
		return c.cfg.tlpktdropEnabled(), nil
	case SockOptNAKReport:
		return !c.cfg.nakReportOff(), nil
	case SockOptRetransmitAlgo:
		return c.cfg.retransmitAlgo(), nil
	case SockOptDriftTracer:
		return c.cfg.driftTracerEnabled(), nil
	case SockOptPacketFilter:
		return c.cfg.PacketFilter, nil
	case SockOptMinVersion:
		return c.cfg.MinVersion, nil
	case SockOptEnforcedEncryption:
		return !c.cfg.enforcedEncryptionOff(), nil
	case SockOptGroupConnect:
		return c.cfg.GroupConnect, nil
	case SockOptSndDropDelay:
		return c.cfg.SndDropDelay, nil
	case SockOptLossMaxTTL:
		return c.cfg.LossMaxTTL, nil
	case SockOptCryptoMode:
		return c.cfg.CryptoMode, nil
	case SockOptPBKeyLen:
		if c.cfg.Passphrase != "" {
			return c.cfg.KeyLength, nil
		}
		return 0, nil
	case SockOptVersion:
		return uint32(handshake.SRTVersion), nil
	case SockOptSndSyn:
		return c.sndSyn, nil
	case SockOptRcvSyn:
		return c.rcvSyn, nil
	case SockOptSndTimeo:
		return c.sndTimeo, nil
	case SockOptRcvTimeo:
		return c.rcvTimeo, nil
	case SockOptISN:
		return c.s.SendISN(), nil
	case SockOptPeerISN:
		return c.s.RecvISN(), nil
	case SockOptPeerVersion:
		return c.s.PeerVersion(), nil
	case SockOptEvent:
		ev := 0
		if c.s.ReadReady() {
			ev |= EventIn
		}
		if c.s.WriteReady() {
			ev |= EventOut
		}
		if !c.s.Alive() {
			ev |= EventErr
		}
		return ev, nil
	}

	// Live values require a stats snapshot.
	if statsErr != nil {
		return nil, statsErr
	}
	switch opt {
	case SockOptFC:
		return st.FlowWindow, nil
	case SockOptSndData:
		return st.SendBufPackets, nil
	case SockOptRcvData:
		return st.RecvBufPackets, nil
	case SockOptFlightSize:
		return st.FlightSize, nil
	case SockOptRTT:
		return st.RTTMicros, nil
	case SockOptRTTVar:
		return st.RTTVarMicros, nil
	case SockOptSndKmState:
		return int32(st.SndKmState), nil
	case SockOptRcvKmState:
		return int32(st.RcvKmState), nil
	case SockOptKmState:
		if c.isServer {
			return int32(st.RcvKmState), nil
		}
		return int32(st.SndKmState), nil
	}
	return nil, fmt.Errorf("%w: %d", ErrInvalidOption, opt)
}

// SetOption changes a writable socket option on a live connection. Read-only
// options return ErrReadOnlyOption; unknown options return ErrInvalidOption.
//
// NOTE(cutover): the rate/CC knobs (MaxBW/InputBW/OverheadBW/MinInputBW/
// SndDropDelay/LossMaxTTL) update the stored config so GetOption round-trips,
// but runtime re-application to the running core is a follow-up (it needs a
// loop control hook). Blocking modes and linger take effect immediately.
func (c *Conn) SetOption(opt SockOpt, val any) error {
	if meta, ok := optionTable[opt]; ok {
		if meta.readonly {
			return fmt.Errorf("%w: %d", ErrReadOnlyOption, opt)
		}
	} else {
		return fmt.Errorf("%w: %d", ErrInvalidOption, opt)
	}

	switch opt {
	case SockOptMaxBW:
		v, ok := val.(int64)
		if !ok || v < 0 {
			return fmt.Errorf("srt: SockOptMaxBW requires a non-negative int64, got %v", val)
		}
		c.cfg.MaxBW = v
		c.s.SetMaxBW(v)
	case SockOptInputBW:
		v, ok := val.(int64)
		if !ok || v < 0 {
			return fmt.Errorf("srt: SockOptInputBW requires a non-negative int64, got %v", val)
		}
		c.cfg.InputBW = v
		c.s.SetInputBW(v)
	case SockOptMinInputBW:
		v, ok := val.(int64)
		if !ok || v < 0 {
			return fmt.Errorf("srt: SockOptMinInputBW requires a non-negative int64, got %v", val)
		}
		c.cfg.MinInputBW = v
	case SockOptOverheadBW:
		v, ok := val.(int)
		if !ok || v < 5 || v > 100 {
			return fmt.Errorf("srt: SockOptOverheadBW requires an int in 5..100, got %v", val)
		}
		c.cfg.OverheadBW = v
		c.s.SetOverhead(v)
	case SockOptSndDropDelay:
		v, ok := val.(int)
		if !ok {
			return fmt.Errorf("srt: SockOptSndDropDelay requires an int, got %v", val)
		}
		c.cfg.SndDropDelay = v
		c.s.SetSndDropDelay(v)
	case SockOptLossMaxTTL:
		v, ok := val.(int)
		if !ok || v < 0 {
			return fmt.Errorf("srt: SockOptLossMaxTTL requires a non-negative int, got %v", val)
		}
		c.cfg.LossMaxTTL = v
		c.s.SetReorderTolerance(v)
	case SockOptLinger:
		v, ok := val.(time.Duration)
		if !ok {
			return fmt.Errorf("srt: SockOptLinger requires a time.Duration, got %v", val)
		}
		if v < 0 {
			v = 0
		}
		c.cfg.Linger = v
		c.s.SetLinger(v)
	case SockOptSndSyn:
		v, ok := val.(bool)
		if !ok {
			return fmt.Errorf("srt: SockOptSndSyn requires a bool, got %v", val)
		}
		c.sndSyn = v
		c.s.SetWriteBlocking(v)
	case SockOptRcvSyn:
		v, ok := val.(bool)
		if !ok {
			return fmt.Errorf("srt: SockOptRcvSyn requires a bool, got %v", val)
		}
		c.rcvSyn = v
		c.s.SetReadBlocking(v)
	case SockOptSndTimeo:
		v, ok := val.(time.Duration)
		if !ok {
			return fmt.Errorf("srt: SockOptSndTimeo requires a time.Duration, got %v", val)
		}
		c.sndTimeo = v
	case SockOptRcvTimeo:
		v, ok := val.(time.Duration)
		if !ok {
			return fmt.Errorf("srt: SockOptRcvTimeo requires a time.Duration, got %v", val)
		}
		c.rcvTimeo = v
	default:
		return fmt.Errorf("%w: %d", ErrInvalidOption, opt)
	}
	return nil
}
