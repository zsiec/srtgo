package srt

import (
	"errors"
	"time"

	"github.com/zsiec/srtgo/internal/filter"
	"github.com/zsiec/srtgo/internal/packet"
)

// Default configuration values.
const (
	DefaultLatency         = 120 * time.Millisecond   // minimum TSBPD delay
	DefaultMSS             = 1500                     // maximum segment size
	DefaultFC              = 25600                    // flow control window (packets)
	DefaultSendBufSize     = 8192                     // send buffer size (packets)
	DefaultRecvBufSize     = 8192                     // receive buffer size (packets)
	DefaultMaxBW           = int64(1_000_000_000 / 8) // 1 Gbps = 125 MB/s
	DefaultOverheadBW      = 25                       // 25% overhead for retransmissions
	DefaultConnTimeout     = 3 * time.Second          // handshake timeout
	DefaultPeerIdleTimeout = 5 * time.Second          // peer inactivity timeout
	MaxLinger              = 180 * time.Second        // maximum linger duration (3 minutes)

	DefaultKMRefreshRate = uint64(1 << 24) // 16.7M packets before key switch
	DefaultKMPreAnnounce = uint64(1 << 16) // 64K packets before refresh to announce new key

	MinMSS     = 76 // minimum MSS (IP header + UDP header + SRT header)
	MaxMSS     = 1500
	MinPayload = 32 // minimum payload size after header overhead
	MinLatency = 20 * time.Millisecond

	MinBufSize = 32 // minimum send/recv buffer size (packets)
	MinFC      = 32 // minimum flow control window (packets)
)

// TransType selects a bundle of settings optimized for a transfer pattern.
type TransType int

const (
	// TransTypeLive is the default: TSBPD=on, TLPKTDROP=on, LiveCC, MessageAPI=true.
	TransTypeLive TransType = iota

	// TransTypeFile disables TSBPD and TLPKTDROP, uses FileCC, MessageAPI=false.
	TransTypeFile
)

// CongestionType selects the congestion control algorithm.
type CongestionType string

const (
	// CongestionLive selects fixed-rate pacing (default).
	CongestionLive CongestionType = "live"

	// CongestionFile selects CUBIC-like adaptive congestion control.
	CongestionFile CongestionType = "file"
)

// Config contains SRT connection configuration.
type Config struct {
	// Latency is the TSBPD latency (receive delay).
	// The actual latency used is max(local, remote) during negotiation.
	// Default: 120ms. Minimum: 20ms.
	// If RecvLatency or PeerLatency are set, they override this value
	// for their respective directions.
	Latency time.Duration

	// RecvLatency is the TSBPD latency for receiving data (SRTO_RCVLATENCY).
	// If zero, defaults to Latency.
	RecvLatency time.Duration

	// PeerLatency is the minimum TSBPD latency requested of the peer (SRTO_PEERLATENCY).
	// If zero, defaults to Latency.
	PeerLatency time.Duration

	// MSS is the Maximum Segment Size (MTU - IP - UDP headers).
	// Negotiated to the smaller of the two sides.
	// Default: 1500. Range: 76-1500.
	MSS int

	// FC is the flow control window in packets.
	// Default: 25600.
	FC int

	// MaxBW is the maximum sending bandwidth in bytes per second.
	// When > 0, used directly (no overhead applied).
	// When 0 and InputBW > 0, InputBW * (1 + OverheadBW/100) is used.
	// When 0 and InputBW == 0, defaults to 125 MB/s (1 Gbps).
	MaxBW int64

	// OverheadBW is the bandwidth overhead percentage for retransmissions.
	// Range: 5-100. Default: 25.
	OverheadBW int

	// SendBufSize is the send buffer size in packets.
	// Default: 8192.
	SendBufSize int

	// RecvBufSize is the receive buffer size in packets.
	// Default: 8192.
	RecvBufSize int

	// PayloadSize is the maximum payload size per packet (SRTO_PAYLOADSIZE).
	// When 0 (default), derived from MSS: MSS - 44 (IP 20 + UDP 8 + SRT 16).
	// When set, must be <= MSS - 44. Used for CC pacing and fragmentation limit.
	PayloadSize int

	// StreamID is the stream identifier sent during the handshake.
	// Maximum 512 bytes. Used by the listener to route/authorize connections.
	StreamID string

	// Passphrase enables encryption. Must be 10-80 bytes if set.
	Passphrase string

	// KeyLength is the AES key size in bytes: 16 (AES-128), 24 (AES-192), or 32 (AES-256).
	// Default: 16. Only used when Passphrase is set.
	KeyLength int

	// CryptoMode selects the encryption cipher mode.
	// 0 = auto (responder adopts initiator's mode), 1 = AES-CTR, 2 = AES-GCM.
	// Default: 0 (auto, which defaults to CTR for initiators).
	// SRTO_CRYPTOMODE: CIPHER_MODE_AUTO=0, CIPHER_MODE_AES_CTR=1, CIPHER_MODE_AES_GCM=2.
	CryptoMode int

	// ConnTimeout is the handshake timeout.
	// Default: 3s.
	ConnTimeout time.Duration

	// Linger is the maximum time Close() will wait for the send buffer
	// to drain before shutting down. Default: 0 (immediate close).
	// Maximum: 3s.
	Linger time.Duration

	// PeerIdleTimeout is the duration of peer inactivity (no packets received)
	// before the connection is considered timed out.
	// Default: 5s. Minimum: 1s.
	PeerIdleTimeout time.Duration

	// KMRefreshRate is the number of packets sent before switching to a new
	// encryption key. Set to 0 to disable key rotation.
	// Default: 2^24 (~16.7M packets).
	KMRefreshRate uint64

	// KMPreAnnounce is the number of packets before the refresh point at
	// which the new key is announced to the peer via KMREQ.
	// Must be less than KMRefreshRate/2. Default: 2^16 (65536 packets).
	KMPreAnnounce uint64

	// MessageAPI enables message-oriented delivery (default: true for live mode).
	// When true, each Write/Read preserves message boundaries.
	// When false, data is treated as a byte stream (FlagStream in handshake).
	MessageAPI *bool

	// TransType selects a bundle of settings. TransTypeFile overrides
	// Congestion to "file" and sets appropriate defaults.
	// Default: TransTypeLive.
	TransType TransType

	// Congestion selects the congestion control algorithm: "live" or "file".
	// Overridden by TransType if set to TransTypeFile.
	// Default: "live".
	Congestion CongestionType

	// MinVersion is the minimum SRT version required of the peer (SRTO_MINVERSION).
	// Connections from peers with a lower version are rejected.
	// Default: 0x010000 (1.0.0).
	MinVersion uint32

	// LossMaxTTL is the maximum reorder tolerance in packets (SRTO_LOSSMAXTTL).
	// When > 0, enables the FreshLoss mechanism: NAK is deferred for up to this
	// many received packets to allow out-of-order arrivals before reporting loss.
	// Default: 0 (immediate NAK, no reorder tolerance).
	LossMaxTTL int

	// SndDropDelay is extra sender drop delay in milliseconds (SRTO_SNDDROPDELAY).
	// Added to the TSBPD latency when computing the sender-side drop threshold.
	// Set to -1 to disable sender-side too-late drop entirely.
	// Default: 0.
	SndDropDelay int

	// EnforcedEncryption when true (default), requires both sides to use
	// matching encryption. When false, allows mixed encrypted/unencrypted
	// connections (SRTO_ENFORCEDENCRYPTION).
	EnforcedEncryption *bool

	// NAKReport when true (default for live mode), enables periodic NAK reports.
	// When false, only immediate NAKs are sent on gap detection.
	// Always false for file mode (SRTO_NAKREPORT).
	NAKReport *bool

	// RetransmitAlgo selects the retransmission algorithm (SRTO_RETRANSMITALGO).
	// 0 = always immediate retransmit on NAK (no timing gate).
	// 1 = timing gate: skip retransmit if packet was recently sent (default for live).
	// Default: 1 for live mode, 0 for file mode.
	RetransmitAlgo *int

	// DriftTracer when true (default), enables TSBPD drift correction.
	// When false, drift compensation is disabled (SRTO_DRIFTTRACER).
	DriftTracer *bool

	// IPTTL sets the IP Time-To-Live for outgoing packets (SRTO_IPTTL).
	// Default: -1 (use OS default). Range: 1-255.
	IPTTL int

	// IPTOS sets the IP Type-Of-Service / DiffServ field (SRTO_IPTOS).
	// Default: -1 (use OS default). Range: 0-255.
	IPTOS int

	// InputBW is the estimated input bandwidth in bytes per second (SRTO_INPUTBW).
	// When MaxBW is 0 (auto), InputBW * (1 + OverheadBW/100) is used as the
	// effective sending rate. Default: 0 (not used).
	InputBW int64

	// MinInputBW is the minimum input bandwidth estimate in bytes per second
	// (SRTO_MININPUTBW). When auto-input-rate sampling is active (MaxBW=0 and
	// InputBW=0), the sampled rate will not drop below this floor. Default: 0.
	MinInputBW int64

	// MaxRexmitBW is the maximum retransmission bandwidth in bytes per second
	// (SRTO_MAXREXMITBW). When > 0, retransmissions are rate-limited using a
	// token bucket. 0 = unlimited (default).
	MaxRexmitBW int64

	// SndSyn when true (default), Write blocks until send buffer has space.
	// When false, Write returns ErrWouldBlock if the send buffer is full.
	// SRTO_SNDSYN (default: true).
	SndSyn *bool

	// RcvSyn when true (default), Read blocks until data is available.
	// When false, Read returns ErrWouldBlock if no data is ready.
	// SRTO_RCVSYN (default: true).
	RcvSyn *bool

	// PacketFilter is the FEC filter configuration string (SRTO_PACKETFILTER).
	// Format: "fec,cols:N,rows:M,layout:staircase,arq:onreq"
	// Empty string disables FEC. Default: "" (disabled).
	PacketFilter string

	// GroupConnect enables accepting grouped connections on a listener.
	// When true, the listener recognizes the group handshake extension
	// and allows multiple connections to join the same group.
	// Default: false (group connections rejected). Maps to SRTO_GROUPCONNECT.
	GroupConnect bool

	// GroupStabTimeout is the minimum stability timeout for backup mode.
	// A link with no response for longer than this is considered unstable.
	// Only used in GroupBackup mode. Default: 1s.
	// Maps to SRTO_GROUPMINSTABLETIMEO.
	GroupStabTimeout time.Duration

	// UDPSendBufSize sets the UDP socket send buffer size in bytes (SO_SNDBUF).
	// When 0 (default), the OS default is used. Must be >= MSS when set.
	// Maps to SRTO_UDP_SNDBUF (PREBIND option, set before I/O).
	UDPSendBufSize int

	// UDPRecvBufSize sets the UDP socket receive buffer size in bytes (SO_RCVBUF).
	// When 0 (default), the OS default is used. Must be >= MSS when set.
	// Maps to SRTO_UDP_RCVBUF (PREBIND option, set before I/O).
	UDPRecvBufSize int

	// IPv6Only controls whether an IPv6 socket accepts IPv4 connections
	// via IPv4-mapped IPv6 addresses (dual-stack). When nil, the OS default
	// is used. When true, only IPv6 is allowed. When false, dual-stack is
	// enabled. Only meaningful for IPv6 listeners. Maps to IPV6_V6ONLY.
	IPv6Only *bool

	// BindToDevice binds the socket to a specific network interface.
	// Only supported on Linux (SO_BINDTODEVICE). Empty string disables.
	BindToDevice string

	// Sender determines the data direction role for HSv4 connections.
	// When non-nil and true, this side sends HSREQ first (data sender role).
	// When nil or false, this side is the responder (data receiver role).
	// Only meaningful for HSv4 connections; HSv5 is always bidirectional.
	Sender *bool

	// Logger receives diagnostic log messages. When nil (the default),
	// no logging occurs and there is zero performance overhead.
	Logger Logger
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() Config {
	return Config{
		Latency:          DefaultLatency,
		MSS:              DefaultMSS,
		FC:               DefaultFC,
		MaxBW:            DefaultMaxBW,
		OverheadBW:       DefaultOverheadBW,
		SendBufSize:      DefaultSendBufSize,
		RecvBufSize:      DefaultRecvBufSize,
		ConnTimeout:      DefaultConnTimeout,
		IPTTL:            -1,
		IPTOS:            -1,
		GroupStabTimeout: time.Second,
	}
}

// validate applies defaults and checks constraints.
func (c *Config) validate() error {
	// TransType overrides Congestion
	if c.TransType == TransTypeFile {
		c.Congestion = CongestionFile
	}
	if c.Congestion == "" {
		c.Congestion = CongestionLive
	}
	if c.Congestion != CongestionLive && c.Congestion != CongestionFile {
		return errors.New("srt: Congestion must be \"live\" or \"file\"")
	}

	if c.MSS == 0 {
		c.MSS = DefaultMSS
	}
	if c.MSS < MinMSS || c.MSS > MaxMSS {
		return errors.New("srt: MSS must be between 76 and 1500")
	}

	if c.Latency == 0 {
		c.Latency = DefaultLatency
	}
	if c.Latency < MinLatency {
		return errors.New("srt: latency must be at least 20ms")
	}

	if c.RecvLatency == 0 {
		c.RecvLatency = c.Latency
	}
	if c.RecvLatency < MinLatency {
		return errors.New("srt: RecvLatency must be at least 20ms")
	}

	if c.PeerLatency == 0 {
		c.PeerLatency = c.Latency
	}
	if c.PeerLatency < MinLatency {
		return errors.New("srt: PeerLatency must be at least 20ms")
	}

	if c.FC == 0 {
		c.FC = DefaultFC
	}
	if c.FC < MinFC {
		return errors.New("srt: FC must be at least 32")
	}

	// MaxBW == 0 is valid: means "auto" (use InputBW+overhead, or DefaultMaxBW).
	// Resolved in newConn.

	if c.OverheadBW == 0 {
		c.OverheadBW = DefaultOverheadBW
	}
	if c.OverheadBW < 5 || c.OverheadBW > 100 {
		return errors.New("srt: overhead bandwidth must be between 5 and 100 percent")
	}

	if c.SendBufSize == 0 {
		c.SendBufSize = DefaultSendBufSize
	}
	if c.SendBufSize < MinBufSize {
		return errors.New("srt: SendBufSize must be at least 32")
	}
	if c.RecvBufSize == 0 {
		c.RecvBufSize = DefaultRecvBufSize
	}
	if c.RecvBufSize < MinBufSize {
		return errors.New("srt: RecvBufSize must be at least 32")
	}
	if c.RecvBufSize > c.FC {
		c.RecvBufSize = c.FC // clamp to FC (matches C++)
	}

	// PayloadSize: if set, must be <= MSS - 44 and >= MinPayload
	maxPayload := c.MSS - 44
	if c.PayloadSize > 0 {
		if c.PayloadSize < MinPayload {
			return errors.New("srt: PayloadSize must be at least 32")
		}
		if c.PayloadSize > maxPayload {
			return errors.New("srt: PayloadSize must be at most MSS - 44")
		}
	}

	if len(c.StreamID) > 512 {
		return errors.New("srt: stream ID must be at most 512 bytes")
	}

	if c.Passphrase != "" {
		if len(c.Passphrase) < 10 || len(c.Passphrase) > 80 {
			return errors.New("srt: passphrase must be 10-80 bytes")
		}
		if c.KeyLength == 0 {
			c.KeyLength = 16 // AES-128 default
		}
		switch c.KeyLength {
		case 16, 24, 32:
		default:
			return errors.New("srt: key length must be 16, 24, or 32")
		}
	}

	if c.ConnTimeout == 0 {
		c.ConnTimeout = DefaultConnTimeout
	}

	// File mode defaults Linger to 180s
	if c.Linger == 0 && c.Congestion == CongestionFile {
		c.Linger = 180 * time.Second
	}
	if c.Linger < 0 {
		c.Linger = 0
	}
	if c.Linger > MaxLinger {
		c.Linger = MaxLinger
	}

	if c.PeerIdleTimeout == 0 {
		c.PeerIdleTimeout = DefaultPeerIdleTimeout
	}
	if c.PeerIdleTimeout < 1*time.Second {
		return errors.New("srt: PeerIdleTimeout must be at least 1s")
	}

	// MessageAPI defaults to true for live mode, false for file mode
	if c.MessageAPI == nil {
		v := c.Congestion != CongestionFile
		c.MessageAPI = &v
	}

	// Key rotation defaults (only relevant when encryption is enabled)
	if c.KMRefreshRate == 0 && c.Passphrase != "" {
		c.KMRefreshRate = DefaultKMRefreshRate
	}
	if c.KMPreAnnounce == 0 && c.KMRefreshRate > 0 {
		c.KMPreAnnounce = DefaultKMPreAnnounce
	}
	if c.KMRefreshRate > 0 && c.KMPreAnnounce >= c.KMRefreshRate/2 {
		return errors.New("srt: KMPreAnnounce must be less than KMRefreshRate/2")
	}

	// MinVersion: default 0x010000 (1.0.0)
	if c.MinVersion == 0 {
		c.MinVersion = 0x010000
	}

	// LossMaxTTL: must be >= 0
	if c.LossMaxTTL < 0 {
		c.LossMaxTTL = 0
	}

	// SndDropDelay: -1 = disable, 0+ = extra delay in ms
	if c.SndDropDelay < -1 {
		c.SndDropDelay = -1
	}

	// EnforcedEncryption: default true
	if c.EnforcedEncryption == nil {
		v := true
		c.EnforcedEncryption = &v
	}

	// NAKReport: default true (live mode sends periodic NAK)
	if c.NAKReport == nil {
		v := true
		c.NAKReport = &v
	}

	// IPTTL: -1 = OS default, 1-255 valid range
	if c.IPTTL != -1 && (c.IPTTL < 1 || c.IPTTL > 255) {
		if c.IPTTL == 0 {
			c.IPTTL = -1 // treat 0 as unset
		} else {
			return errors.New("srt: IPTTL must be -1 (default) or 1-255")
		}
	}

	// IPTOS: -1 = OS default, 0-255 valid range
	if c.IPTOS < -1 || c.IPTOS > 255 {
		return errors.New("srt: IPTOS must be -1 (default) or 0-255")
	}

	// UDP buffer sizes: must be >= MSS when set
	if c.UDPSendBufSize < 0 {
		c.UDPSendBufSize = 0
	}
	if c.UDPSendBufSize > 0 && c.UDPSendBufSize < c.MSS {
		c.UDPSendBufSize = c.MSS
	}
	if c.UDPRecvBufSize < 0 {
		c.UDPRecvBufSize = 0
	}
	if c.UDPRecvBufSize > 0 && c.UDPRecvBufSize < c.MSS {
		c.UDPRecvBufSize = c.MSS
	}

	// InputBW: must be >= 0
	if c.InputBW < 0 {
		c.InputBW = 0
	}

	// PacketFilter: validate config string early
	if c.PacketFilter != "" {
		if _, err := filter.ParseConfig(c.PacketFilter); err != nil {
			return err
		}
	}

	return nil
}

// latencyMS returns the latency in milliseconds as uint16 for the handshake.
func (c *Config) latencyMS() uint16 {
	return uint16(c.Latency.Milliseconds())
}

// recvLatencyMS returns the receive latency in milliseconds for the handshake.
func (c *Config) recvLatencyMS() uint16 {
	return uint16(c.RecvLatency.Milliseconds())
}

// peerLatencyMS returns the peer latency in milliseconds for the handshake.
func (c *Config) peerLatencyMS() uint16 {
	return uint16(c.PeerLatency.Milliseconds())
}

// messageAPIEnabled returns whether message API is enabled.
func (c *Config) messageAPIEnabled() bool {
	return c.MessageAPI == nil || *c.MessageAPI
}

// srtFlags returns the SRT feature flags for the handshake.
// File mode omits TSBPD and TLPKTDROP flags.
// When MessageAPI is false, the FlagStream bit is set.
// NAKReport=false clears the FlagPeriodicNAK bit (tells peer we won't send periodic NAKs).
func (c *Config) srtFlags() uint32 {
	var flags uint32
	if c.Congestion == CongestionFile {
		// File mode: no TSBPD, no TLPKTDROP
		flags = uint32(packet.FlagCrypt | packet.FlagPeriodicNAK | packet.FlagRexmit)
	} else {
		flags = uint32(packet.FlagTSBPDSend | packet.FlagTSBPDRecv |
			packet.FlagCrypt | packet.FlagTLPktDrop |
			packet.FlagPeriodicNAK | packet.FlagRexmit)
	}
	// If NAKReport is explicitly false, clear the FlagPeriodicNAK bit.
	// This tells the peer that we will NOT send periodic NAK reports,
	// which activates FASTREXMIT on their side.
	if c.NAKReport != nil && !*c.NAKReport {
		flags &^= packet.FlagPeriodicNAK
	}
	if !c.messageAPIEnabled() {
		flags |= packet.FlagStream
	}
	// SRT_OPT_FILTERCAP is always set
	// to advertise filter capability, regardless of whether a filter is configured.
	flags |= packet.FlagPacketFilter
	return flags
}

// congestionString returns the congestion type string for the handshake.
func (c *Config) congestionString() string {
	if c.Congestion == CongestionFile {
		return "file"
	}
	return "live"
}

// tsbpdEnabled returns whether TSBPD is enabled for this config.
func (c *Config) tsbpdEnabled() bool {
	return c.Congestion != CongestionFile
}

// tlpktdropEnabled returns whether too-late packet drop is enabled.
func (c *Config) tlpktdropEnabled() bool {
	return c.Congestion != CongestionFile
}

// retransmitAlgo returns the retransmission algorithm setting.
// Default: 1 for live mode, 0 for file mode.
func (c *Config) retransmitAlgo() int {
	if c.RetransmitAlgo != nil {
		return *c.RetransmitAlgo
	}
	if c.Congestion == CongestionFile {
		return 0
	}
	return 1
}

// driftTracerEnabled returns whether drift correction is enabled.
func (c *Config) driftTracerEnabled() bool {
	return c.DriftTracer == nil || *c.DriftTracer
}

// sndSynEnabled returns whether blocking Write mode is enabled (default true).
func (c *Config) sndSynEnabled() bool {
	return c.SndSyn == nil || *c.SndSyn
}

// rcvSynEnabled returns whether blocking Read mode is enabled (default true).
func (c *Config) rcvSynEnabled() bool {
	return c.RcvSyn == nil || *c.RcvSyn
}
