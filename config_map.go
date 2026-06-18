package srt

import (
	"github.com/zsiec/srtgo/internal/clock"
	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/session"
)

// This file maps the public Config onto the internal/core + internal/session
// configuration the façade delegates to. The derivation helpers it relies on
// (congestionString, tsbpdEnabled, messageAPIEnabled, …) live in config.go.

// bufferCapacity is the shared default ring capacity (the larger of the two);
// the core also takes independent SendBufCapacity/RecvBufCapacity below.
func (cfg *Config) bufferCapacity() int {
	n := cfg.SendBufSize
	if cfg.RecvBufSize > n {
		n = cfg.RecvBufSize
	}
	return n
}

func (cfg *Config) enforcedEncryptionOff() bool {
	return cfg.EnforcedEncryption != nil && !*cfg.EnforcedEncryption
}

func (cfg *Config) nakReportOff() bool {
	return cfg.NAKReport != nil && !*cfg.NAKReport
}

func (cfg *Config) peerIdleMicros() clock.Microseconds {
	return clock.Microseconds(cfg.PeerIdleTimeout.Microseconds())
}

// dialConfig builds the caller-side core.DialConfig. The host (session.Dial)
// generates the random socket ID / ISN and builds the crypto context from
// Passphrase, so neither is set here.
func (cfg *Config) dialConfig() core.DialConfig {
	return core.DialConfig{
		MSS:                      uint32(cfg.MSS),
		FC:                       uint32(cfg.FC),
		RecvLatencyMS:            cfg.recvLatencyMS(),
		SendLatencyMS:            cfg.peerLatencyMS(),
		Congestion:               cfg.congestionString(),
		StreamID:                 cfg.StreamID,
		FilterConfig:             cfg.PacketFilter,
		Passphrase:               cfg.Passphrase,
		KeyLength:                cfg.KeyLength,
		CryptoMode:               cfg.CryptoMode,
		KMRefreshRate:            cfg.KMRefreshRate,
		KMPreAnnounce:            cfg.KMPreAnnounce,
		AllowUnencryptedFallback: cfg.enforcedEncryptionOff(),
		PayloadSize:              cfg.PayloadSize,
		BufferCapacity:           cfg.bufferCapacity(),
		SendBufCapacity:          cfg.SendBufSize,
		RecvBufCapacity:          cfg.RecvBufSize,
		MaxBW:                    cfg.MaxBW,
		Live:                     cfg.tsbpdEnabled(),
		Message:                  cfg.messageAPIEnabled(),
		TLPktDrop:                cfg.tlpktdropEnabled(),
		SndDropDelay:             cfg.SndDropDelay,
		LossMaxTTL:               cfg.LossMaxTTL,
		DisableNAKReport:         cfg.nakReportOff(),
		PeerIdleTimeout:          cfg.peerIdleMicros(),
	}
}

// listenerConfig builds the core.ListenerConfig applied to accepted connections.
func (cfg *Config) listenerConfig() core.ListenerConfig {
	return core.ListenerConfig{
		RecvLatencyMS:            cfg.recvLatencyMS(),
		SendLatencyMS:            cfg.peerLatencyMS(),
		Congestion:               cfg.congestionString(),
		Live:                     cfg.tsbpdEnabled(),
		Message:                  cfg.messageAPIEnabled(),
		TLPktDrop:                cfg.tlpktdropEnabled(),
		SndDropDelay:             cfg.SndDropDelay,
		LossMaxTTL:               cfg.LossMaxTTL,
		DisableNAKReport:         cfg.nakReportOff(),
		PeerIdleTimeout:          cfg.peerIdleMicros(),
		MaxBW:                    cfg.MaxBW,
		PayloadSize:              cfg.PayloadSize,
		BufferCapacity:           cfg.bufferCapacity(),
		SendBufCapacity:          cfg.SendBufSize,
		RecvBufCapacity:          cfg.RecvBufSize,
		Passphrase:               cfg.Passphrase,
		KeyLength:                cfg.KeyLength,
		CryptoMode:               cfg.CryptoMode,
		AllowUnencryptedFallback: cfg.enforcedEncryptionOff(),
		KMRefreshRate:            cfg.KMRefreshRate,
		KMPreAnnounce:            cfg.KMPreAnnounce,
		FilterConfig:             cfg.PacketFilter,
	}
}

// rendezvousConfig builds the core.RendezvousConfig for a simultaneous-open
// connection. The host (session.DialRendezvous) generates the socket ID / ISN /
// cookie when left zero and builds the crypto context from Passphrase.
func (cfg *Config) rendezvousConfig() core.RendezvousConfig {
	return core.RendezvousConfig{
		MSS:             uint32(cfg.MSS),
		FC:              uint32(cfg.FC),
		RecvLatencyMS:   cfg.recvLatencyMS(),
		SendLatencyMS:   cfg.peerLatencyMS(),
		Congestion:      cfg.congestionString(),
		StreamID:        cfg.StreamID,
		FilterConfig:    cfg.PacketFilter,
		PayloadSize:     cfg.PayloadSize,
		BufferCapacity:  cfg.bufferCapacity(),
		MaxBW:           cfg.MaxBW,
		Live:            cfg.tsbpdEnabled(),
		Message:         cfg.messageAPIEnabled(),
		PeerIdleTimeout: cfg.peerIdleMicros(),
		Passphrase:      cfg.Passphrase,
		KeyLength:       cfg.KeyLength,
		CryptoMode:      cfg.CryptoMode,
	}
}

// udpSocketOptions maps the OS-level socket knobs onto the host helper.
func (cfg *Config) udpSocketOptions() session.UDPSocketOptions {
	return session.UDPSocketOptions{
		IPTTL:          cfg.IPTTL,
		IPTOS:          cfg.IPTOS,
		IPv6Only:       cfg.IPv6Only,
		BindToDevice:   cfg.BindToDevice,
		UDPSendBufSize: cfg.UDPSendBufSize,
		UDPRecvBufSize: cfg.UDPRecvBufSize,
	}
}
