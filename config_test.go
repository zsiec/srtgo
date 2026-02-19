package srt

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Latency != DefaultLatency {
		t.Errorf("Latency: got %v, want %v", cfg.Latency, DefaultLatency)
	}
	if cfg.MSS != DefaultMSS {
		t.Errorf("MSS: got %d, want %d", cfg.MSS, DefaultMSS)
	}
	if cfg.FC != DefaultFC {
		t.Errorf("FC: got %d, want %d", cfg.FC, DefaultFC)
	}
	if cfg.MaxBW != DefaultMaxBW {
		t.Errorf("MaxBW: got %d, want %d", cfg.MaxBW, DefaultMaxBW)
	}
	if cfg.OverheadBW != DefaultOverheadBW {
		t.Errorf("OverheadBW: got %d, want %d", cfg.OverheadBW, DefaultOverheadBW)
	}
	if cfg.ConnTimeout != DefaultConnTimeout {
		t.Errorf("ConnTimeout: got %v, want %v", cfg.ConnTimeout, DefaultConnTimeout)
	}
}

func TestConfigValidateDefaults(t *testing.T) {
	// Zero config should fill in defaults
	cfg := Config{}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate zero config: %v", err)
	}

	if cfg.MSS != DefaultMSS {
		t.Errorf("MSS: got %d, want %d", cfg.MSS, DefaultMSS)
	}
	if cfg.Latency != DefaultLatency {
		t.Errorf("Latency: got %v, want %v", cfg.Latency, DefaultLatency)
	}
	if cfg.FC != DefaultFC {
		t.Errorf("FC: got %d, want %d", cfg.FC, DefaultFC)
	}
}

func TestConfigValidateMSS(t *testing.T) {
	tests := []struct {
		name    string
		mss     int
		wantErr bool
	}{
		{"valid 1500", 1500, false},
		{"valid 76", 76, false},
		{"valid 1000", 1000, false},
		{"too small", 50, true},
		{"too large", 9000, true},
		{"zero (default)", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{MSS: tt.mss}
			err := cfg.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("validate(MSS=%d): err=%v, wantErr=%v", tt.mss, err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidateLatency(t *testing.T) {
	tests := []struct {
		name    string
		latency time.Duration
		wantErr bool
	}{
		{"valid 120ms", 120 * time.Millisecond, false},
		{"valid 20ms (minimum)", 20 * time.Millisecond, false},
		{"valid 1s", 1 * time.Second, false},
		{"too small 10ms", 10 * time.Millisecond, true},
		{"too small 1ms", 1 * time.Millisecond, true},
		{"zero (default)", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Latency: tt.latency}
			err := cfg.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("validate(Latency=%v): err=%v, wantErr=%v", tt.latency, err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidateOverhead(t *testing.T) {
	tests := []struct {
		name    string
		pct     int
		wantErr bool
	}{
		{"valid 25%", 25, false},
		{"valid 5%", 5, false},
		{"valid 100%", 100, false},
		{"too small 3%", 3, true},
		{"too large 150%", 150, true},
		{"zero (default)", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{OverheadBW: tt.pct}
			err := cfg.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("validate(Overhead=%d): err=%v, wantErr=%v", tt.pct, err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidateStreamID(t *testing.T) {
	// Valid stream ID
	cfg := Config{StreamID: "live/test"}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate valid streamID: %v", err)
	}

	// Too long
	longID := make([]byte, 513)
	for i := range longID {
		longID[i] = 'a'
	}
	cfg = Config{StreamID: string(longID)}
	if err := cfg.validate(); err == nil {
		t.Error("validate should fail for stream ID > 512 bytes")
	}
}

func TestConfigValidatePassphrase(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		wantErr    bool
	}{
		{"empty (no encryption)", "", false},
		{"valid 10 bytes", "1234567890", false},
		{"valid 80 bytes", string(make([]byte, 80)), false},
		{"too short", "short", true},
		{"too long", string(make([]byte, 81)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Passphrase: tt.passphrase}
			err := cfg.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("validate(Passphrase len=%d): err=%v, wantErr=%v",
					len(tt.passphrase), err, tt.wantErr)
			}
		})
	}
}

func TestConfigLatencyMS(t *testing.T) {
	cfg := Config{Latency: 120 * time.Millisecond}
	if cfg.latencyMS() != 120 {
		t.Errorf("latencyMS: got %d, want 120", cfg.latencyMS())
	}

	cfg = Config{Latency: 500 * time.Millisecond}
	if cfg.latencyMS() != 500 {
		t.Errorf("latencyMS: got %d, want 500", cfg.latencyMS())
	}
}

func TestConfigValidateLinger(t *testing.T) {
	// Negative linger is clamped to 0
	cfg := Config{Linger: -1 * time.Second}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.Linger != 0 {
		t.Errorf("Linger: got %v, want 0 (clamped)", cfg.Linger)
	}

	// Linger above max is clamped to MaxLinger (180s)
	cfg = Config{Linger: 200 * time.Second}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.Linger != MaxLinger {
		t.Errorf("Linger: got %v, want %v (clamped)", cfg.Linger, MaxLinger)
	}

	// Valid linger
	cfg = Config{Linger: 1 * time.Second}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.Linger != 1*time.Second {
		t.Errorf("Linger: got %v, want 1s", cfg.Linger)
	}
}

func TestConfigValidatePeerIdleTimeout(t *testing.T) {
	// Default: 5s
	cfg := Config{}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.PeerIdleTimeout != DefaultPeerIdleTimeout {
		t.Errorf("PeerIdleTimeout: got %v, want %v", cfg.PeerIdleTimeout, DefaultPeerIdleTimeout)
	}

	// Custom valid value
	cfg = Config{PeerIdleTimeout: 10 * time.Second}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.PeerIdleTimeout != 10*time.Second {
		t.Errorf("PeerIdleTimeout: got %v, want 10s", cfg.PeerIdleTimeout)
	}

	// Too small
	cfg = Config{PeerIdleTimeout: 500 * time.Millisecond}
	if err := cfg.validate(); err == nil {
		t.Error("validate should fail for PeerIdleTimeout < 1s")
	}
}

func TestConfigValidateKMRefresh(t *testing.T) {
	// Defaults when passphrase is set
	cfg := Config{Passphrase: "1234567890"}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.KMRefreshRate != DefaultKMRefreshRate {
		t.Errorf("KMRefreshRate: got %d, want %d", cfg.KMRefreshRate, DefaultKMRefreshRate)
	}
	if cfg.KMPreAnnounce != DefaultKMPreAnnounce {
		t.Errorf("KMPreAnnounce: got %d, want %d", cfg.KMPreAnnounce, DefaultKMPreAnnounce)
	}

	// No defaults when no passphrase
	cfg = Config{}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.KMRefreshRate != 0 {
		t.Errorf("KMRefreshRate without passphrase: got %d, want 0", cfg.KMRefreshRate)
	}

	// Invalid: KMPreAnnounce >= KMRefreshRate/2
	cfg = Config{
		Passphrase:    "1234567890",
		KMRefreshRate: 100,
		KMPreAnnounce: 60,
	}
	if err := cfg.validate(); err == nil {
		t.Error("validate should fail when KMPreAnnounce >= KMRefreshRate/2")
	}

	// Valid custom values
	cfg = Config{
		Passphrase:    "1234567890",
		KMRefreshRate: 100,
		KMPreAnnounce: 10,
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestConfigValidateBufferSizing(t *testing.T) {
	// FC < MinFC rejected
	cfg := Config{FC: 16}
	if err := cfg.validate(); err == nil {
		t.Error("validate should fail for FC < 32")
	}

	// FC == MinFC accepted
	cfg = Config{FC: MinFC}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate FC=32: %v", err)
	}

	// SendBufSize < MinBufSize rejected
	cfg = Config{SendBufSize: 16}
	if err := cfg.validate(); err == nil {
		t.Error("validate should fail for SendBufSize < 32")
	}

	// SendBufSize == MinBufSize accepted
	cfg = Config{SendBufSize: MinBufSize}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate SendBufSize=32: %v", err)
	}

	// RecvBufSize < MinBufSize rejected
	cfg = Config{RecvBufSize: 16}
	if err := cfg.validate(); err == nil {
		t.Error("validate should fail for RecvBufSize < 32")
	}

	// RecvBufSize == MinBufSize accepted
	cfg = Config{RecvBufSize: MinBufSize}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate RecvBufSize=32: %v", err)
	}

	// RecvBufSize > FC silently clamped to FC
	cfg = Config{FC: 64, RecvBufSize: 128}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate RecvBufSize>FC: %v", err)
	}
	if cfg.RecvBufSize != 64 {
		t.Errorf("RecvBufSize: got %d, want 64 (clamped to FC)", cfg.RecvBufSize)
	}

	// Defaults still pass
	cfg = Config{}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate defaults: %v", err)
	}
	if cfg.FC != DefaultFC {
		t.Errorf("FC: got %d, want %d", cfg.FC, DefaultFC)
	}
	if cfg.SendBufSize != DefaultSendBufSize {
		t.Errorf("SendBufSize: got %d, want %d", cfg.SendBufSize, DefaultSendBufSize)
	}
	if cfg.RecvBufSize != DefaultRecvBufSize {
		t.Errorf("RecvBufSize: got %d, want %d", cfg.RecvBufSize, DefaultRecvBufSize)
	}
}

func TestConfigLatencySplit(t *testing.T) {
	// Default: RecvLatency and PeerLatency default to Latency
	cfg := Config{Latency: 200 * time.Millisecond}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.RecvLatency != 200*time.Millisecond {
		t.Errorf("RecvLatency: got %v, want 200ms", cfg.RecvLatency)
	}
	if cfg.PeerLatency != 200*time.Millisecond {
		t.Errorf("PeerLatency: got %v, want 200ms", cfg.PeerLatency)
	}
	if cfg.recvLatencyMS() != 200 {
		t.Errorf("recvLatencyMS: got %d, want 200", cfg.recvLatencyMS())
	}
	if cfg.peerLatencyMS() != 200 {
		t.Errorf("peerLatencyMS: got %d, want 200", cfg.peerLatencyMS())
	}

	// Override: explicit RecvLatency/PeerLatency override Latency
	cfg = Config{
		Latency:     120 * time.Millisecond,
		RecvLatency: 300 * time.Millisecond,
		PeerLatency: 50 * time.Millisecond,
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.recvLatencyMS() != 300 {
		t.Errorf("recvLatencyMS: got %d, want 300", cfg.recvLatencyMS())
	}
	if cfg.peerLatencyMS() != 50 {
		t.Errorf("peerLatencyMS: got %d, want 50", cfg.peerLatencyMS())
	}

	// Validation: RecvLatency below minimum
	cfg = Config{RecvLatency: 5 * time.Millisecond}
	if err := cfg.validate(); err == nil {
		t.Error("validate should fail for RecvLatency < 20ms")
	}

	// Validation: PeerLatency below minimum
	cfg = Config{PeerLatency: 5 * time.Millisecond}
	if err := cfg.validate(); err == nil {
		t.Error("validate should fail for PeerLatency < 20ms")
	}
}
