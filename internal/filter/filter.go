// Package filter implements the SRT packet filter framework for Forward Error
// Correction (FEC). It provides XOR-based proactive loss recovery using row
// and column FEC groups per SMPTE 2022-1-2007.
package filter

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ARQLevel controls cooperation between FEC and ARQ (retransmission).
type ARQLevel int

const (
	// ARQAlways sends NAK immediately on gap detection. FEC recoveries are
	// a bonus that may arrive before the retransmit. Default for live mode.
	ARQAlways ARQLevel = iota

	// ARQOnReq defers NAK until the FEC group completes. Only packets that
	// FEC cannot recover are reported via NAK. Default for FEC config.
	ARQOnReq

	// ARQNever suppresses all NAK. Relies entirely on FEC for loss recovery.
	ARQNever
)

// Layout determines how column groups are arranged in the packet stream.
type Layout int

const (
	// LayoutStaircase staggers column starting points by (1 + rows) per column.
	// Spreads FEC packet transmission more evenly. Default.
	LayoutStaircase Layout = iota

	// LayoutEven places all column bases at the same matrix origin.
	LayoutEven
)

// Config holds parsed FEC filter parameters.
type Config struct {
	Cols     int      // number of columns (mandatory, >= 2)
	Rows     int      // number of rows (1 = column-only, default 1)
	Layout   Layout   // LayoutStaircase or LayoutEven
	ARQ      ARQLevel // default: ARQOnReq
	ColsOnly bool     // true = suppress row FEC, only column FEC
}

// ParseConfig parses an FEC config string like "fec,cols:10,rows:5,layout:staircase,arq:onreq".
// The first token must be "fec". cols is mandatory and must be >= 2.
func ParseConfig(s string) (Config, error) {
	if s == "" {
		return Config{}, errors.New("filter: empty config string")
	}

	parts := strings.Split(s, ",")
	if len(parts) == 0 {
		return Config{}, errors.New("filter: empty config parts")
	}
	filterName := parts[0]
	// Accept any registered filter name, or "fec" (built-in)
	if filterName != "fec" && Lookup(filterName) == nil {
		return Config{}, fmt.Errorf("filter: unknown filter type %q (registered: fec)", filterName)
	}

	cfg := Config{
		Rows:   1,
		Layout: LayoutStaircase,
		ARQ:    ARQOnReq,
	}

	hasCols := false
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			return Config{}, fmt.Errorf("filter: invalid parameter %q (expected key:value)", part)
		}
		key, val := kv[0], kv[1]

		switch key {
		case "cols":
			v, err := strconv.Atoi(val)
			if err != nil {
				return Config{}, fmt.Errorf("filter: invalid cols value %q: %w", val, err)
			}
			if v < 2 {
				return Config{}, fmt.Errorf("filter: cols must be >= 2, got %d", v)
			}
			cfg.Cols = v
			hasCols = true

		case "rows":
			v, err := strconv.Atoi(val)
			if err != nil {
				return Config{}, fmt.Errorf("filter: invalid rows value %q: %w", val, err)
			}
			if v <= 0 {
				return Config{}, fmt.Errorf("filter: rows must be positive, got %d", v)
			}
			cfg.Rows = v

		case "layout":
			switch val {
			case "staircase":
				cfg.Layout = LayoutStaircase
			case "even":
				cfg.Layout = LayoutEven
			default:
				return Config{}, fmt.Errorf("filter: invalid layout %q (must be \"even\" or \"staircase\")", val)
			}

		case "arq":
			switch val {
			case "always":
				cfg.ARQ = ARQAlways
			case "onreq":
				cfg.ARQ = ARQOnReq
			case "never":
				cfg.ARQ = ARQNever
			default:
				return Config{}, fmt.Errorf("filter: invalid arq %q (must be \"always\", \"onreq\", or \"never\")", val)
			}

		default:
			return Config{}, fmt.Errorf("filter: unknown parameter %q", key)
		}
	}

	if !hasCols {
		return Config{}, errors.New("filter: cols parameter is mandatory")
	}

	return cfg, nil
}

// FormatConfig serializes a Config back to the wire string format.
func FormatConfig(c Config) string {
	var b strings.Builder
	b.WriteString("fec")
	fmt.Fprintf(&b, ",cols:%d", c.Cols)
	if c.Rows > 1 {
		fmt.Fprintf(&b, ",rows:%d", c.Rows)
	}
	switch c.Layout {
	case LayoutEven:
		b.WriteString(",layout:even")
	default:
		b.WriteString(",layout:staircase")
	}
	switch c.ARQ {
	case ARQAlways:
		b.WriteString(",arq:always")
	case ARQNever:
		b.WriteString(",arq:never")
	default:
		b.WriteString(",arq:onreq")
	}
	return b.String()
}

// NegotiateConfig checks that local and peer FEC configs are compatible.
// Per packetfilter.cpp:CheckFilterCompat, all parameters must match.
// Returns the agreed config or an error if incompatible.
func NegotiateConfig(local, peer Config) (Config, error) {
	if local.Cols != peer.Cols {
		return Config{}, fmt.Errorf("filter: cols mismatch (local=%d, peer=%d)", local.Cols, peer.Cols)
	}
	if local.Rows != peer.Rows {
		return Config{}, fmt.Errorf("filter: rows mismatch (local=%d, peer=%d)", local.Rows, peer.Rows)
	}
	if local.Layout != peer.Layout {
		return Config{}, fmt.Errorf("filter: layout mismatch")
	}
	if local.ARQ != peer.ARQ {
		return Config{}, fmt.Errorf("filter: arq mismatch")
	}
	return local, nil
}

// ExtraHeaderSize is the size of the FEC control packet header (4 bytes):
// [0] int8 group index (-1=row, 0..N=column)
// [1] uint8 flag clip
// [2:4] uint16 length clip (network byte order)
const ExtraHeaderSize = 4

// FilterFactory creates a packet filter from a parsed config.
// payloadSize is the maximum payload per packet; isn is the initial sequence number.
type FilterFactory func(cfg Config, payloadSize int, isn uint32) (sender *FECSender, receiver *FECReceiver, err error)

// registry holds registered filter factories, keyed by name.
var registry = map[string]FilterFactory{}

func init() {
	Register("fec", func(cfg Config, payloadSize int, isn uint32) (*FECSender, *FECReceiver, error) {
		sender := NewFECSender(cfg, payloadSize, isn)
		receiver := NewFECReceiver(cfg, payloadSize, isn)
		return sender, receiver, nil
	})
}

// Register registers a filter factory under the given name.
// The name must match the first token of the config string (e.g., "fec").
func Register(name string, factory FilterFactory) {
	registry[name] = factory
}

// Lookup returns the factory registered for the given filter name, or nil.
func Lookup(name string) FilterFactory {
	return registry[name]
}

// FilterName extracts the filter name (first token) from a config string.
func FilterName(config string) string {
	parts := strings.SplitN(config, ",", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
