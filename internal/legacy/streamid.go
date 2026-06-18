package legacy

import "strings"

// StreamType identifies the type of SRT stream session.
type StreamType string

const (
	StreamTypeStream StreamType = "stream" // live media streaming
	StreamTypeFile   StreamType = "file"   // file transfer
	StreamTypeAuth   StreamType = "auth"   // authentication only
)

// StreamMode identifies the data direction for an SRT stream.
type StreamMode string

const (
	StreamModeRequest       StreamMode = "request"       // pull data from server
	StreamModePublish       StreamMode = "publish"       // push data to server
	StreamModeBidirectional StreamMode = "bidirectional" // both directions
)

// streamIDPrefix is the magic prefix for structured stream IDs (C++ access_control.h).
const streamIDPrefix = "#!::"

// StreamIDInfo holds the parsed fields of a structured SRT stream ID.
// See C++ SRT access control guidelines for the field definitions.
type StreamIDInfo struct {
	UserName     string            // "u" — user/application name
	ResourceName string            // "r" — resource path (e.g. "live/stream")
	HostName     string            // "h" — host name
	SessionID    string            // "s" — session identifier
	Type         StreamType        // "t" — session type
	Mode         StreamMode        // "m" — data direction
	Extra        map[string]string // any non-standard keys
}

// ParseStreamID parses a raw SRT stream ID string into structured fields.
//
// Two formats are supported:
//   - Bare path: the entire string becomes ResourceName (e.g. "live/stream").
//   - Structured: starts with "#!::" followed by comma-separated key=value pairs
//     (e.g. "#!::u=admin,r=live/stream,m=publish").
//
// Returns the parsed info and true on success.
// Returns false only if the "#!::" prefix is present but zero valid pairs are found.
func ParseStreamID(raw string) (StreamIDInfo, bool) {
	var info StreamIDInfo

	// Bare path — no prefix
	if !strings.HasPrefix(raw, streamIDPrefix) {
		info.ResourceName = raw
		return info, true
	}

	// Strip prefix
	body := raw[len(streamIDPrefix):]
	if body == "" {
		return info, false
	}

	parsed := 0
	for _, field := range strings.Split(body, ",") {
		k, v, ok := strings.Cut(field, "=")
		if !ok || k == "" {
			continue // skip malformed pairs
		}
		parsed++
		switch k {
		case "u":
			info.UserName = v
		case "r":
			info.ResourceName = v
		case "h":
			info.HostName = v
		case "s":
			info.SessionID = v
		case "t":
			info.Type = StreamType(v)
		case "m":
			info.Mode = StreamMode(v)
		default:
			if info.Extra == nil {
				info.Extra = make(map[string]string)
			}
			info.Extra[k] = v
		}
	}

	if parsed == 0 {
		return info, false
	}
	return info, true
}
