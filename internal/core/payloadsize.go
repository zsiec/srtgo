package core

import "github.com/zsiec/srtgo/internal/packet"

// negotiatedPayloadSize applies the mode default after MSS negotiation. The
// handshake validates MSS before calling this; an explicit payload cap can only
// reduce the negotiated packet size, never enlarge it.
func negotiatedPayloadSize(requested int, mss uint32, congestion string) int {
	limit := int(mss) - packet.WireHeaderSize
	if requested <= 0 {
		requested = liveDefaultPayloadSize
		if congestion == "file" {
			requested = limit
		}
	}
	return min(requested, limit)
}
