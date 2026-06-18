// Package srt implements the SRT (Secure Reliable Transport) protocol in pure Go.
//
// SRT is a UDP-based protocol for low-latency, reliable transport of live media
// streams. This implementation supports live streaming and file transfer modes
// with caller-listener and rendezvous (P2P) connection models.
//
// # Architecture
//
// Each SRT connection uses exactly 3 goroutines:
//   - recvLoop: reads packets from the mux, processes control packets, inserts
//     data packets into the receive buffer
//   - timerLoop: 10ms ticker drives periodic events (ACK, NAK, keepalive, TSBPD)
//   - application goroutine: calls Read/Write on the connection
//
// All connections sharing a listener multiplex over a single UDP socket. Packets
// are dispatched by DestinationSocketID in a single read goroutine.
//
// # Usage
//
// Listener (server):
//
//	l, err := srt.Listen("0.0.0.0:6000", srt.DefaultConfig())
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer l.Close()
//
//	l.SetAcceptFunc(func(req srt.ConnRequest) bool {
//	    return req.StreamID == "live/stream"
//	})
//
//	conn, err := l.Accept()
//	// conn implements net.Conn
//
// Dialer (client):
//
//	cfg := srt.DefaultConfig()
//	cfg.StreamID = "live/stream"
//	cfg.Latency = 120 * time.Millisecond
//
//	conn, err := srt.Dial("server:6000", cfg)
//	// conn implements net.Conn
//
// Rendezvous (P2P):
//
//	cfg := srt.DefaultConfig()
//	conn, err := srt.DialRendezvous(":6000", "peer:6000", cfg)
//	// conn implements net.Conn
package legacy
