package session_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/zsiec/srtgo/internal/core"
	"github.com/zsiec/srtgo/internal/session"
)

// dialExpectReject dials the new listener with the given caller config and
// asserts the dial fails with a RejectError carrying wantCode.
func dialExpectReject(t *testing.T, ln *session.Listener, dc core.DialConfig, wantCode uint32) {
	t.Helper()
	cuconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = session.Dial(cuconn, ln.Addr(), dc, nil, 3*time.Second)
	if err == nil {
		t.Fatal("expected the dial to be rejected, but it succeeded")
	}
	var re core.RejectError
	if !errors.As(err, &re) {
		t.Fatalf("expected a RejectError, got %T: %v", err, err)
	}
	if re.Code != wantCode {
		t.Errorf("rejection code = %d, want %d", re.Code, wantCode)
	}
}

func newRejectListener(t *testing.T, passphrase string) *session.Listener {
	t.Helper()
	uconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := session.Listen(uconn, core.ListenerConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
		Passphrase: passphrase,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Drain accepts so a (hypothetical) accepted connection doesn't block the test.
	go func() {
		for {
			s, err := ln.Accept()
			if err != nil {
				return
			}
			s.Close()
		}
	}()
	return ln
}

const (
	rejBadSecret = 1010
	rejUnsecure  = 1011
)

func TestRejectWrongPassphrase(t *testing.T) {
	ln := newRejectListener(t, "correct horse battery")
	defer ln.Close()
	dialExpectReject(t, ln, core.DialConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
		Passphrase: "wrong passphrase!!", KeyLength: 16,
	}, rejBadSecret)
}

func TestRejectEncryptionRequired(t *testing.T) {
	ln := newRejectListener(t, "correct horse battery")
	defer ln.Close()
	// Caller offers no passphrase but the listener requires one.
	dialExpectReject(t, ln, core.DialConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
	}, rejUnsecure)
}

func TestRejectUnexpectedEncryption(t *testing.T) {
	ln := newRejectListener(t, "") // listener has no passphrase
	defer ln.Close()
	// Caller insists on encryption the listener cannot do.
	dialExpectReject(t, ln, core.DialConfig{
		Live: true, MaxBW: 125_000_000, RecvLatencyMS: 120, SendLatencyMS: 120,
		Passphrase: "some passphrase", KeyLength: 16,
	}, rejUnsecure)
}
