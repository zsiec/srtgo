package legacy

import (
	"bytes"
	"strings"
	"testing"
)

func TestLogLevelString(t *testing.T) {
	tests := []struct {
		level LogLevel
		want  string
	}{
		{LogDebug, "DEBUG"},
		{LogNote, "NOTE"},
		{LogWarning, "WARN"},
		{LogError, "ERROR"},
		{LogLevel(99), "LogLevel(99)"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("LogLevel(%d).String() = %q, want %q", int(tt.level), got, tt.want)
		}
	}
}

func TestLogfNilLogger(t *testing.T) {
	// Must not panic or allocate when logger is nil
	logf(nil, LogDebug, LogGeneral, 0, "test %d %s", 42, "hello")
}

func TestLogfWithLogger(t *testing.T) {
	var calls []string
	logger := &testLogger{fn: func(level LogLevel, cat LogCategory, socketID uint32, msg string) {
		calls = append(calls, msg)
	}}

	logf(logger, LogNote, LogConn, 123, "connected to %s", "peer")

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0] != "connected to peer" {
		t.Errorf("got msg %q, want %q", calls[0], "connected to peer")
	}
}

func TestStdLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := StdLogger(&buf)

	logger.Log(LogWarning, LogCrypto, 42, "key rotation started")

	output := buf.String()
	if !strings.Contains(output, "[WARN]") {
		t.Errorf("output missing level: %q", output)
	}
	if !strings.Contains(output, "crypto") {
		t.Errorf("output missing category: %q", output)
	}
	if !strings.Contains(output, "[42]") {
		t.Errorf("output missing socket ID: %q", output)
	}
	if !strings.Contains(output, "key rotation started") {
		t.Errorf("output missing message: %q", output)
	}
	if !strings.HasSuffix(output, "\n") {
		t.Errorf("output missing trailing newline: %q", output)
	}
}

func BenchmarkLogfNilLogger(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		logf(nil, LogDebug, LogGeneral, 0, "msg %d %s %v", 42, "hello", true)
	}
}

func BenchmarkLogfWithLogger(b *testing.B) {
	logger := &testLogger{fn: func(LogLevel, LogCategory, uint32, string) {}}
	b.ReportAllocs()
	for b.Loop() {
		logf(logger, LogDebug, LogGeneral, 0, "msg %d %s %v", 42, "hello", true)
	}
}

// testLogger is a Logger that delegates to a function.
type testLogger struct {
	fn func(level LogLevel, cat LogCategory, socketID uint32, msg string)
}

func (l *testLogger) Log(level LogLevel, cat LogCategory, socketID uint32, msg string) {
	l.fn(level, cat, socketID, msg)
}
