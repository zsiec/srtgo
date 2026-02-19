package srt

import (
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// LogLevel represents the severity of a log message.
type LogLevel int

const (
	// LogDebug is for detailed diagnostic information.
	LogDebug LogLevel = iota
	// LogNote is for notable but normal events.
	LogNote
	// LogWarning is for unexpected but recoverable conditions.
	LogWarning
	// LogError is for error conditions that affect operation.
	LogError
)

// String returns a human-readable name for the log level.
func (l LogLevel) String() string {
	switch l {
	case LogDebug:
		return "DEBUG"
	case LogNote:
		return "NOTE"
	case LogWarning:
		return "WARN"
	case LogError:
		return "ERROR"
	default:
		return fmt.Sprintf("LogLevel(%d)", int(l))
	}
}

// LogCategory identifies the subsystem that generated a log message.
// Categories match SRT_LOGFA_* facility areas.
type LogCategory string

const (
	LogGeneral    LogCategory = "general"
	LogConn       LogCategory = "conn"
	LogHandshake  LogCategory = "handshake"
	LogTSBPD      LogCategory = "tsbpd"
	LogCongestion LogCategory = "congestion"
	LogMux        LogCategory = "mux"
	LogCrypto     LogCategory = "crypto"
	LogGroup      LogCategory = "group"
	LogFilter     LogCategory = "filter"
)

// Logger is the interface for SRT diagnostic log output.
// Implementations must be safe for concurrent use from multiple goroutines.
//
// When Config.Logger is nil (the default), no logging occurs and there is
// zero performance overhead — the logf() helper returns immediately without
// formatting the message.
type Logger interface {
	// Log emits a log message. socketID is 0 for non-connection-scoped messages.
	// Implementations should not block or perform expensive operations.
	Log(level LogLevel, category LogCategory, socketID uint32, msg string)
}

// logf formats and emits a log message if logger is non-nil.
// The format string and args are only evaluated when the logger is present,
// ensuring zero allocation when logging is disabled.
func logf(logger Logger, level LogLevel, category LogCategory, socketID uint32, format string, args ...any) {
	if logger == nil {
		return
	}
	logger.Log(level, category, socketID, fmt.Sprintf(format, args...))
}

// StdLogger returns a Logger that writes timestamped messages to w.
// Output format: "2006-01-02T15:04:05.000Z07:00 [LEVEL] category [socketID] message\n"
//
// Example:
//
//	cfg := srt.DefaultConfig()
//	cfg.Logger = srt.StdLogger(os.Stderr)
func StdLogger(w io.Writer) Logger {
	return &stdLogger{w: w}
}

type stdLogger struct {
	w  io.Writer
	mu sync.Mutex
}

func (l *stdLogger) Log(level LogLevel, category LogCategory, socketID uint32, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s [%s] %s [%d] %s\n",
		time.Now().Format("2006-01-02T15:04:05.000Z07:00"), level, category, socketID, msg)
}

// SlogLogger returns a Logger that emits messages through a [slog.Logger].
// Log levels are mapped as: LogDebug→Debug, LogNote→Info, LogWarning→Warn, LogError→Error.
// The category and socket ID are included as structured attributes.
//
// Example:
//
//	cfg := srt.DefaultConfig()
//	cfg.Logger = srt.SlogLogger(slog.Default())
func SlogLogger(l *slog.Logger) Logger {
	return &slogAdapter{l: l}
}

type slogAdapter struct {
	l *slog.Logger
}

func (a *slogAdapter) Log(level LogLevel, category LogCategory, socketID uint32, msg string) {
	var lvl slog.Level
	switch level {
	case LogDebug:
		lvl = slog.LevelDebug
	case LogNote:
		lvl = slog.LevelInfo
	case LogWarning:
		lvl = slog.LevelWarn
	default:
		lvl = slog.LevelError
	}
	a.l.LogAttrs(nil, lvl, msg,
		slog.String("category", string(category)),
		slog.Int("socket_id", int(socketID)),
	)
}
