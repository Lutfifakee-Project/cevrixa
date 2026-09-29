package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New creates a slog.Logger for the given level name. Recognized levels are
// "debug", "info", "warn", "error". Unknown levels fall back to "info".
// If quiet is true, the logger discards everything.
func New(level string, quiet bool) *slog.Logger {
	if quiet {
		return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{
			Level: slog.LevelError + 1,
		}))
	}

	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	handler := slog.NewTextHandler(os.Stderr, opts)
	return slog.New(handler)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) {
	return len(p), nil
}
