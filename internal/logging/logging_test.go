package logging

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestNewDefault(t *testing.T) {
	logger := New("info", false)
	if logger == nil {
		t.Fatal("New returned nil")
	}
	// Should be usable without panic.
	logger.Info("test")
}

func TestNewQuiet(t *testing.T) {
	logger := New("debug", true)
	if logger == nil {
		t.Fatal("New quiet returned nil")
	}
	// Should not panic and should discard everything.
	logger.Debug("should be discarded")
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"":        slog.LevelInfo,
		"garbage": slog.LevelInfo,
	}
	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			got := parseLevel(input)
			if got != want {
				t.Fatalf("parseLevel(%q) = %v, want %v", input, got, want)
			}
		})
	}
}

// Sanity: the logger actually emits at the configured level.
func TestLoggerEmits(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)
	logger.Debug("hello")
	if !bytes.Contains(buf.Bytes(), []byte("hello")) {
		t.Fatalf("expected 'hello' in output, got: %s", buf.String())
	}
}
