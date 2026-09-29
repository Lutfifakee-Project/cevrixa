package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.LogLevel != "info" {
		t.Fatalf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.DefaultOutput != "human" {
		t.Fatalf("DefaultOutput = %q, want human", cfg.DefaultOutput)
	}
}

func TestLoadMissingFile(t *testing.T) {
	// Point HOME at a temp dir with no .cevrixa/config.json
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with missing file should not error, got: %v", err)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("expected default LogLevel, got %q", cfg.LogLevel)
	}
}

func TestLoadValidFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	dir := filepath.Join(tmp, ".cevrixa")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	content := `{"log_level": "debug", "default_output": "json", "nvd_api_key": "test-key"}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q", cfg.LogLevel)
	}
	if cfg.DefaultOutput != "json" {
		t.Fatalf("DefaultOutput = %q", cfg.DefaultOutput)
	}
	if cfg.NVDAPIKey != "test-key" {
		t.Fatalf("NVDAPIKey = %q", cfg.NVDAPIKey)
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	dir := filepath.Join(tmp, ".cevrixa")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte("{not json"), 0o644)

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
