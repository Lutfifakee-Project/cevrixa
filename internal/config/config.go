package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	NVDAPIKey     string `json:"nvd_api_key,omitempty"`
	LogLevel      string `json:"log_level,omitempty"`
	DefaultOutput string `json:"default_output,omitempty"`
}

func Default() Config {
	return Config{
		LogLevel:      "info",
		DefaultOutput: "human",
	}
}

// Load reads ~/.cevrixa/config.json if it exists, applying defaults for
// any field not set. A missing config file is not an error.
func Load() (Config, error) {
	cfg := Default()

	path, err := defaultPath()
	if err != nil {
		return cfg, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("config: read %s: %w", path, err)
	}

	var fileCfg Config
	if err := json.Unmarshal(raw, &fileCfg); err != nil {
		return cfg, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if fileCfg.LogLevel != "" {
		cfg.LogLevel = fileCfg.LogLevel
	}
	if fileCfg.DefaultOutput != "" {
		cfg.DefaultOutput = fileCfg.DefaultOutput
	}
	if fileCfg.NVDAPIKey != "" {
		cfg.NVDAPIKey = fileCfg.NVDAPIKey
	}
	return cfg, nil
}

func defaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cevrixa", "config.json"), nil
}
