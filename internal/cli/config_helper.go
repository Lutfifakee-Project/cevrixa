package cli

import (
	"github.com/Lutfifakee-Project/cevrixa/internal/config"
)

func loadConfigIfPresent() (config.Config, error) {
	return config.Load()
}
