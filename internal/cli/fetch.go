package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/cevrixa/internal/config"
	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/source"
	"github.com/Lutfifakee-Project/cevrixa/internal/source/nvd"
)

// nvdBaseURL is the NVD API base URL used by fetch-on-miss. It is a variable so
// tests can point the fetch at a local mock server instead of the live API.
var nvdBaseURL = nvd.DefaultBaseURL

// fetchTimeout bounds a single on-demand NVD lookup so an unreachable or slow
// API cannot hang an interactive explain indefinitely.
const fetchTimeout = 30 * time.Second

// errCVENotInNVD marks a successful NVD query that returned no record for the
// requested CVE. It is deliberately distinct from a transport, rate-limit, or
// parse failure: the source answered, and the answer was no such CVE.
var errCVENotInNVD = errors.New("CVE not found in NVD")

// fetchVulnByID retrieves one CVE from NVD by ID. It is used only when the
// local dataset does not already contain the requested ID, so the local lookup
// always stays the primary path. A response that does not contain the requested
// ID is an error rather than a silent wrong answer.
func fetchVulnByID(ctx context.Context, cveID string) (domain.Vulnerability, error) {
	cfg, _ := config.Load()

	client := nvd.NewClient(&http.Client{Timeout: fetchTimeout})
	client.BaseURL = nvdBaseURL
	if cfg.NVDAPIKey != "" {
		client.APIKey = cfg.NVDAPIKey
	}

	res, err := client.List(ctx, source.Query{ID: cveID})
	if err != nil {
		return domain.Vulnerability{}, fmt.Errorf("fetch from NVD failed: %w", err)
	}
	if len(res.Vulnerabilities) == 0 {
		return domain.Vulnerability{}, errCVENotInNVD
	}
	for _, v := range res.Vulnerabilities {
		if strings.EqualFold(v.ID, cveID) {
			return v, nil
		}
	}
	return domain.Vulnerability{}, fmt.Errorf("NVD response for %q did not contain that CVE", cveID)
}
