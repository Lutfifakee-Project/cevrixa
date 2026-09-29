package source

import (
	"context"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

type VulnerabilitySource interface {
	Name() string
	List(ctx context.Context, query Query) (Result, error)
}

type Query struct {
	ID           string
	PackageName  string
	Ecosystem    string
	PURL         string
	Version      string
	Commit       string
	PageToken    string
	StartIndex   int
	ResultsLimit int

	// Date range filters for incremental sync (NVD).
	// Format: ISO-8601, e.g. "2024-01-01T00:00:00.000".
	// When both are set, they must span at most 120 days (NVD limit).
	LastModStart string
	LastModEnd   string
}

type Result struct {
	Vulnerabilities []domain.Vulnerability
	TotalResults    int
	StartIndex      int
	ResultsPerPage  int
	NextPageToken   string
}
