package source

import (
	"context"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

// VulnerabilitySource retrieves canonical vulnerability records from an upstream source.
type VulnerabilitySource interface {
	Name() string
	List(ctx context.Context, query Query) (Result, error)
}

// Query describes a provider-neutral vulnerability lookup.
type Query struct {
	ID           string
	StartIndex   int
	ResultsLimit int
}

// Result contains a page of canonical records and pagination metadata.
type Result struct {
	Vulnerabilities []domain.Vulnerability
	TotalResults    int
	StartIndex      int
	ResultsPerPage  int
}
