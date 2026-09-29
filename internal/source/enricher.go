package source

import (
	"context"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

// VulnerabilityEnricher adds supplemental intelligence to a canonical
// vulnerability record. Enrichers are deliberately separate from
// VulnerabilitySource because enrichment is keyed by an existing vulnerability
// identifier rather than a general list query.
type VulnerabilityEnricher interface {
	Name() string
	Enrich(ctx context.Context, vulnerabilityID string) (domain.Enrichment, error)
}
