package engine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

// ErrNotFound reports that a vulnerability ID is not present in the dataset.
// It lets callers distinguish a genuine miss from a store or parse failure.
var ErrNotFound = errors.New("vulnerability not found")

// FindByID returns the vulnerability record whose ID (or any alias) matches
// vulnID. The search order is: store first (if non-nil), then embedded
// fixtures. Matching is case-insensitive.
func FindByID(vulnID string, opts Options) (domain.Vulnerability, error) {
	if vulnID == "" {
		return domain.Vulnerability{}, fmt.Errorf("engine: vulnerability ID is required")
	}
	want := strings.ToUpper(vulnID)

	vulns, _, err := loadVulnerabilities(opts)
	if err != nil {
		return domain.Vulnerability{}, err
	}

	for _, v := range vulns {
		if strings.EqualFold(v.ID, want) {
			return v, nil
		}
		for _, a := range v.Aliases {
			if strings.EqualFold(a, want) {
				return v, nil
			}
		}
	}
	return domain.Vulnerability{}, fmt.Errorf("engine: vulnerability %q: %w", vulnID, ErrNotFound)
}
