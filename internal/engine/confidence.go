package engine

import (
	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
)

func computeConfidence(mr matcher.Result) domain.FindingConfidence {
	if !mr.Matched {
		return domain.ConfidenceUnknown
	}

	switch mr.Mode {
	case "exact":
		return domain.ConfidenceExact
	case "range":
		return domain.ConfidenceStrong
	case "partial":
		return domain.ConfidenceModerate
	case "wildcard":
		return domain.ConfidenceWeak
	default:
		return domain.ConfidenceUnknown
	}
}
