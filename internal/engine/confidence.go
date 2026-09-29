package engine

import (
	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
)

func computeConfidence(mr matcher.Result) domain.FindingConfidence {
	if !mr.Matched {
		return domain.ConfidenceUnknown
	}
	return confidenceFromMode(mr.Mode)
}

func confidenceFromMode(mode string) domain.FindingConfidence {
	switch mode {
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
