package engine

import (
	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
)

func computeConfidence(mr matcher.Result) domain.FindingConfidence {
	if !mr.Matched {
		return domain.ConfidenceUnknown
	}
	return ConfidenceFromMode(mr.Mode)
}

// ConfidenceFromMode maps a matcher mode string to a FindingConfidence value.
// Exported so callers outside the engine (e.g. the explain command) can
// reuse the same classification.
func ConfidenceFromMode(mode string) domain.FindingConfidence {
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
