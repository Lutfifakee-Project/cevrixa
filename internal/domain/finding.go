package domain

type FindingStatus string

const (
	FindingStatusAffected    FindingStatus = "affected"
	FindingStatusNotAffected FindingStatus = "not_affected"
	FindingStatusUnknown     FindingStatus = "unknown"
	FindingStatusConflict    FindingStatus = "conflict"
)

type FindingConfidence string

const (
	ConfidenceExact    FindingConfidence = "exact"
	ConfidenceStrong   FindingConfidence = "strong"
	ConfidenceModerate FindingConfidence = "moderate"
	ConfidenceWeak     FindingConfidence = "weak"
	ConfidenceUnknown  FindingConfidence = "unknown"
)

type Applicability struct {
	Matched   bool   `json:"matched"`
	Range     string `json:"range,omitempty"`
	MatchedBy string `json:"matched_by,omitempty"`
	Source    string `json:"source,omitempty"`
}

type Why struct {
	IdentityMatch string   `json:"identity_match,omitempty"`
	VersionMatch  string   `json:"version_match,omitempty"`
	FixedReason   string   `json:"fixed_reason,omitempty"`
	Steps         []string `json:"steps,omitempty"`
}

type Finding struct {
	VulnerabilityID string            `json:"vulnerability_id"`
	Status          FindingStatus     `json:"status"`
	Confidence      FindingConfidence `json:"confidence"`
	Applicability   Applicability     `json:"applicability"`
	Why             Why               `json:"why"`
	FixedVersions   []string          `json:"fixed_versions,omitempty"`
	Evidence        []Evidence        `json:"evidence,omitempty"`
	Conflicts       []Conflict        `json:"conflicts,omitempty"`
	KnownExploited  *KEVInfo          `json:"known_exploited,omitempty"`
}

type Report struct {
	Target   Target    `json:"target"`
	Findings []Finding `json:"findings"`
}

func (f Finding) IsSeverityAtLeast(threshold string) bool {
	switch threshold {
	case "", "none":
		return false
	case "any":
		return true
	case "affected":
		return f.Status == FindingStatusAffected || f.Status == FindingStatusConflict
	case "kev":
		return f.KnownExploited != nil
	default:
		return false
	}
}
