package domain

import "strings"

type FindingStatus string

const (
	FindingStatusAffected     FindingStatus = "affected"
	FindingStatusNotAffected  FindingStatus = "not_affected"
	FindingStatusInconclusive FindingStatus = "inconclusive"
	FindingStatusUnknown      FindingStatus = "unknown"
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
	// Questions lists what Cevrixa would need in order to answer, when the
	// verdict is inconclusive.
	Questions []string `json:"questions,omitempty"`
}

type Finding struct {
	VulnerabilityID string            `json:"vulnerability_id"`
	Status          FindingStatus     `json:"status"`
	Confidence      FindingConfidence `json:"confidence"`
	Risk            *Risk             `json:"risk,omitempty"`
	Applicability   Applicability     `json:"applicability"`
	Why             Why               `json:"why"`
	FixedVersions   []string          `json:"fixed_versions,omitempty"`
	Evidence        []Evidence        `json:"evidence,omitempty"`
	Conflicts       []Conflict        `json:"conflicts,omitempty"`
	KnownExploited  *KEVInfo          `json:"known_exploited,omitempty"`
	Enrichment      *Enrichment       `json:"enrichment,omitempty"`
}

type Report struct {
	Target   Target      `json:"target"`
	Findings []Finding   `json:"findings"`
	Dataset  DatasetInfo `json:"dataset"`
	// Trace records the reasoning path behind this report's decision. It is
	// populated when the caller asked for it, and omitted otherwise.
	Trace Trace `json:"trace,omitzero"`
}

// severityRank orders canonical severity labels from least to most severe.
// Gates such as --fail-on high are evaluated against this order.
var severityRank = map[string]int{
	"none":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// CanonicalSeverity normalises severity vocabulary differences between
// sources. NVD publishes MODERATE while other databases use medium; a
// difference in wording must never be reported as a difference in meaning.
func CanonicalSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "unknown", "unspecified", "not_defined":
		return ""
	case "moderate":
		return "medium"
	case "info", "informational", "negligible":
		return "none"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

// ValidGate reports whether gate is a threshold Cevrixa understands. Callers
// that accept user input must validate it, so that a typo in --fail-on fails
// loudly instead of silently disabling the gate.
func ValidGate(gate string) bool {
	switch strings.ToLower(strings.TrimSpace(gate)) {
	case "", "none", "any", "affected", "inconclusive", "kev":
		return true
	}
	_, ok := severityRank[CanonicalSeverity(gate)]
	return ok
}

// IsSeverityAtLeast reports whether the finding satisfies the given gate.
// Recognised gates: none, any, affected, inconclusive, kev, and the severity
// labels low, medium (moderate), high, critical. An unrecognised gate returns
// false; validate user input with ValidGate first.
func (f Finding) IsSeverityAtLeast(threshold string) bool {
	switch g := strings.ToLower(strings.TrimSpace(threshold)); g {
	case "", "none":
		return false
	case "any":
		return true
	case "affected":
		return f.Status == FindingStatusAffected
	case "inconclusive":
		return f.Status == FindingStatusInconclusive
	case "kev":
		return f.KnownExploited != nil
	default:
		want, ok := severityRank[CanonicalSeverity(g)]
		if !ok {
			return false
		}
		// A severity gate only applies to findings the target is actually
		// affected by. A not_affected or inconclusive finding carries the
		// vulnerability's severity for context, but must not fail a build.
		if f.Status != FindingStatusAffected {
			return false
		}
		have, ok := severityRank[CanonicalSeverity(f.severity())]
		if !ok {
			return false
		}
		return have >= want
	}
}

func (f Finding) severity() string {
	if f.Risk == nil {
		return ""
	}
	return f.Risk.Severity
}
