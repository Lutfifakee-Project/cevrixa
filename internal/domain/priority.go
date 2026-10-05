package domain

import (
	"fmt"
	"sort"
	"strings"
)

// Priority levels, from least to most urgent.
const (
	PriorityNone     = "none"
	PriorityLow      = "low"
	PriorityMedium   = "medium"
	PriorityHigh     = "high"
	PriorityCritical = "critical"
)

// Priority is a prioritization summary for a finding. It ranks how urgently a
// finding should be addressed; it never changes applicability. A finding keeps
// its status (affected, not_affected, inconclusive); priority is metadata
// attached afterward.
type Priority struct {
	Level   string   `json:"level"`
	Factors []string `json:"factors,omitempty"`
}

// priorityRank orders the levels for comparison.
var priorityRank = map[string]int{
	PriorityNone:     0,
	PriorityLow:      1,
	PriorityMedium:   2,
	PriorityHigh:     3,
	PriorityCritical: 4,
}

// ComputePriority derives a prioritization summary from a finding. Only an
// affected finding has a priority; anything else is "none", because ranking a
// question that was not answered would imply an urgency the evidence does not
// support.
//
// Inputs are combined, never allowed to override each other: a known-exploited
// vulnerability is critical, a high EPSS score raises urgency, and severity
// sets a floor. The factors are recorded so the level is inspectable.
func ComputePriority(f Finding) Priority {
	if f.Status != FindingStatusAffected {
		return Priority{Level: PriorityNone}
	}

	factors := make([]string, 0, 3)
	level := PriorityLow

	// Severity sets the floor.
	if f.Risk != nil {
		switch CanonicalSeverity(f.Risk.Severity) {
		case "critical":
			level = PriorityCritical
		case "high":
			if priorityRank[level] < priorityRank[PriorityHigh] {
				level = PriorityHigh
			}
		case "medium":
			if priorityRank[level] < priorityRank[PriorityMedium] {
				level = PriorityMedium
			}
		}
		if f.Risk.Severity != "" {
			factors = append(factors, "severity "+strings.ToUpper(f.Risk.Severity))
		}
	}

	// Known exploitation is the strongest signal.
	if f.KnownExploited != nil || (f.Risk != nil && f.Risk.KEV) {
		level = PriorityCritical
		factors = append(factors, "known exploited")
	}

	// A high EPSS probability raises urgency but is not proof of exploitation.
	if f.Risk != nil && f.Risk.EPSS >= 0.5 {
		if priorityRank[level] < priorityRank[PriorityHigh] {
			level = PriorityHigh
		}
		factors = append(factors, fmt.Sprintf("EPSS %.2f", f.Risk.EPSS))
	}

	sort.Strings(factors)
	return Priority{Level: level, Factors: factors}
}
