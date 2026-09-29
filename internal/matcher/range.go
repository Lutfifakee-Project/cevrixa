package matcher

import (
	"fmt"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/version"
)

func parseVersion(raw string) (version.Version, error) {
	return version.ParseLenient(raw)
}

func buildRange(m domain.CPEMatch) (version.Range, error) {
	var lower, upper *version.Bound

	if m.VersionStart != "" {
		v, err := version.ParseLenient(m.VersionStart)
		if err != nil {
			return version.Range{}, fmt.Errorf("matcher: parse version_start %q: %w", m.VersionStart, err)
		}
		lower = &version.Bound{Version: v, Inclusive: m.VersionStartMode != domain.BoundModeExcluding}
	}
	if m.VersionEnd != "" {
		v, err := version.ParseLenient(m.VersionEnd)
		if err != nil {
			return version.Range{}, fmt.Errorf("matcher: parse version_end %q: %w", m.VersionEnd, err)
		}
		upper = &version.Bound{Version: v, Inclusive: m.VersionEndMode == domain.BoundModeIncluding}
	}
	return version.NewRange(lower, upper)
}

func formatRange(m domain.CPEMatch) string {
	if m.VersionStart == "" && m.VersionEnd == "" {
		return "any"
	}
	out := ""
	if m.VersionStart != "" {
		if m.VersionStartMode == domain.BoundModeIncluding {
			out = ">=" + m.VersionStart
		} else {
			out = ">" + m.VersionStart
		}
	}
	if m.VersionEnd != "" {
		if out != "" {
			out += " "
		}
		if m.VersionEndMode == domain.BoundModeIncluding {
			out += "<=" + m.VersionEnd
		} else {
			out += "<" + m.VersionEnd
		}
	}
	return out
}

func fixedVersion(m domain.CPEMatch) string {
	if m.VersionEnd != "" && m.VersionEndMode == domain.BoundModeExcluding {
		return m.VersionEnd
	}
	return ""
}

func classifyMode(m domain.CPEMatch) string {
	hasStart := m.VersionStart != ""
	hasEnd := m.VersionEnd != ""

	if !hasStart && !hasEnd {
		return "wildcard"
	}
	if hasStart && hasEnd {
		if m.VersionStart == m.VersionEnd &&
			m.VersionStartMode == domain.BoundModeIncluding &&
			m.VersionEndMode == domain.BoundModeIncluding {
			return "exact"
		}
		return "range"
	}
	return "partial"
}
