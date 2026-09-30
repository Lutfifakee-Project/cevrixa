package engine

import (
	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/version"
)

type PackageMatchResult struct {
	Matched  bool
	Range    string
	Fixed    string
	Mode     string
	Criteria string

	// Undecided reports that the package matched by name and ecosystem, but the
	// target version could not be compared with the applicable ranges. The
	// caller must not report the target as unaffected: an uncomparable version
	// is a gap in Cevrixa's knowledge, not a clean result.
	Undecided bool
	Reason    string
}

type osvSegment struct {
	introduced   string
	fixed        string
	lastAffected string
}

func matchPackage(purl domain.PURL, vuln domain.Vulnerability) (PackageMatchResult, bool) {
	ecosystem := normalizeEcosystem(purl.Type)
	if ecosystem == "" {
		return PackageMatchResult{}, false
	}

	for _, pkg := range vuln.PackageApplicability {
		if pkg.Ecosystem != ecosystem {
			continue
		}
		if !matchName(ecosystem, purl.Namespace, purl.Name, pkg.Name) {
			continue
		}

		for _, v := range pkg.Versions {
			if v == purl.Version {
				return PackageMatchResult{
					Matched:  true,
					Range:    "exact version " + v,
					Mode:     "exact",
					Criteria: "pkg:" + purl.Type + "/" + pkg.Name,
				}, true
			}
		}

		// The package matched by name and ecosystem. If the target version
		// cannot be compared with the applicable ranges, say so: silently
		// returning nothing here would report an affected package as clean.
		if len(pkg.Ranges) > 0 {
			if _, err := version.ParseLenient(purl.Version); err != nil {
				return PackageMatchResult{
					Mode:      "undecided",
					Criteria:  "pkg:" + purl.Type + "/" + pkg.Name,
					Undecided: true,
					Reason:    "target version " + purl.Version + " cannot be compared with " + ecosystem + " ranges",
				}, true
			}
		}

		var lastAttempt PackageMatchResult
		hasAttempt := false
		for _, r := range pkg.Ranges {
			res, ok := evalRange(purl, pkg, r)
			if !ok {
				continue
			}
			if res.Matched {
				return res, true
			}
			if !hasAttempt {
				lastAttempt = res
				hasAttempt = true
			}
		}
		if hasAttempt {
			return lastAttempt, true
		}
	}
	return PackageMatchResult{}, false
}

func evalRange(purl domain.PURL, pkg domain.PackageApplicability, r domain.PackageRange) (PackageMatchResult, bool) {
	target, err := version.ParseLenient(purl.Version)
	if err != nil {
		return PackageMatchResult{}, false
	}

	segments := buildSegments(r.Events)
	if len(segments) == 0 {
		return PackageMatchResult{}, false
	}

	var lastAttempt PackageMatchResult
	hasAttempt := false
	for _, seg := range segments {
		res, ok := evalSegment(target, purl, pkg, seg)
		if !ok {
			// A range whose bounds cannot be parsed or compared cannot be
			// evaluated. Report that instead of skipping the package.
			return PackageMatchResult{
				Mode:      "undecided",
				Criteria:  "pkg:" + purl.Type + "/" + pkg.Name,
				Undecided: true,
				Reason:    "range bounds for " + pkg.Name + " cannot be compared",
			}, true
		}
		hasAttempt = true
		if res.Matched {
			return res, true
		}
		lastAttempt = res
	}
	if !hasAttempt {
		return PackageMatchResult{}, false
	}
	return lastAttempt, true
}

func buildSegments(events []domain.PackageRangeEvent) []osvSegment {
	var segments []osvSegment
	var cur *osvSegment

	for _, ev := range events {
		if ev.Introduced != "" {
			if cur != nil {
				segments = append(segments, *cur)
			}
			cur = &osvSegment{introduced: ev.Introduced}
		}
		if cur != nil {
			if ev.Fixed != "" {
				cur.fixed = ev.Fixed
			}
			if ev.LastAffected != "" {
				cur.lastAffected = ev.LastAffected
			}
		}
	}
	if cur != nil {
		segments = append(segments, *cur)
	}
	return segments
}

func evalSegment(target version.Version, purl domain.PURL, pkg domain.PackageApplicability, seg osvSegment) (PackageMatchResult, bool) {
	var lower *version.Bound
	if seg.introduced != "" {
		v, err := version.ParseLenient(seg.introduced)
		if err != nil {
			return PackageMatchResult{}, false
		}
		lower = &version.Bound{Version: v, Inclusive: true}
	}

	var upper *version.Bound
	if seg.fixed != "" {
		v, err := version.ParseLenient(seg.fixed)
		if err != nil {
			return PackageMatchResult{}, false
		}
		upper = &version.Bound{Version: v, Inclusive: false}
	} else if seg.lastAffected != "" {
		v, err := version.ParseLenient(seg.lastAffected)
		if err != nil {
			return PackageMatchResult{}, false
		}
		upper = &version.Bound{Version: v, Inclusive: true}
	}

	rng, err := version.NewRange(lower, upper)
	if err != nil {
		return PackageMatchResult{}, false
	}

	matched := rng.Contains(target)

	mode := "range"
	if lower == nil || upper == nil {
		mode = "partial"
	}

	return PackageMatchResult{
		Matched:  matched,
		Range:    formatSegment(seg),
		Fixed:    seg.fixed,
		Mode:     mode,
		Criteria: "pkg:" + purl.Type + "/" + pkg.Name,
	}, true
}

func formatSegment(seg osvSegment) string {
	if seg.introduced == "" && seg.fixed == "" && seg.lastAffected == "" {
		return "any"
	}
	out := ""
	if seg.introduced != "" && seg.introduced != "0" {
		out = ">=" + seg.introduced
	}
	if seg.fixed != "" {
		if out != "" {
			out += " "
		}
		out += "<" + seg.fixed
	} else if seg.lastAffected != "" {
		if out != "" {
			out += " "
		}
		out += "<=" + seg.lastAffected
	}
	if out == "" {
		return "any"
	}
	return out
}
