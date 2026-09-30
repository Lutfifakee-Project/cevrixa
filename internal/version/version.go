package version

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Version is a normalized software version with numeric core components,
// optional SemVer-compatible pre-release identifiers, and optional post-release
// identifiers. Build metadata is accepted and intentionally ignored for
// comparison.
type Version struct {
	raw        string
	components []uint64
	prerelease []Identifier
	// suffix holds post-release identifiers: text that sorts *after* the plain
	// version. Debian style upstream versions carry a letter suffix
	// (openssl 1.1.1c) and package revisions are post-release too, so
	// 1.1.1 < 1.1.1c < 1.1.2 and 2.4.7 < 2.4.7-1.
	suffix []Identifier
}

// Identifier represents one pre-release identifier.
type Identifier struct {
	numeric bool
	number  uint64
	text    string
}

// Parse parses a version string such as 2.4.49, v2.4.49, or 1.2.3-rc.1+build7.
// The parser intentionally supports a practical numeric version subset rather
// than claiming to implement every ecosystem-specific version scheme.
func Parse(input string) (Version, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return Version{}, fmt.Errorf("version: empty input")
	}

	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	if s == "" {
		return Version{}, fmt.Errorf("version: missing numeric component")
	}

	// Ignore build metadata for ordering, consistent with SemVer.
	if idx := strings.IndexByte(s, '+'); idx >= 0 {
		s = s[:idx]
	}

	core := s
	prereleasePart := ""
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		core = s[:idx]
		prereleasePart = s[idx+1:]
		if prereleasePart == "" {
			return Version{}, fmt.Errorf("version %q: empty prerelease identifier", input)
		}
	}

	coreParts := strings.Split(core, ".")
	if len(coreParts) == 0 {
		return Version{}, fmt.Errorf("version %q: missing numeric components", input)
	}

	components := make([]uint64, len(coreParts))
	var suffix []Identifier
	for i, part := range coreParts {
		if part == "" {
			return Version{}, fmt.Errorf("version %q: empty numeric component", input)
		}
		digits, letters := splitLetterSuffix(part)
		if !allDigits(digits) {
			return Version{}, fmt.Errorf("version %q: invalid numeric component %q", input, part)
		}
		if letters != "" {
			// Debian style upstream versions may carry a letter suffix, as in
			// openssl 1.1.1c. Keeping it as a post-release identifier keeps
			// 1.1.1 < 1.1.1c < 1.1.2 instead of rejecting the version.
			suffix = append(suffix, Identifier{text: letters})
		}
		if len(digits) > 1 && digits[0] == '0' {
			return Version{}, fmt.Errorf("version %q: leading zero in numeric component %q", input, part)
		}
		n, err := strconv.ParseUint(digits, 10, 64)
		if err != nil {
			return Version{}, fmt.Errorf("version %q: invalid numeric component %q: %w", input, part, err)
		}
		components[i] = n
	}

	var prerelease []Identifier
	if prereleasePart != "" {
		ids := strings.Split(prereleasePart, ".")
		prerelease = make([]Identifier, len(ids))
		for i, id := range ids {
			if id == "" {
				return Version{}, fmt.Errorf("version %q: empty prerelease identifier", input)
			}
			if allDigits(id) {
				if len(id) > 1 && id[0] == '0' {
					return Version{}, fmt.Errorf("version %q: leading zero in numeric prerelease identifier %q", input, id)
				}
				n, err := strconv.ParseUint(id, 10, 64)
				if err != nil {
					return Version{}, fmt.Errorf("version %q: invalid prerelease identifier %q: %w", input, id, err)
				}
				prerelease[i] = Identifier{numeric: true, number: n}
				continue
			}
			for _, r := range id {
				if !isAllowedPrereleaseChar(r) {
					return Version{}, fmt.Errorf("version %q: invalid prerelease identifier %q", input, id)
				}
			}
			prerelease[i] = Identifier{text: id}
		}
	}

	return Version{
		raw:        input,
		components: components,
		prerelease: prerelease,
		suffix:     suffix,
	}, nil
}

// MustParse parses input and panics only when the input is a programmer-known
// constant that is invalid.
func MustParse(input string) Version {
	v, err := Parse(input)
	if err != nil {
		panic(err)
	}
	return v
}

// Raw returns the original version string supplied to Parse.
func (v Version) Raw() string { return v.raw }

// String returns the original version string supplied to Parse.
func (v Version) String() string { return v.raw }

// Compare returns -1 when v < other, 0 when equal, and 1 when v > other.
// Missing numeric components are treated as zero for practical generic-version
// semantics, so 2.4 and 2.4.0 compare equal. Pre-release versions sort before
// their corresponding release version.
func (v Version) Compare(other Version) int {
	max := len(v.components)
	if len(other.components) > max {
		max = len(other.components)
	}

	for i := 0; i < max; i++ {
		var a, b uint64
		if i < len(v.components) {
			a = v.components[i]
		}
		if i < len(other.components) {
			b = other.components[i]
		}
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
	}

	// A release version has higher precedence than a pre-release version.
	if len(v.prerelease) == 0 && len(other.prerelease) == 0 {
		// Same numeric core and no pre-release: a post-release identifier
		// sorts after the plain release, so 1.1.1 < 1.1.1c and 2.4.7 < 2.4.7-1.
		return compareIdentifiers(v.suffix, other.suffix)
	}
	if len(v.prerelease) == 0 {
		return 1
	}
	if len(other.prerelease) == 0 {
		return -1
	}

	max = len(v.prerelease)
	if len(other.prerelease) > max {
		max = len(other.prerelease)
	}
	for i := 0; i < max; i++ {
		if i >= len(v.prerelease) {
			return -1
		}
		if i >= len(other.prerelease) {
			return 1
		}

		a := v.prerelease[i]
		b := other.prerelease[i]
		if a.numeric && b.numeric {
			if a.number < b.number {
				return -1
			}
			if a.number > b.number {
				return 1
			}
			continue
		}
		if a.numeric != b.numeric {
			if a.numeric {
				return -1
			}
			return 1
		}
		if a.text < b.text {
			return -1
		}
		if a.text > b.text {
			return 1
		}
	}

	return compareIdentifiers(v.suffix, other.suffix)
}

// compareIdentifiers orders two identifier lists: a shorter list that is a
// prefix of the other sorts first, numeric identifiers sort before text ones,
// and equal lists compare equal.
func compareIdentifiers(a, b []Identifier) int {
	max := len(a)
	if len(b) > max {
		max = len(b)
	}
	for i := 0; i < max; i++ {
		if i >= len(a) {
			return -1
		}
		if i >= len(b) {
			return 1
		}
		x, y := a[i], b[i]
		if x.numeric && y.numeric {
			if x.number < y.number {
				return -1
			}
			if x.number > y.number {
				return 1
			}
			continue
		}
		if x.numeric != y.numeric {
			if x.numeric {
				return -1
			}
			return 1
		}
		if x.text < y.text {
			return -1
		}
		if x.text > y.text {
			return 1
		}
	}
	return 0
}

// splitLetterSuffix splits a core component such as "1c" into its numeric part
// ("1") and its trailing alphabetic part ("c"). A component that is not exactly
// "<digits><letters>" is returned unchanged with an empty suffix, so that
// invalid input still fails validation.
func splitLetterSuffix(part string) (digits, letters string) {
	i := 0
	for i < len(part) && isDigitByte(part[i]) {
		i++
	}
	if i == 0 || i == len(part) {
		return part, ""
	}
	for j := i; j < len(part); j++ {
		if !isLetterByte(part[j]) {
			return part, ""
		}
	}
	return part[:i], part[i:]
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }

func isLetterByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// Equal reports whether two parsed versions compare equal.
func (v Version) Equal(other Version) bool { return v.Compare(other) == 0 }

// Bound describes one end of a version range.
type Bound struct {
	Version   Version
	Inclusive bool
}

// Range describes a single contiguous version interval.
// Nil lower/upper bounds represent an open-ended interval.
type Range struct {
	Lower *Bound
	Upper *Bound
}

// NewRange constructs and validates a single version range.
func NewRange(lower *Bound, upper *Bound) (Range, error) {
	if lower != nil && upper != nil {
		cmp := lower.Version.Compare(upper.Version)
		if cmp > 0 {
			return Range{}, fmt.Errorf("version range: lower bound is greater than upper bound")
		}
		if cmp == 0 && (!lower.Inclusive || !upper.Inclusive) {
			return Range{}, fmt.Errorf("version range: empty interval")
		}
	}
	return Range{Lower: lower, Upper: upper}, nil
}

// Contains reports whether v falls within the range boundaries.
func (r Range) Contains(v Version) bool {
	if r.Lower != nil {
		cmp := v.Compare(r.Lower.Version)
		if cmp < 0 || (cmp == 0 && !r.Lower.Inclusive) {
			return false
		}
	}
	if r.Upper != nil {
		cmp := v.Compare(r.Upper.Version)
		if cmp > 0 || (cmp == 0 && !r.Upper.Inclusive) {
			return false
		}
	}
	return true
}

// ParseRange parses a compact AND-style expression such as:
//
//	>=2.4.0,<2.4.51
//	>2.4.49
//	<=2.4.50
//	2.4.49
//
// Only one contiguous interval is represented in Phase 1. OR expressions and
// ecosystem-specific range syntax are intentionally deferred to later phases.
func ParseRange(expr string) (Range, error) {
	s := strings.TrimSpace(expr)
	if s == "" {
		return Range{}, fmt.Errorf("version range: empty expression")
	}

	var lower, upper *Bound
	for _, rawConstraint := range strings.Split(s, ",") {
		constraint := strings.TrimSpace(rawConstraint)
		if constraint == "" {
			return Range{}, fmt.Errorf("version range: empty constraint")
		}

		op := "="
		versionText := constraint
		for _, candidate := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(constraint, candidate) {
				op = candidate
				versionText = strings.TrimSpace(strings.TrimPrefix(constraint, candidate))
				break
			}
		}
		if versionText == "" {
			return Range{}, fmt.Errorf("version range: missing version in %q", constraint)
		}

		v, err := Parse(versionText)
		if err != nil {
			return Range{}, err
		}

		switch op {
		case ">=":
			candidate := &Bound{Version: v, Inclusive: true}
			if lower == nil || candidate.Version.Compare(lower.Version) > 0 || (candidate.Version.Equal(lower.Version) && !lower.Inclusive) {
				lower = candidate
			}
		case ">":
			candidate := &Bound{Version: v, Inclusive: false}
			if lower == nil || candidate.Version.Compare(lower.Version) > 0 || (candidate.Version.Equal(lower.Version) && lower.Inclusive) {
				lower = candidate
			}
		case "<=":
			candidate := &Bound{Version: v, Inclusive: true}
			if upper == nil || candidate.Version.Compare(upper.Version) < 0 || (candidate.Version.Equal(upper.Version) && !upper.Inclusive) {
				upper = candidate
			}
		case "<":
			candidate := &Bound{Version: v, Inclusive: false}
			if upper == nil || candidate.Version.Compare(upper.Version) < 0 || (candidate.Version.Equal(upper.Version) && upper.Inclusive) {
				upper = candidate
			}
		case "=":
			candidateLower := &Bound{Version: v, Inclusive: true}
			candidateUpper := &Bound{Version: v, Inclusive: true}
			if lower == nil || candidateLower.Version.Compare(lower.Version) > 0 ||
				(candidateLower.Version.Equal(lower.Version) && candidateLower.Inclusive && !lower.Inclusive) {
				lower = candidateLower
			}
			if upper == nil || candidateUpper.Version.Compare(upper.Version) < 0 ||
				(candidateUpper.Version.Equal(upper.Version) && candidateUpper.Inclusive && !upper.Inclusive) {
				upper = candidateUpper
			}
		}
	}

	return NewRange(lower, upper)
}
func ParseLenient(input string) (Version, error) {
	if v, err := Parse(input); err == nil {
		return v, nil
	}

	s := strings.TrimSpace(input)
	if s == "" {
		return Version{}, fmt.Errorf("version: empty input")
	}

	// Strip Debian/RPM epoch prefix "N:rest".
	if idx := strings.IndexByte(s, ':'); idx > 0 && allDigits(s[:idx]) {
		s = s[idx+1:]
	}

	// Strip leading tilde (Debian pre-release marker) so "~1.2.3" parses as "1.2.3".
	s = strings.TrimPrefix(s, "~")

	// Strip trailing whitespace-separated junk such as "1.2.3 something".
	if idx := strings.IndexAny(s, " \t"); idx >= 0 {
		s = s[:idx]
	}

	return Parse(s)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isAllowedPrereleaseChar(r rune) bool {
	return r == '-' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// ParseDebian parses a Debian package version such as:
//
//	1:2.4.7-1ubuntu4.20
//	2.4.7-1
//	1:1.2.3-4
//
// Epoch (before ':') is stripped. The upstream version is compared using
// generic semantics, including Debian letter suffixes such as 1.1.1c. The
// Debian revision (after the last '-') is captured as a post-release
// identifier so that "2.4.7-1" < "2.4.7-2" and "2.4.7" < "2.4.7-1".
//
// This is a pragmatic approximation, not a full Debian policy implementation.
func ParseDebian(s string) (Version, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Version{}, fmt.Errorf("version: empty input")
	}

	body := raw
	if idx := strings.IndexByte(body, ':'); idx > 0 && allDigits(body[:idx]) {
		body = body[idx+1:]
	}

	var upstream, revision string
	if idx := strings.LastIndexByte(body, '-'); idx > 0 {
		upstream = body[:idx]
		revision = body[idx+1:]
	} else {
		upstream = body
	}

	v, err := Parse(upstream)
	if err != nil {
		return Version{}, fmt.Errorf("version: parse debian upstream %q: %w", upstream, err)
	}

	if revision != "" {
		v.suffix = append(v.suffix, Identifier{text: "rev:" + revision})
	}
	v.raw = raw
	return v, nil
}

// ParseRPM parses an RPM package version such as:
//
//	1.2.3-4.el8
//	2.4.49-1
//
// Structure is VERSION-RELEASE. The release is captured as a post-release
// identifier so that "1.2.3-4.el8" > "1.2.3" (version alone).
func ParseRPM(s string) (Version, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Version{}, fmt.Errorf("version: empty input")
	}

	var upstream, release string
	if idx := strings.LastIndexByte(raw, '-'); idx > 0 {
		upstream = raw[:idx]
		release = raw[idx+1:]
	} else {
		upstream = raw
	}

	v, err := Parse(upstream)
	if err != nil {
		return Version{}, fmt.Errorf("version: parse rpm upstream %q: %w", upstream, err)
	}

	if release != "" {
		v.suffix = append(v.suffix, Identifier{text: "rel:" + release})
	}
	v.raw = raw
	return v, nil
}
