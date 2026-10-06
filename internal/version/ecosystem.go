package version

// Scheme names the version semantics a target should be evaluated with. They
// are derived from an ecosystem, not chosen by the user, so that a Debian
// package and an rpm package are not compared with generic semantics when the
// ecosystem says otherwise.
type Scheme string

const (
	SchemeGeneric Scheme = "generic"
	SchemeDebian  Scheme = "debian"
	SchemeRPM     Scheme = "rpm"
)

// ParseForScheme parses input with the semantics of the given scheme. A generic
// scheme (or an empty one) uses the lenient generic parser. Debian and RPM use
// their own parsers, so an epoch or a package revision is modelled instead of
// being misread as a pre-release.
func ParseForScheme(input string, scheme Scheme) (Version, error) {
	switch scheme {
	case SchemeDebian:
		return ParseDebian(input)
	case SchemeRPM:
		return ParseRPM(input)
	default:
		return ParseLenient(input)
	}
}
