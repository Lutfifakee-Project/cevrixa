package version

// normalizePreReleaseSeparators rewrites PEP 440 style pre-release markers that
// sit between digits, such as 3.2a1 or 1.10rc1, into a hyphenated pre-release
// (3.2-a1, 1.10-rc1). The generic parser already reads a hyphenated pre-release,
// and a pre-release sorts before its plain release, which matches PEP 440:
// 3.2a1 < 3.2.
//
// A trailing letter with no following digit (Debian openssl 1.1.1c) is left
// alone: that is a post-release suffix, handled elsewhere.
func normalizePreReleaseSeparators(s string) string {
	// Only look at the core, before any existing pre-release or build metadata.
	end := len(s)
	for i := 0; i < len(s); i++ {
		if s[i] == '-' || s[i] == '+' {
			end = i
			break
		}
	}
	core := s[:end]

	for i := 1; i < len(core)-1; i++ {
		if !isDigitByte(core[i-1]) || !isLetterByte(core[i]) {
			continue
		}
		// Run of letters, then require a digit right after.
		j := i
		for j < len(core) && isLetterByte(core[j]) {
			j++
		}
		if j < len(core) && isDigitByte(core[j]) {
			return core[:i] + "-" + core[i:] + s[end:]
		}
	}
	return s
}
