package resolver

import "strings"

func NormalizeProduct(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	var b strings.Builder
	lastUnderscore := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore && b.Len() > 0 {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.TrimRight(b.String(), "_")
}

func BuildCPE(base, version string) string {
	parts := strings.Split(base, ":")
	if len(parts) != 5 {
		return ""
	}
	v := version
	if v == "" {
		v = "*"
	}
	parts = append(parts, v)
	for len(parts) < 13 {
		parts = append(parts, "*")
	}
	return strings.Join(parts, ":")
}
