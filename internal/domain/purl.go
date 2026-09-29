package domain

import (
	"fmt"
	"sort"
	"strings"
)

type PURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
}

func ParsePURL(s string) (PURL, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return PURL{}, fmt.Errorf("purl: empty input")
	}
	if !strings.HasPrefix(raw, "pkg:") {
		return PURL{}, fmt.Errorf("purl: must start with %q, got %q", "pkg:", s)
	}

	rest := raw[len("pkg:"):]

	var subpath string
	if idx := strings.IndexByte(rest, '#'); idx >= 0 {
		subpath = rest[idx+1:]
		rest = rest[:idx]
	}

	var qualifiers map[string]string
	if idx := strings.IndexByte(rest, '?'); idx >= 0 {
		qualifiers = parsePURLQualifiers(rest[idx+1:])
		rest = rest[:idx]
	}

	var version string
	if idx := strings.IndexByte(rest, '@'); idx >= 0 {
		version = rest[idx+1:]
		rest = rest[:idx]
	}

	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return PURL{}, fmt.Errorf("purl: missing name (need at least type/name), got %q", s)
	}

	typ := strings.ToLower(parts[0])
	if typ == "" {
		return PURL{}, fmt.Errorf("purl: empty type")
	}

	name := parts[len(parts)-1]
	if name == "" {
		return PURL{}, fmt.Errorf("purl: empty name")
	}

	var namespace string
	if len(parts) > 2 {
		namespace = strings.Join(parts[1:len(parts)-1], "/")
	}

	return PURL{
		Type:       typ,
		Namespace:  namespace,
		Name:       name,
		Version:    version,
		Qualifiers: qualifiers,
		Subpath:    subpath,
	}, nil
}

func parsePURLQualifiers(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := make(map[string]string)
	for _, kv := range strings.Split(s, "&") {
		if kv == "" {
			continue
		}
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(kv[:idx])
		value := kv[idx+1:]
		if key == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (p PURL) String() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	if p.Namespace != "" {
		b.WriteByte('/')
		b.WriteString(p.Namespace)
	}
	b.WriteByte('/')
	b.WriteString(p.Name)
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(p.Version)
	}
	if len(p.Qualifiers) > 0 {
		keys := make([]string, 0, len(p.Qualifiers))
		for k := range p.Qualifiers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('?')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte('&')
			}
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(p.Qualifiers[k])
		}
	}
	if p.Subpath != "" {
		b.WriteByte('#')
		b.WriteString(p.Subpath)
	}
	return b.String()
}
