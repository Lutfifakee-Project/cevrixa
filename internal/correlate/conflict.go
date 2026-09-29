package correlate

import "github.com/Lutfifakee-Project/cevrixa/internal/domain"

var scalarConflictKinds = map[domain.EvidenceKind]bool{
	domain.EvidenceKindSeverity: true,
	domain.EvidenceKindStatus:   true,
	domain.EvidenceKindCVSS:     true,
	domain.EvidenceKindKEV:      true,
}

func detectConflicts(evidence []domain.Evidence) []domain.Conflict {
	type key struct {
		kind  domain.EvidenceKind
		group string
	}
	type bucket struct {
		values []domain.ConflictValue
		seen   map[string]bool
	}

	buckets := make(map[key]*bucket)
	order := make([]key, 0)

	for _, e := range evidence {
		if !scalarConflictKinds[e.Kind] {
			continue
		}
		if e.Value == "" {
			continue
		}

		k := key{kind: e.Kind}
		if e.Kind == domain.EvidenceKindCVSS {
			k.group = cvssGroupKey(evidence, e)
		}

		b, ok := buckets[k]
		if !ok {
			b = &bucket{seen: make(map[string]bool)}
			buckets[k] = b
			order = append(order, k)
		}
		dedupKey := e.Source + "\x00" + e.Value
		if b.seen[dedupKey] {
			continue
		}
		b.seen[dedupKey] = true
		b.values = append(b.values, domain.ConflictValue{
			Source: e.Source,
			Value:  e.Value,
		})
	}

	var out []domain.Conflict
	for _, k := range order {
		b := buckets[k]
		if b == nil || len(b.values) < 2 {
			continue
		}
		if !hasMultipleSources(b.values) {
			continue
		}
		first := b.values[0].Value
		allEqual := true
		for _, v := range b.values[1:] {
			if v.Value != first {
				allEqual = false
				break
			}
		}
		if allEqual {
			continue
		}
		out = append(out, domain.Conflict{
			Kind:   k.kind,
			Values: b.values,
		})
	}
	return out
}

func hasMultipleSources(values []domain.ConflictValue) bool {
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		seen[v.Source] = struct{}{}
	}
	return len(seen) >= 2
}

func cvssGroupKey(all []domain.Evidence, target domain.Evidence) string {
	for _, e := range all {
		if e.Kind != domain.EvidenceKindCVSSVersion {
			continue
		}
		if e.Source != target.Source {
			continue
		}
		return e.Value
	}
	return ""
}
