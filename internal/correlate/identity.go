package correlate

import (
	"sort"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

type identityGroup struct {
	vulns       []domain.Vulnerability
	identifiers []string
}

func groupByIdentity(vulns []domain.Vulnerability) []identityGroup {
	if len(vulns) == 0 {
		return nil
	}

	parent := make([]int, len(vulns))
	rank := make([]int, len(vulns))
	for i := range parent {
		parent[i] = i
	}

	var find func(int) int
	find = func(i int) int {
		if parent[i] != i {
			parent[i] = find(parent[i])
		}
		return parent[i]
	}
	// Union by rank keeps the trees shallow, so grouping stays near-linear
	// even when many records share identifiers.
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		if rank[ra] < rank[rb] {
			ra, rb = rb, ra
		}
		parent[rb] = ra
		if rank[ra] == rank[rb] {
			rank[ra]++
		}
	}

	firstSeen := make(map[string]int)
	for i, v := range vulns {
		for _, id := range identifiersOf(v) {
			if prev, ok := firstSeen[id]; ok {
				union(prev, i)
			} else {
				firstSeen[id] = i
			}
		}
	}

	type bucket struct {
		indices []int
	}
	byRoot := make(map[int]*bucket)
	rootOrder := make([]int, 0)
	for i := range vulns {
		root := find(i)
		b, ok := byRoot[root]
		if !ok {
			b = &bucket{}
			byRoot[root] = b
			rootOrder = append(rootOrder, root)
		}
		b.indices = append(b.indices, i)
	}

	groups := make([]identityGroup, 0, len(rootOrder))
	for _, root := range rootOrder {
		b := byRoot[root]
		group := identityGroup{}
		seen := make(map[string]struct{})
		for _, i := range b.indices {
			group.vulns = append(group.vulns, vulns[i])
			for _, id := range identifiersOf(vulns[i]) {
				if _, ok := seen[id]; ok {
					continue
				}
				seen[id] = struct{}{}
				group.identifiers = append(group.identifiers, id)
			}
		}
		groups = append(groups, group)
	}
	return groups
}

func identifiersOf(v domain.Vulnerability) []string {
	out := make([]string, 0, 1+len(v.Aliases))
	if v.ID != "" {
		out = append(out, v.ID)
	}
	for _, a := range v.Aliases {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

func sortStrings(s []string) {
	sort.Strings(s)
}
