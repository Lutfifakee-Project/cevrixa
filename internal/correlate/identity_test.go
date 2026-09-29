package correlate

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func TestGroupByIdentityNoOverlap(t *testing.T) {
	a := domain.Vulnerability{ID: "CVE-2021-1"}
	b := domain.Vulnerability{ID: "CVE-2021-2"}
	groups := groupByIdentity([]domain.Vulnerability{a, b})
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
}

func TestGroupByIdentityTransitive(t *testing.T) {
	a := domain.Vulnerability{ID: "CVE-2021-1"}
	b := domain.Vulnerability{ID: "GHSA-x", Aliases: []string{"CVE-2021-1"}}
	c := domain.Vulnerability{ID: "PYSEC-y", Aliases: []string{"GHSA-x"}}
	groups := groupByIdentity([]domain.Vulnerability{a, b, c})
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if len(groups[0].identifiers) != 3 {
		t.Fatalf("expected 3 identifiers, got %v", groups[0].identifiers)
	}
}

func TestGroupByIdentityEmptyID(t *testing.T) {
	a := domain.Vulnerability{ID: "CVE-2021-1"}
	b := domain.Vulnerability{}
	groups := groupByIdentity([]domain.Vulnerability{a, b})
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
}

func TestGroupByIdentityPreservesFirstAppearanceOrder(t *testing.T) {
	vulns := []domain.Vulnerability{
		{ID: "X", Source: "s"},
		{ID: "Y", Source: "s"},
		{ID: "Y", Source: "s"},
		{ID: "X", Source: "s"},
	}
	groups := groupByIdentity(vulns)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if len(groups[0].identifiers) != 1 || groups[0].identifiers[0] != "X" {
		t.Fatalf("expected first group to be X, got %v", groups[0].identifiers)
	}
	if len(groups[1].identifiers) != 1 || groups[1].identifiers[0] != "Y" {
		t.Fatalf("expected second group to be Y, got %v", groups[1].identifiers)
	}
}

func TestGroupByIdentityNonContiguousGroupKeepsOrder(t *testing.T) {
	vulns := []domain.Vulnerability{
		{ID: "A", Source: "s"},
		{ID: "B", Source: "s"},
		{ID: "C", Source: "s"},
		{ID: "B", Source: "s"},
		{ID: "A", Source: "s"},
		{ID: "C", Source: "s"},
	}
	groups := groupByIdentity(vulns)
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}
	wantOrder := []string{"A", "B", "C"}
	for i, want := range wantOrder {
		if len(groups[i].identifiers) != 1 || groups[i].identifiers[0] != want {
			t.Fatalf("group %d: got %v, want first identifier %q", i, groups[i].identifiers, want)
		}
	}
}
