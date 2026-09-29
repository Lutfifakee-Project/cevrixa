package sync

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

type fakeEnricher struct {
	failFor map[string]bool
	calls   int
}

func (f *fakeEnricher) Name() string { return "fake" }
func (f *fakeEnricher) Enrich(ctx context.Context, id string) (domain.Enrichment, error) {
	f.calls++
	if f.failFor[id] {
		return domain.Enrichment{}, errors.New("simulated failure")
	}
	return domain.Enrichment{
		Source:          "fake",
		VulnerabilityID: id,
		Mitigation:      "upgrade",
	}, nil
}

func openEnrichStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSyncEnrichmentExplicitIDs(t *testing.T) {
	s := openEnrichStore(t)
	e := &fakeEnricher{}

	written, failed, err := SyncEnrichment(context.Background(), EnrichmentSyncOptions{
		Enricher: e,
		Store:    s,
		VulnIDs:  []string{"CVE-2021-0001", "CVE-2021-0002"},
	})
	if err != nil {
		t.Fatalf("SyncEnrichment: %v", err)
	}
	if written != 2 || failed != 0 {
		t.Fatalf("written=%d failed=%d", written, failed)
	}
	n, _ := s.CountEnrichments()
	if n != 2 {
		t.Fatalf("store count = %d", n)
	}
}

func TestSyncEnrichmentFromStore(t *testing.T) {
	s := openEnrichStore(t)
	_ = s.SaveVulnerability(domain.Vulnerability{ID: "CVE-2021-0001", Source: "nvd"})
	_ = s.SaveVulnerability(domain.Vulnerability{ID: "CVE-2021-0002", Source: "nvd"})
	_ = s.SaveVulnerability(domain.Vulnerability{ID: "GHSA-xxxx", Source: "osv"})

	e := &fakeEnricher{}
	written, failed, err := SyncEnrichment(context.Background(), EnrichmentSyncOptions{
		Enricher:  e,
		Store:     s,
		FromStore: true,
	})
	if err != nil {
		t.Fatalf("SyncEnrichment: %v", err)
	}
	if written != 2 || failed != 0 {
		t.Fatalf("written=%d failed=%d", written, failed)
	}
	// GHSA-* should be skipped — ListCVEIDs filters to CVE-* only.
	if e.calls != 2 {
		t.Fatalf("calls = %d", e.calls)
	}
}

func TestSyncEnrichmentLimit(t *testing.T) {
	s := openEnrichStore(t)
	e := &fakeEnricher{}

	written, _, err := SyncEnrichment(context.Background(), EnrichmentSyncOptions{
		Enricher: e,
		Store:    s,
		VulnIDs:  []string{"CVE-1", "CVE-2", "CVE-3", "CVE-4"},
		Limit:    2,
	})
	if err != nil {
		t.Fatalf("SyncEnrichment: %v", err)
	}
	if written != 2 {
		t.Fatalf("written = %d", written)
	}
}

func TestSyncEnrichmentFailures(t *testing.T) {
	s := openEnrichStore(t)
	e := &fakeEnricher{failFor: map[string]bool{"CVE-2": true}}

	written, failed, err := SyncEnrichment(context.Background(), EnrichmentSyncOptions{
		Enricher: e,
		Store:    s,
		VulnIDs:  []string{"CVE-1", "CVE-2", "CVE-3"},
	})
	if err != nil {
		t.Fatalf("SyncEnrichment: %v", err)
	}
	if written != 2 || failed != 1 {
		t.Fatalf("written=%d failed=%d", written, failed)
	}
}

func TestSyncEnrichmentInterval(t *testing.T) {
	s := openEnrichStore(t)
	e := &fakeEnricher{}
	start := time.Now()
	_, _, err := SyncEnrichment(context.Background(), EnrichmentSyncOptions{
		Enricher: e,
		Store:    s,
		VulnIDs:  []string{"CVE-1", "CVE-2", "CVE-3"},
		Interval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("SyncEnrichment: %v", err)
	}
	// 2 intervals between 3 items → at least 100ms
	if time.Since(start) < 90*time.Millisecond {
		t.Fatalf("expected interval delay, got %v", time.Since(start))
	}
}

func TestSyncEnrichmentRequiresOptions(t *testing.T) {
	if _, _, err := SyncEnrichment(context.Background(), EnrichmentSyncOptions{}); err == nil {
		t.Fatal("expected error for missing enricher")
	}
	s := openEnrichStore(t)
	if _, _, err := SyncEnrichment(context.Background(), EnrichmentSyncOptions{Store: s}); err == nil {
		t.Fatal("expected error for missing enricher")
	}
}

func TestSyncEnrichmentNoIDs(t *testing.T) {
	s := openEnrichStore(t)
	e := &fakeEnricher{}
	_, _, err := SyncEnrichment(context.Background(), EnrichmentSyncOptions{
		Enricher: e,
		Store:    s,
	})
	if err == nil {
		t.Fatal("expected error for empty IDs")
	}
}
