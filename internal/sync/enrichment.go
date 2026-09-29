package sync

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Lutfifakee-Project/cevrixa/internal/source"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

type EnrichmentSyncOptions struct {
	Enricher     source.VulnerabilityEnricher
	Store        *store.Store
	VulnIDs      []string
	FromStore    bool
	Limit        int
	Interval     time.Duration
	ProgressFreq int
}

// SyncEnrichment fetches enrichment records from a VulnerabilityEnricher
// and persists them to the store.
//
// When FromStore is true and VulnIDs is empty, the list of CVE IDs already
// in the store is used as the enrichment target set.
func SyncEnrichment(ctx context.Context, opts EnrichmentSyncOptions) (written, failed int, err error) {
	if opts.Enricher == nil {
		return 0, 0, fmt.Errorf("sync enrichment: enricher required")
	}
	if opts.Store == nil {
		return 0, 0, fmt.Errorf("sync enrichment: store required")
	}

	ids := append([]string(nil), opts.VulnIDs...)
	if opts.FromStore && len(ids) == 0 {
		stored, listErr := opts.Store.ListCVEIDs()
		if listErr != nil {
			return 0, 0, fmt.Errorf("sync enrichment: list CVE IDs: %w", listErr)
		}
		ids = stored
	}
	if len(ids) == 0 {
		return 0, 0, fmt.Errorf("sync enrichment: no IDs to enrich (use --cve or --from-store)")
	}
	if opts.Limit > 0 && len(ids) > opts.Limit {
		ids = ids[:opts.Limit]
	}

	total := len(ids)
	for i, id := range ids {
		select {
		case <-ctx.Done():
			return written, failed, ctx.Err()
		default:
		}

		if i > 0 && opts.Interval > 0 {
			time.Sleep(opts.Interval)
		}

		e, enrichErr := opts.Enricher.Enrich(ctx, id)
		if enrichErr != nil {
			failed++
			continue
		}
		if e.VulnerabilityID == "" {
			e.VulnerabilityID = id
		}
		if saveErr := opts.Store.SaveEnrichment(e); saveErr != nil {
			return written, failed, fmt.Errorf("sync enrichment: save %s: %w", id, saveErr)
		}
		written++

		if opts.ProgressFreq > 0 && written%opts.ProgressFreq == 0 {
			fmt.Fprintf(os.Stderr, "sync enrichment: %d / %d written (source=%s)\n",
				written, total, opts.Enricher.Name())
		}
	}

	return written, failed, nil
}
