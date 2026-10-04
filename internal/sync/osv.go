package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/Lutfifakee-Project/cevrixa/internal/source"
	"github.com/Lutfifakee-Project/cevrixa/internal/source/osv"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

type OSVOptions struct {
	Source      *osv.Client
	Store       *store.Store
	PURL        string
	PackageName string
	Ecosystem   string
	Version     string
	// MaxPages is a safety limit on pagination, default 100.
	MaxPages int
}

func (o *OSVOptions) applyDefaults() {
	if o.MaxPages <= 0 {
		o.MaxPages = 100
	}
}

// SyncOSV queries OSV and persists the results, following the pagination token
// until the source stops returning one. Without this the first page of a
// package with many advisories would be stored and the rest lost silently.
func SyncOSV(ctx context.Context, opts OSVOptions) (int, error) {
	opts.applyDefaults()

	if opts.Source == nil {
		return 0, fmt.Errorf("sync osv: source client required")
	}
	if opts.Store == nil {
		return 0, fmt.Errorf("sync osv: store required")
	}
	if opts.PURL == "" && opts.PackageName == "" {
		return 0, fmt.Errorf("sync osv: --purl or --package required")
	}

	total := 0
	pageToken := ""
	pages := 0

	for {
		if pages >= opts.MaxPages {
			return total, fmt.Errorf("sync osv: reached MaxPages=%d at %d records", opts.MaxPages, total)
		}
		pages++

		res, err := opts.Source.List(ctx, source.Query{
			PURL:        opts.PURL,
			PackageName: opts.PackageName,
			Ecosystem:   opts.Ecosystem,
			Version:     opts.Version,
			PageToken:   pageToken,
		})
		if err != nil {
			return total, fmt.Errorf("sync osv: query page %d: %w", pages, err)
		}

		for _, v := range res.Vulnerabilities {
			if err := opts.Store.SaveVulnerability(v); err != nil {
				return total, fmt.Errorf("sync osv: save %s: %w", v.ID, err)
			}
			total++
		}

		if res.NextPageToken == "" {
			break
		}
		pageToken = res.NextPageToken
	}

	if err := opts.Store.SaveSyncMetadata(store.SyncMetadata{
		Source:        "osv",
		LastSyncAt:    time.Now().UTC(),
		RecordsSynced: total,
	}); err != nil {
		return total, fmt.Errorf("sync osv: save metadata: %w", err)
	}

	return total, nil
}
