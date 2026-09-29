// Package sync orchestrates multi-page downloads from upstream sources
// into the local SQLite store.
package sync

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Lutfifakee-Project/cevrixa/internal/source"
	"github.com/Lutfifakee-Project/cevrixa/internal/source/nvd"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

type NVDOptions struct {
	Source       *nvd.Client
	Store        *store.Store
	PageLimit    int    // per-page results, default 2000
	MaxPages     int    // safety limit, default 50 (100k records max per run)
	LastModStart string // ISO-8601, empty = start from latest known
	LastModEnd   string // ISO-8601, empty = now
	ProgressFreq int    // print every N records, 0 = silent
}

func (o *NVDOptions) applyDefaults() {
	if o.PageLimit <= 0 {
		o.PageLimit = 2000
	}
	if o.MaxPages <= 0 {
		o.MaxPages = 50
	}
}

// SyncNVD fetches CVE records from NVD and persists them to the store.
// Returns the number of records written.
func SyncNVD(ctx context.Context, opts NVDOptions) (int, error) {
	opts.applyDefaults()

	if opts.Source == nil {
		return 0, fmt.Errorf("sync nvd: source client is required")
	}
	if opts.Store == nil {
		return 0, fmt.Errorf("sync nvd: store is required")
	}

	start, end, err := resolveDateRange(opts)
	if err != nil {
		return 0, err
	}

	total := 0
	startIndex := 0
	pages := 0

	for {
		if pages >= opts.MaxPages {
			return total, fmt.Errorf("sync nvd: reached MaxPages=%d at %d records; increase MaxPages or narrow date range", opts.MaxPages, total)
		}
		pages++

		res, err := opts.Source.List(ctx, source.Query{
			StartIndex:   startIndex,
			ResultsLimit: opts.PageLimit,
			LastModStart: start,
			LastModEnd:   end,
		})
		if err != nil {
			return total, fmt.Errorf("sync nvd: page %d: %w", pages, err)
		}

		for _, v := range res.Vulnerabilities {
			if err := opts.Store.SaveVulnerability(v); err != nil {
				return total, fmt.Errorf("sync nvd: save %s: %w", v.ID, err)
			}
			total++
		}

		if opts.ProgressFreq > 0 && total > 0 && total%opts.ProgressFreq < len(res.Vulnerabilities) {
			fmt.Fprintf(os.Stderr, "sync nvd: %d records\n", total)
		}

		// Stop when all pages consumed.
		if res.StartIndex+res.ResultsPerPage >= res.TotalResults {
			break
		}
		if res.ResultsPerPage == 0 {
			break
		}
		startIndex = res.StartIndex + res.ResultsPerPage
	}

	if err := opts.Store.SaveSyncMetadata(store.SyncMetadata{
		Source:        "nvd",
		LastSyncAt:    time.Now().UTC(),
		LastSyncISO:   end,
		RecordsSynced: total,
	}); err != nil {
		return total, fmt.Errorf("sync nvd: save metadata: %w", err)
	}

	return total, nil
}

func resolveDateRange(opts NVDOptions) (string, string, error) {
	end := opts.LastModEnd
	if end == "" {
		end = time.Now().UTC().Format("2006-01-02T15:04:05.000")
	}

	start := opts.LastModStart
	if start == "" {
		if meta, err := opts.Store.GetSyncMetadata("nvd"); err == nil && meta.LastSyncISO != "" {
			start = meta.LastSyncISO
		} else {
			// First run: default to 7 days back.
			start = time.Now().UTC().AddDate(0, 0, -7).Format("2006-01-02T15:04:05.000")
		}
	}
	return start, end, nil
}
