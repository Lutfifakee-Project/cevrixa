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

type NVDBackfillOptions struct {
	Source       *nvd.Client
	Store        *store.Store
	PageLimit    int
	WindowDays   int    // NVD allows max 120
	EarliestISO  string // stop when end < this; default "2002-01-01T00:00:00.000"
	ProgressFreq int
}

func (o *NVDBackfillOptions) applyDefaults() {
	if o.PageLimit <= 0 {
		o.PageLimit = 2000
	}
	if o.WindowDays <= 0 || o.WindowDays > 120 {
		o.WindowDays = 120
	}
	if o.EarliestISO == "" {
		o.EarliestISO = "2002-01-01T00:00:00.000"
	}
}

// BackfillNVD fetches the full NVD history in 120-day windows, oldest
// first. Returns total records written.
func BackfillNVD(ctx context.Context, opts NVDBackfillOptions) (int, error) {
	opts.applyDefaults()

	if opts.Source == nil {
		return 0, fmt.Errorf("sync nvd backfill: source client required")
	}
	if opts.Store == nil {
		return 0, fmt.Errorf("sync nvd backfill: store required")
	}

	const layout = "2006-01-02T15:04:05.000"

	end, err := time.Parse(layout, "2026-12-31T00:00:00.000")
	if err != nil {
		return 0, fmt.Errorf("parse default end: %w", err)
	}
	earliest, err := time.Parse(layout, opts.EarliestISO)
	if err != nil {
		return 0, fmt.Errorf("parse earliest: %w", err)
	}

	total := 0
	windowNum := 0

	for end.After(earliest) {
		start := end.AddDate(0, 0, -opts.WindowDays)
		if start.Before(earliest) {
			start = earliest
		}

		windowNum++
		startISO := start.Format(layout)
		endISO := end.Format(layout)

		if opts.ProgressFreq > 0 {
			fmt.Fprintf(os.Stderr, "sync nvd backfill: window %d [%s .. %s]\n",
				windowNum, startISO, endISO)
		}

		n, err := SyncNVD(ctx, NVDOptions{
			Source:       opts.Source,
			Store:        opts.Store,
			PageLimit:    opts.PageLimit,
			LastModStart: startISO,
			LastModEnd:   endISO,
		})
		if err != nil {
			return total, fmt.Errorf("window %d [%s..%s]: %w", windowNum, startISO, endISO, err)
		}
		total += n

		if opts.ProgressFreq > 0 {
			fmt.Fprintf(os.Stderr, "sync nvd backfill: window %d done, %d records (total %d)\n",
				windowNum, n, total)
		}

		end = start
	}

	return total, nil
}
