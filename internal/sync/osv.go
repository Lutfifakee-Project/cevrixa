package sync

import (
	"context"
	"fmt"

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
}

func SyncOSV(ctx context.Context, opts OSVOptions) (int, error) {
	if opts.Source == nil {
		return 0, fmt.Errorf("sync osv: source client required")
	}
	if opts.Store == nil {
		return 0, fmt.Errorf("sync osv: store required")
	}
	if opts.PURL == "" && opts.PackageName == "" {
		return 0, fmt.Errorf("sync osv: --purl or --package required")
	}

	res, err := opts.Source.List(ctx, source.Query{
		PURL:        opts.PURL,
		PackageName: opts.PackageName,
		Ecosystem:   opts.Ecosystem,
		Version:     opts.Version,
	})
	if err != nil {
		return 0, fmt.Errorf("sync osv: query: %w", err)
	}

	total := 0
	for _, v := range res.Vulnerabilities {
		if err := opts.Store.SaveVulnerability(v); err != nil {
			return total, fmt.Errorf("sync osv: save %s: %w", v.ID, err)
		}
		total++
	}
	return total, nil
}
