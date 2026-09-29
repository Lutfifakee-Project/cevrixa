package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const LiveURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

func FetchLive(ctx context.Context) (*Catalog, error) {
	return FetchLiveFrom(ctx, LiveURL)
}

func FetchLiveFrom(ctx context.Context, url string) (*Catalog, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("kev: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kev: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev: HTTP %d", resp.StatusCode)
	}

	const maxBytes = 32 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, fmt.Errorf("kev: read: %w", err)
	}

	var apiResp apiResponse
	if err := json.Unmarshal(raw, &apiResp); err != nil {
		return nil, fmt.Errorf("kev: parse: %w", err)
	}
	return &Catalog{Entries: mapResponse(apiResp)}, nil
}
