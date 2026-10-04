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

const (
	maxRetries        = 4
	initialRetryDelay = 2 * time.Second
	maxRetryDelay     = 30 * time.Second
)

// disableRetry is set by tests so they do not wait through real backoff delays.
var disableRetry bool

// DisableRetry disables retry backoff globally. Intended for tests only.
func DisableRetry() {
	disableRetry = true
}

func FetchLive(ctx context.Context) (*Catalog, error) {
	return FetchLiveFrom(ctx, LiveURL)
}

func FetchLiveFrom(ctx context.Context, url string) (*Catalog, error) {
	client := &http.Client{Timeout: 60 * time.Second}

	attempts := maxRetries
	if disableRetry {
		attempts = 0
	}

	var lastErr error
	for attempt := 0; attempt <= attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(backoffDelay(attempt)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		catalog, err := fetchOnce(ctx, client, url)
		if err != nil {
			lastErr = err
			if isRetryable(err) {
				continue
			}
			return nil, err
		}
		return catalog, nil
	}
	return nil, fmt.Errorf("kev: exhausted retries: %w", lastErr)
}

func fetchOnce(ctx context.Context, client *http.Client, url string) (*Catalog, error) {
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

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
		return nil, &retryableError{status: resp.StatusCode}
	}
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

// backoffDelay returns the delay before the given retry attempt (1-based),
// growing exponentially and capped at maxRetryDelay.
func backoffDelay(attempt int) time.Duration {
	d := initialRetryDelay
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= maxRetryDelay {
			return maxRetryDelay
		}
	}
	if d > maxRetryDelay {
		d = maxRetryDelay
	}
	return d
}

type retryableError struct {
	status int
}

func (e *retryableError) Error() string {
	return fmt.Sprintf("kev: retryable status %d", e.status)
}

func isRetryable(err error) bool {
	_, ok := err.(*retryableError)
	return ok
}
