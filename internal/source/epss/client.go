// Package epss fetches and parses the FIRST.org EPSS feed: per-CVE
// probability scores used for prioritization. EPSS never affects
// applicability; it only ranks findings the engine already decided.
package epss

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultURL is the daily EPSS CSV feed (gzip).
const DefaultURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

const (
	maxRetries        = 4
	initialRetryDelay = 2 * time.Second
	maxRetryDelay     = 30 * time.Second
	maxBytes          = 64 << 20
)

// Score is one CVE's EPSS values.
type Score struct {
	CVEID      string
	Score      float64
	Percentile float64
}

// disableRetry is set by tests so they do not wait through real backoff delays.
var disableRetry bool

// DisableRetry disables retry backoff globally. Intended for tests only.
func DisableRetry() { disableRetry = true }

// Client fetches the EPSS feed.
type Client struct {
	HTTPClient *http.Client
	URL        string
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 120 * time.Second}
	}
	return &Client{HTTPClient: httpClient, URL: DefaultURL}
}

// Fetch downloads and parses the EPSS feed. A network failure is retried on a
// retryable status; a parse failure is returned as-is.
func (c *Client) Fetch(ctx context.Context) ([]Score, error) {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 120 * time.Second}
	}
	url := c.URL
	if url == "" {
		url = DefaultURL
	}

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

		scores, err := c.fetchOnce(ctx, url)
		if err != nil {
			lastErr = err
			if isRetryable(err) {
				continue
			}
			return nil, err
		}
		return scores, nil
	}
	return nil, fmt.Errorf("epss: exhausted retries: %w", lastErr)
}

func (c *Client) fetchOnce(ctx context.Context, url string) ([]Score, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("epss: create request: %w", err)
	}
	req.Header.Set("Accept", "text/csv")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("epss: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
		return nil, &retryableError{status: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("epss: HTTP %d", resp.StatusCode)
	}

	return Parse(io.LimitReader(resp.Body, maxBytes))
}

// Parse reads the EPSS CSV. The feed opens with a comment line carrying the
// model version, then a header row, then cve,epss,percentile rows. It accepts
// the body as-is or gzip-compressed.
func Parse(r io.Reader) ([]Score, error) {
	br := bufio.NewReader(r)

	// Peek the first two bytes for the gzip magic number; the feed is normally
	// gzip-compressed, but a test or a mirror may serve it uncompressed.
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, gerr := gzip.NewReader(br)
		if gerr != nil {
			return nil, fmt.Errorf("epss: gunzip: %w", gerr)
		}
		defer gz.Close()
		br = bufio.NewReader(gz)
	}

	var out []Score
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				s, ok := parseLine(trimmed)
				if ok {
					out = append(out, s)
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("epss: read: %w", err)
		}
	}
	return out, nil
}

// parseLine parses one "cve,score,percentile" row, skipping the header.
func parseLine(line string) (Score, bool) {
	parts := strings.Split(line, ",")
	if len(parts) < 3 {
		return Score{}, false
	}
	cve := strings.TrimSpace(parts[0])
	if !strings.HasPrefix(cve, "CVE-") {
		return Score{}, false
	}
	score, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	if err != nil {
		return Score{}, false
	}
	pct, err := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
	if err != nil {
		return Score{}, false
	}
	return Score{CVEID: cve, Score: score, Percentile: pct}, true
}

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

type retryableError struct{ status int }

func (e *retryableError) Error() string { return fmt.Sprintf("epss: retryable status %d", e.status) }

func isRetryable(err error) bool {
	_, ok := err.(*retryableError)
	return ok
}
