package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/source"
)

const DefaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

const (
	maxRetries        = 5
	initialRetryDelay = 10 * time.Second
)

type Client struct {
	HTTPClient *http.Client
	BaseURL    string
	APIKey     string

	limiter *rateLimiter
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 120 * time.Second}
	}
	return &Client{HTTPClient: httpClient, BaseURL: DefaultBaseURL}
}

func (c *Client) Name() string { return "nvd" }

func (c *Client) limiterFor() *rateLimiter {
	if c.limiter == nil {
		c.limiter = newRateLimiter(defaultInterval(c.APIKey != ""))
	}
	return c.limiter
}

func (c *Client) List(ctx context.Context, query source.Query) (source.Result, error) {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 120 * time.Second}
	}
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}

	u, err := url.Parse(base)
	if err != nil {
		return source.Result{}, fmt.Errorf("nvd: parse base URL: %w", err)
	}
	q := u.Query()
	if query.ID != "" {
		q.Set("cveId", query.ID)
	}
	if query.StartIndex > 0 {
		q.Set("startIndex", strconv.Itoa(query.StartIndex))
	}
	if query.ResultsLimit > 0 {
		q.Set("resultsPerPage", strconv.Itoa(query.ResultsLimit))
	}
	if query.LastModStart != "" || query.LastModEnd != "" {
		if query.ID != "" {
			return source.Result{}, fmt.Errorf("nvd: date range cannot be combined with cveId")
		}
		if query.LastModStart == "" || query.LastModEnd == "" {
			return source.Result{}, fmt.Errorf("nvd: both lastModStartDate and lastModEndDate are required")
		}
		q.Set("lastModStartDate", query.LastModStart)
		q.Set("lastModEndDate", query.LastModEnd)
	}
	u.RawQuery = q.Encode()

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := initialRetryDelay * time.Duration(attempt)
			fmt.Fprintf(io.Discard, "") // no-op to keep format stable
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return source.Result{}, ctx.Err()
			}
		}

		if err := c.limiterFor().wait(ctx); err != nil {
			return source.Result{}, err
		}

		res, err := c.doRequest(ctx, u.String())
		if err != nil {
			lastErr = err
			if isRetryable(err) {
				continue
			}
			return source.Result{}, err
		}
		return res, nil
	}
	return source.Result{}, fmt.Errorf("nvd: exhausted retries: %w", lastErr)
}

func (c *Client) doRequest(ctx context.Context, urlStr string) (source.Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return source.Result{}, fmt.Errorf("nvd: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return source.Result{}, fmt.Errorf("nvd: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		return source.Result{}, &retryableError{status: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return source.Result{}, fmt.Errorf("nvd: HTTP %d: %s", resp.StatusCode, string(body))
	}

	const maxResponseBytes = 32 << 20
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	var payload apiResponse
	if err := decoder.Decode(&payload); err != nil {
		return source.Result{}, fmt.Errorf("nvd: decode response: %w", err)
	}

	records := make([]domain.Vulnerability, 0, len(payload.Vulnerabilities))
	for _, item := range payload.Vulnerabilities {
		records = append(records, mapVulnerability(item.CVE))
	}

	return source.Result{
		Vulnerabilities: records,
		TotalResults:    payload.TotalResults,
		StartIndex:      payload.StartIndex,
		ResultsPerPage:  payload.ResultsPerPage,
	}, nil
}

type retryableError struct {
	status int
}

func (e *retryableError) Error() string {
	return fmt.Sprintf("nvd: retryable status %d", e.status)
}

func isRetryable(err error) bool {
	_, ok := err.(*retryableError)
	return ok
}
