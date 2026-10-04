package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/source"
)

const DefaultBaseURL = "https://api.osv.dev/v1/query"

const (
	maxRetries        = 4
	initialRetryDelay = 2 * time.Second
	maxRetryDelay     = 30 * time.Second
)

type Client struct {
	HTTPClient *http.Client
	BaseURL    string
}

type queryPackage struct {
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

type queryPayload struct {
	Package   *queryPackage `json:"package,omitempty"`
	Version   string        `json:"version,omitempty"`
	Commit    string        `json:"commit,omitempty"`
	PageToken string        `json:"page_token,omitempty"`
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{HTTPClient: httpClient, BaseURL: DefaultBaseURL}
}

func (c *Client) Name() string { return "osv" }

func (c *Client) List(ctx context.Context, query source.Query) (source.Result, error) {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}

	payload := queryPayload{
		Version:   strings.TrimSpace(query.Version),
		Commit:    strings.TrimSpace(query.Commit),
		PageToken: strings.TrimSpace(query.PageToken),
	}
	if query.PURL != "" {
		payload.Package = &queryPackage{PURL: strings.TrimSpace(query.PURL)}
	} else if query.PackageName != "" || query.Ecosystem != "" {
		if query.PackageName == "" || query.Ecosystem == "" {
			return source.Result{}, fmt.Errorf("osv: package name and ecosystem must be provided together")
		}
		payload.Package = &queryPackage{
			Name:      strings.TrimSpace(query.PackageName),
			Ecosystem: strings.TrimSpace(query.Ecosystem),
		}
	} else if query.Commit == "" {
		return source.Result{}, fmt.Errorf("osv: package/PURL or commit is required")
	}

	if payload.Package != nil && payload.Package.PURL != "" && payload.Version != "" && strings.Contains(payload.Package.PURL, "@") {
		return source.Result{}, fmt.Errorf("osv: version must not be supplied with a versioned PURL")
	}
	if payload.Commit != "" && payload.Version != "" {
		return source.Result{}, fmt.Errorf("osv: version and commit are mutually exclusive")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return source.Result{}, fmt.Errorf("osv: encode request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(backoffDelay(attempt)):
			case <-ctx.Done():
				return source.Result{}, ctx.Err()
			}
		}

		res, err := c.doQuery(ctx, base, body)
		if err != nil {
			lastErr = err
			if isRetryable(err) {
				continue
			}
			return source.Result{}, err
		}
		return res, nil
	}
	return source.Result{}, fmt.Errorf("osv: exhausted retries: %w", lastErr)
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

func (c *Client) doQuery(ctx context.Context, base string, body []byte) (source.Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base, strings.NewReader(string(body)))
	if err != nil {
		return source.Result{}, fmt.Errorf("osv: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return source.Result{}, fmt.Errorf("osv: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
		return source.Result{}, &retryableError{status: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return source.Result{}, fmt.Errorf("osv: HTTP %d: %s", resp.StatusCode, string(raw))
	}

	const maxResponseBytes = 32 << 20
	var payloadResp apiResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&payloadResp); err != nil {
		return source.Result{}, fmt.Errorf("osv: decode response: %w", err)
	}

	records := make([]domain.Vulnerability, 0, len(payloadResp.Vulnerabilities))
	for _, vuln := range payloadResp.Vulnerabilities {
		records = append(records, mapVulnerability(vuln))
	}

	return source.Result{
		Vulnerabilities: records,
		NextPageToken:   payloadResp.NextPageToken,
		ResultsPerPage:  len(records),
	}, nil
}

type retryableError struct {
	status int
}

func (e *retryableError) Error() string {
	return fmt.Sprintf("osv: retryable status %d", e.status)
}

func isRetryable(err error) bool {
	_, ok := err.(*retryableError)
	return ok
}
