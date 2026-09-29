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

// Client implements the source interface for the NVD CVE API.
type Client struct {
	HTTPClient *http.Client
	BaseURL    string
	APIKey     string
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{HTTPClient: httpClient, BaseURL: DefaultBaseURL}
}

func (c *Client) Name() string { return "nvd" }

func (c *Client) List(ctx context.Context, query source.Query) (source.Result, error) {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 20 * time.Second}
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
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
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
