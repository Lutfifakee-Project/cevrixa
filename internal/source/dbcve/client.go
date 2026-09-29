package dbcve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

const DefaultBaseURL = "https://dbcve.org/api/v1"

// Client retrieves supplemental vulnerability intelligence from the upstream
// enrichment API and maps it into Cevrixa's provider-neutral domain model.
type Client struct {
	HTTPClient *http.Client
	BaseURL    string
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{HTTPClient: httpClient, BaseURL: DefaultBaseURL}
}

func (c *Client) Name() string { return "dbcve" }

func (c *Client) Enrich(ctx context.Context, vulnerabilityID string) (domain.Enrichment, error) {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}

	id := strings.TrimSpace(vulnerabilityID)
	if id == "" {
		return domain.Enrichment{}, fmt.Errorf("dbcve: vulnerability ID is required")
	}

	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}

	endpoint := base + "/cve/" + url.PathEscape(id) + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return domain.Enrichment{}, fmt.Errorf("dbcve: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return domain.Enrichment{}, fmt.Errorf("dbcve: request: %w", err)
	}
	defer resp.Body.Close()

	const maxResponseBytes = 8 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return domain.Enrichment{}, fmt.Errorf("dbcve: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &errBody) == nil && errBody.Error != "" {
			return domain.Enrichment{}, fmt.Errorf("dbcve: HTTP %d: %s", resp.StatusCode, errBody.Error)
		}
		return domain.Enrichment{}, fmt.Errorf("dbcve: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var payload apiResponse
	if err := json.Unmarshal(raw, &payload); err != nil {
		return domain.Enrichment{}, fmt.Errorf("dbcve: decode response: %w", err)
	}
	if payload.Data.CVEID == "" {
		return domain.Enrichment{}, fmt.Errorf("dbcve: response missing data.cve_id")
	}

	return mapEnrichment(payload), nil
}
