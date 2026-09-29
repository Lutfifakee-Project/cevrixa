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
