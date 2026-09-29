package osv

import "time"

type apiResponse struct {
	Vulnerabilities []apiVulnerability `json:"vulns"`
	NextPageToken   string             `json:"next_page_token"`
}

type apiVulnerability struct {
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Modified   time.Time      `json:"modified"`
	Published  time.Time      `json:"published"`
	Aliases    []string       `json:"aliases"`
	References []apiReference `json:"references"`
	Affected   []apiAffected  `json:"affected"`
}

type apiReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type apiAffected struct {
	Package           apiPackage     `json:"package"`
	Ranges            []apiRange     `json:"ranges"`
	Versions          []string       `json:"versions"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific"`
}

type apiPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
}

type apiRange struct {
	Type   string          `json:"type"`
	Repo   string          `json:"repo"`
	Events []apiRangeEvent `json:"events"`
}

type apiRangeEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}
