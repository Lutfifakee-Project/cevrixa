package dbcve

type apiResponse struct {
	Data        apiData         `json:"data"`
	Attribution *apiAttribution `json:"attribution,omitempty"`
	Error       string          `json:"error,omitempty"`
}

type apiData struct {
	CVEID          string         `json:"cve_id"`
	Severity       string         `json:"severity"`
	CVSS           float64        `json:"cvss"`
	CVSSVersion    string         `json:"cvss_version"`
	KEV            bool           `json:"kev"`
	EPSS           float64        `json:"epss"`
	EPSSPercentile float64        `json:"epss_percentile"`
	Published      string         `json:"published"`
	Vendor         string         `json:"vendor"`
	Product        string         `json:"product"`
	Description    string         `json:"description"`
	URL            string         `json:"url"`
	Enrichment     apiEnrichment  `json:"enrichment"`
	CWEs           []apiCWE       `json:"cwes"`
	References     []apiReference `json:"references"`
}

type apiEnrichment struct {
	Status         string `json:"status"`
	Summary        string `json:"summary"`
	Mitigation     string `json:"mitigation"`
	Confidence     string `json:"confidence"`
	PoCURL         string `json:"poc_url"`
	PatchCommitURL string `json:"patch_commit_url"`
}

type apiCWE struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type apiReference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

type apiAttribution struct {
	Source  string `json:"source"`
	License string `json:"license"`
	Terms   string `json:"terms"`
	Docs    string `json:"docs"`
}
