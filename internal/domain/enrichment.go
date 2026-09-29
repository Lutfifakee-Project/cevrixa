package domain

type Enrichment struct {
	Source          string       `json:"source"`
	VulnerabilityID string       `json:"vulnerability_id,omitempty"`
	Status          string       `json:"status,omitempty"`
	Summary         string       `json:"summary,omitempty"`
	Mitigation      string       `json:"mitigation,omitempty"`
	Confidence      string       `json:"confidence,omitempty"`
	PoCURL          string       `json:"poc_url,omitempty"`
	PatchCommitURL  string       `json:"patch_commit_url,omitempty"`
	Weaknesses      []Weakness   `json:"weaknesses,omitempty"`
	References      []Reference  `json:"references,omitempty"`
	Attribution     *Attribution `json:"attribution,omitempty"`
	Risk            *Risk        `json:"risk,omitempty"`
}

type Risk struct {
	Severity       string  `json:"severity,omitempty"`
	CVSS           float64 `json:"cvss,omitempty"`
	CVSSVersion    string  `json:"cvss_version,omitempty"`
	KEV            bool    `json:"kev,omitempty"`
	EPSS           float64 `json:"epss,omitempty"`
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
}

type Weakness struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type Attribution struct {
	Source  string `json:"source,omitempty"`
	License string `json:"license,omitempty"`
	Terms   string `json:"terms,omitempty"`
	Docs    string `json:"docs,omitempty"`
}
