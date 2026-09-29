package domain

// Enrichment contains supplemental vulnerability intelligence that can be
// attached to a canonical vulnerability without coupling the core model to
// one upstream provider schema.
type Enrichment struct {
	Source         string       `json:"source"`
	Status         string       `json:"status,omitempty"`
	Summary        string       `json:"summary,omitempty"`
	Mitigation     string       `json:"mitigation,omitempty"`
	Confidence     string       `json:"confidence,omitempty"`
	PoCURL         string       `json:"poc_url,omitempty"`
	PatchCommitURL string       `json:"patch_commit_url,omitempty"`
	Weaknesses     []Weakness   `json:"weaknesses,omitempty"`
	References     []Reference  `json:"references,omitempty"`
	Attribution    *Attribution `json:"attribution,omitempty"`
	Risk           *Risk        `json:"risk,omitempty"`
}

// Risk contains vulnerability risk metadata supplied by an upstream source.
type Risk struct {
	Severity       string  `json:"severity,omitempty"`
	CVSS           float64 `json:"cvss,omitempty"`
	CVSSVersion    string  `json:"cvss_version,omitempty"`
	KEV            bool    `json:"kev,omitempty"`
	EPSS           float64 `json:"epss,omitempty"`
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
}

// Weakness identifies a weakness classification associated with an enrichment.
type Weakness struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Attribution preserves the licensing/provenance notice returned by an
// upstream enrichment service. It is intentionally explicit so downstream
// consumers do not accidentally discard attribution requirements.
type Attribution struct {
	Source  string `json:"source,omitempty"`
	License string `json:"license,omitempty"`
	Terms   string `json:"terms,omitempty"`
	Docs    string `json:"docs,omitempty"`
}
