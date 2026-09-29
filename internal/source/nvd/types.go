package nvd

type apiResponse struct {
	ResultsPerPage  int       `json:"resultsPerPage"`
	StartIndex      int       `json:"startIndex"`
	TotalResults    int       `json:"totalResults"`
	Vulnerabilities []apiVuln `json:"vulnerabilities"`
}

type apiVuln struct {
	CVE apiCVE `json:"cve"`
}

type apiCVE struct {
	ID               string           `json:"id"`
	SourceIdentifier string           `json:"sourceIdentifier"`
	Published        nvdTime          `json:"published"`
	LastModified     nvdTime          `json:"lastModified"`
	VulnStatus       string           `json:"vulnStatus"`
	Descriptions     []apiDescription `json:"descriptions"`
	Configurations   []apiConfigNode  `json:"configurations"`
	References       []apiReference   `json:"references"`
	Metrics          apiMetrics       `json:"metrics"`
}

type apiDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type apiConfigNode struct {
	Operator string          `json:"operator"`
	Negate   bool            `json:"negate"`
	Children []apiConfigNode `json:"children"`
	CPEMatch []apiCPEMatch   `json:"cpeMatch"`
}

type apiCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type apiReference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

type apiMetrics struct {
	CVSSMetricV31 []apiCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []apiCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []apiCVSSMetric `json:"cvssMetricV2"`
}

type apiCVSSMetric struct {
	Source       string      `json:"source"`
	Type         string      `json:"type"`
	CVSSData     apiCVSSData `json:"cvssData"`
	BaseSeverity string      `json:"baseSeverity"`
}

type apiCVSSData struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}
