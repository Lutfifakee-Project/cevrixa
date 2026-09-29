package nvd

import "time"

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
	Published        time.Time        `json:"published"`
	LastModified     time.Time        `json:"lastModified"`
	VulnStatus       string           `json:"vulnStatus"`
	Descriptions     []apiDescription `json:"descriptions"`
	Configurations   []apiConfigNode  `json:"configurations"`
	References       []apiReference   `json:"references"`
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
