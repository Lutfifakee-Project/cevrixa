package domain

type Target struct {
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
	CPE         string `json:"cpe,omitempty"`
	PURL        string `json:"purl,omitempty"`
	ResolvedCPE string `json:"resolved_cpe,omitempty"`
}
