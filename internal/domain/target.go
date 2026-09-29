package domain

// TargetKind describes how a target is identified.
type TargetKind string

const (
	TargetKindUnknown TargetKind = "unknown"
	TargetKindProduct TargetKind = "product"
	TargetKindCPE     TargetKind = "cpe"
	TargetKindPURL    TargetKind = "purl"
)

// Target is an input identity for a vulnerability detection request.
type Target struct {
	Kind    TargetKind `json:"kind"`
	Product string     `json:"product,omitempty"`
	Version string     `json:"version,omitempty"`
	CPE     string     `json:"cpe,omitempty"`
	PURL    string     `json:"purl,omitempty"`
}
