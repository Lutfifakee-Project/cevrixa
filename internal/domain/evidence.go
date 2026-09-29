package domain

type EvidenceKind string

const (
	EvidenceKindAlias  EvidenceKind = "alias"
	EvidenceKindStatus EvidenceKind = "status"

	EvidenceKindApplicability EvidenceKind = "applicability"
	EvidenceKindPackageRange  EvidenceKind = "package_range"

	EvidenceKindSeverity       EvidenceKind = "severity"
	EvidenceKindCVSS           EvidenceKind = "cvss"
	EvidenceKindCVSSVersion    EvidenceKind = "cvss_version"
	EvidenceKindKEV            EvidenceKind = "kev"
	EvidenceKindEPSS           EvidenceKind = "epss"
	EvidenceKindEPSSPercentile EvidenceKind = "epss_percentile"

	EvidenceKindMitigation EvidenceKind = "mitigation"
	EvidenceKindPoC        EvidenceKind = "poc"
	EvidenceKindPatch      EvidenceKind = "patch"
	EvidenceKindReference  EvidenceKind = "reference"
	EvidenceKindWeakness   EvidenceKind = "weakness"
)

type Evidence struct {
	Kind   EvidenceKind
	Source string
	Value  string

	Reference     *Reference
	Range         *PackageRange
	Applicability *ApplicabilityNode
}
