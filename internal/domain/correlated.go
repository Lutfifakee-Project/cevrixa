package domain

type Conflict struct {
	Kind   EvidenceKind    `json:"kind"`
	Values []ConflictValue `json:"values"`
}

type ConflictValue struct {
	Source string `json:"source"`
	Value  string `json:"value"`
}

type CorrelatedVulnerability struct {
	Identifiers []string   `json:"identifiers"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	Conflicts   []Conflict `json:"conflicts,omitempty"`
}
