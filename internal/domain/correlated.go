package domain

type Conflict struct {
	Kind   EvidenceKind
	Values []ConflictValue
}

type ConflictValue struct {
	Source string
	Value  string
}

type CorrelatedVulnerability struct {
	Identifiers []string
	Evidence    []Evidence
	Conflicts   []Conflict
}
