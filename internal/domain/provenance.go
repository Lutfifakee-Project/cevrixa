package domain

// Provenance records where a piece of intelligence came from, so a finding can
// answer "which source record is this" rather than only naming the source.
type Provenance struct {
	Source         string `json:"source"`
	SourceRecordID string `json:"source_record_id,omitempty"`
}
