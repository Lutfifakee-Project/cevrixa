package domain

// DatasetInfo describes the local dataset a Report was computed from.
//
// It exists so that "no findings" can never be silently confused with "no
// data": a caller can always tell which records were searched, and whether
// embedded test fixtures contributed to the answer. When the report came from
// a named snapshot, the snapshot name and its digest identify the exact
// intelligence state, so the result can be reproduced.
type DatasetInfo struct {
	StoreRecords   int      `json:"store_records"`
	FixtureRecords int      `json:"fixture_records"`
	Sources        []string `json:"sources,omitempty"`
	Snapshot       string   `json:"snapshot,omitempty"`
	Digest         string   `json:"digest,omitempty"`
	// EngineVersion is the Cevrixa version that produced this report. With the
	// digest and snapshot it makes the result reproducible: same target, same
	// intelligence state, same engine version, same decision.
	EngineVersion string `json:"engine_version,omitempty"`
}

// Total returns the number of records that were searched.
func (d DatasetInfo) Total() int {
	return d.StoreRecords + d.FixtureRecords
}

// Empty reports whether no records at all were searched.
func (d DatasetInfo) Empty() bool {
	return d.Total() == 0
}

// TestData reports whether embedded fixtures contributed to the dataset.
// Fixture records are Cevrixa's own test data, not vulnerability intelligence,
// so any result influenced by them must be labelled as such.
func (d DatasetInfo) TestData() bool {
	return d.FixtureRecords > 0
}
