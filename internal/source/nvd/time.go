package nvd

import (
	"fmt"
	"strings"
	"time"
)

// nvdTime accepts NVD's timestamp formats, which may or may not include a
// timezone offset. Examples observed from the live API:
//
//	2024-01-01T00:00:00.000
//	2024-01-01T00:00:00.000Z
//	2024-01-01T00:00:00.000-05:00
//
// Missing timezone is treated as UTC.
type nvdTime struct {
	time.Time
}

const (
	nvdLayoutNoTZ = "2006-01-02T15:04:05.000"
	nvdLayoutRFC  = time.RFC3339
)

func (t *nvdTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		t.Time = time.Time{}
		return nil
	}

	// Try no-timezone layout first (most common from NVD).
	if parsed, err := time.Parse(nvdLayoutNoTZ, s); err == nil {
		t.Time = parsed.UTC()
		return nil
	}

	// Try RFC3339 (with timezone).
	if parsed, err := time.Parse(nvdLayoutRFC, s); err == nil {
		t.Time = parsed.UTC()
		return nil
	}

	// Try without milliseconds.
	if parsed, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
		t.Time = parsed.UTC()
		return nil
	}

	return fmt.Errorf("nvd: cannot parse timestamp %q", s)
}

func (t nvdTime) MarshalJSON() ([]byte, error) {
	if t.Time.IsZero() {
		return []byte(`""`), nil
	}
	return []byte(`"` + t.Time.UTC().Format(nvdLayoutNoTZ) + `Z"`), nil
}
