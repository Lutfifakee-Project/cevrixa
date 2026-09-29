package nvd

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNVDTimeNoTimezone(t *testing.T) {
	var v struct {
		T nvdTime `json:"t"`
	}
	if err := json.Unmarshal([]byte(`{"t":"2024-01-15T05:00:00.000"}`), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := time.Date(2024, 1, 15, 5, 0, 0, 0, time.UTC)
	if !v.T.Time.Equal(want) {
		t.Fatalf("got %v, want %v", v.T.Time, want)
	}
}

func TestNVDTimeWithZ(t *testing.T) {
	var v struct {
		T nvdTime `json:"t"`
	}
	if err := json.Unmarshal([]byte(`{"t":"2024-01-15T05:00:00.000Z"}`), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := time.Date(2024, 1, 15, 5, 0, 0, 0, time.UTC)
	if !v.T.Time.Equal(want) {
		t.Fatalf("got %v, want %v", v.T.Time, want)
	}
}

func TestNVDTimeWithOffset(t *testing.T) {
	var v struct {
		T nvdTime `json:"t"`
	}
	if err := json.Unmarshal([]byte(`{"t":"2024-01-15T05:00:00.000-05:00"}`), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	if !v.T.Time.Equal(want) {
		t.Fatalf("got %v, want %v", v.T.Time, want)
	}
}

func TestNVDTimeEmpty(t *testing.T) {
	var v struct {
		T nvdTime `json:"t"`
	}
	if err := json.Unmarshal([]byte(`{"t":""}`), &v); err != nil {
		t.Fatalf("unmarshal empty: %v", err)
	}
	if !v.T.Time.IsZero() {
		t.Fatalf("expected zero time, got %v", v.T.Time)
	}
}

func TestNVDTimeInvalid(t *testing.T) {
	var v struct {
		T nvdTime `json:"t"`
	}
	err := json.Unmarshal([]byte(`{"t":"not a date"}`), &v)
	if err == nil {
		t.Fatal("expected error for invalid date")
	}
}

func TestNVDTimeRoundTrip(t *testing.T) {
	src := time.Date(2024, 1, 15, 5, 0, 0, 0, time.UTC)
	b, err := json.Marshal(struct {
		T nvdTime `json:"t"`
	}{nvdTime{src}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{"t":"2024-01-15T05:00:00.000Z"}` {
		t.Fatalf("marshal = %s", b)
	}
}
