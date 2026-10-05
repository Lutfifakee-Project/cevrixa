package store

import (
	"path/filepath"
	"testing"
)

func TestEPSSRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "epss.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	records := []EPSSRecord{
		{CVEID: "CVE-2021-41773", Score: 0.974, Percentile: 0.999, ModelDate: "2024-01-01"},
		{CVEID: "CVE-2021-42013", Score: 0.95, Percentile: 0.98},
	}
	if err := s.SaveEPSS(records); err != nil {
		t.Fatalf("SaveEPSS: %v", err)
	}

	n, err := s.CountEPSS()
	if err != nil {
		t.Fatalf("CountEPSS: %v", err)
	}
	if n != 2 {
		t.Fatalf("count = %d, want 2", n)
	}

	got, ok, err := s.GetEPSS("CVE-2021-41773")
	if err != nil {
		t.Fatalf("GetEPSS: %v", err)
	}
	if !ok || got.Score != 0.974 || got.Percentile != 0.999 {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
}

func TestEPSSUpsert(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "epss2.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.SaveEPSS([]EPSSRecord{{CVEID: "CVE-1", Score: 0.1}}); err != nil {
		t.Fatalf("SaveEPSS: %v", err)
	}
	if err := s.SaveEPSS([]EPSSRecord{{CVEID: "CVE-1", Score: 0.9}}); err != nil {
		t.Fatalf("SaveEPSS second: %v", err)
	}

	got, _, err := s.GetEPSS("CVE-1")
	if err != nil {
		t.Fatalf("GetEPSS: %v", err)
	}
	if got.Score != 0.9 {
		t.Fatalf("score = %v, want 0.9", got.Score)
	}
	n, _ := s.CountEPSS()
	if n != 1 {
		t.Fatalf("count = %d, want 1 (upsert)", n)
	}
}

func TestEPSSMissing(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "epss3.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	_, ok, err := s.GetEPSS("CVE-0000-0000")
	if err != nil {
		t.Fatalf("GetEPSS: %v", err)
	}
	if ok {
		t.Fatal("expected not found")
	}
}
