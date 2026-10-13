package cli

import "testing"

func TestParseSyncArgsDaysOverLimit(t *testing.T) {
	if _, err := parseSyncArgs([]string{"--days", "121"}); err == nil {
		t.Fatal("expected error for --days over the NVD limit")
	}
}

func TestParseSyncArgsDaysAtLimit(t *testing.T) {
	got, err := parseSyncArgs([]string{"--days", "120"})
	if err != nil {
		t.Fatalf("parseSyncArgs: %v", err)
	}
	if got.Days != 120 {
		t.Fatalf("Days = %d", got.Days)
	}
}

func TestParseSyncArgsDaysZeroAndNegative(t *testing.T) {
	if _, err := parseSyncArgs([]string{"--days", "0"}); err == nil {
		t.Fatal("expected error for --days 0")
	}
	if _, err := parseSyncArgs([]string{"--days", "-5"}); err == nil {
		t.Fatal("expected error for negative --days")
	}
}
