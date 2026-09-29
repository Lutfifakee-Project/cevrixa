package store

import (
	"testing"
	"time"
)

func TestSaveAndGetSyncMetadata(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	m := SyncMetadata{
		Source:        "nvd",
		LastSyncAt:    now,
		LastSyncISO:   "2024-01-01T00:00:00.000",
		RecordsSynced: 42,
	}
	if err := s.SaveSyncMetadata(m); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.GetSyncMetadata("nvd")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Source != "nvd" || got.RecordsSynced != 42 {
		t.Fatalf("got %+v", got)
	}
	if !got.LastSyncAt.Equal(now) {
		t.Fatalf("LastSyncAt = %v, want %v", got.LastSyncAt, now)
	}
}

func TestGetSyncMetadataNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.GetSyncMetadata("missing"); err == nil {
		t.Fatal("expected error for missing metadata")
	}
}

func TestSaveSyncMetadataRejectsEmpty(t *testing.T) {
	s := openTestStore(t)
	if err := s.SaveSyncMetadata(SyncMetadata{}); err == nil {
		t.Fatal("expected error for empty source")
	}
}

func TestSyncMetadataUpsert(t *testing.T) {
	s := openTestStore(t)
	_ = s.SaveSyncMetadata(SyncMetadata{Source: "nvd", RecordsSynced: 10})
	_ = s.SaveSyncMetadata(SyncMetadata{Source: "nvd", RecordsSynced: 20})
	got, _ := s.GetSyncMetadata("nvd")
	if got.RecordsSynced != 20 {
		t.Fatalf("RecordsSynced = %d, want 20", got.RecordsSynced)
	}
}

func TestDeleteSyncMetadata(t *testing.T) {
	s := openTestStore(t)
	_ = s.SaveSyncMetadata(SyncMetadata{Source: "nvd"})
	if err := s.DeleteSyncMetadata("nvd"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.GetSyncMetadata("nvd"); err == nil {
		t.Fatal("expected error after delete")
	}
}
