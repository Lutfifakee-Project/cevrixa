package engine

import (
	"errors"
	"testing"
)

func TestFindByIDNotFoundSentinel(t *testing.T) {
	_, err := FindByID("CVE-9999-99999", Options{})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
