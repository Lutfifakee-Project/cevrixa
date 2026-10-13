//go:build !windows

package main

import (
	"os"
	"testing"
)

// TestIsBrokenPipeRealPipe closes the read end of a pipe, then writes, and
// checks the resulting error is recognised as a broken pipe.
func TestIsBrokenPipeRealPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	r.Close()
	_, werr := w.WriteString("x")
	w.Close()
	if werr == nil {
		t.Skip("write did not fail on this platform")
	}
	if !isBrokenPipe(werr) {
		t.Fatalf("expected a broken pipe, got %v", werr)
	}
}
