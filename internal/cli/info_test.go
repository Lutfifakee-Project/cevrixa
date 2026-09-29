package cli

import "testing"

func TestRunInfoHelp(t *testing.T) {
	if err := runInfo([]string{"--help"}); err != nil {
		t.Fatalf("info --help: %v", err)
	}
}

func TestRunInfoNoArgs(t *testing.T) {
	if err := runInfo(nil); err != nil {
		t.Fatalf("info: %v", err)
	}
}
