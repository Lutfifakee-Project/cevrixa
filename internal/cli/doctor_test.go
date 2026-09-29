package cli

import "testing"

func TestRunDoctorHelp(t *testing.T) {
	if err := runDoctor([]string{"--help"}); err != nil {
		t.Fatalf("doctor --help: %v", err)
	}
}

func TestRunDoctorNoArgs(t *testing.T) {
	if err := runDoctor(nil); err != nil {
		t.Fatalf("doctor: %v", err)
	}
}
