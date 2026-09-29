package cli

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "cevrixa-cli-test-")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", tmp)
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}
