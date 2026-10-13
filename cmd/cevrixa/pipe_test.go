package main

import (
	"errors"
	"testing"
)

func TestIsBrokenPipeNil(t *testing.T) {
	if isBrokenPipe(nil) {
		t.Fatal("nil is not a broken pipe")
	}
}

func TestIsBrokenPipeOther(t *testing.T) {
	if isBrokenPipe(errors.New("some error")) {
		t.Fatal("a plain error is not a broken pipe")
	}
}
