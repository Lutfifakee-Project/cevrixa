//go:build !windows

package main

import (
	"errors"
	"syscall"
)

// isBrokenPipe reports whether err is a write to a pipe whose reader closed.
// A downstream consumer that stops reading (a command piped into head, or a
// grep that exits early) closes the pipe; that is a clean stop, not a failure.
func isBrokenPipe(err error) bool {
	return errors.Is(err, syscall.EPIPE)
}
