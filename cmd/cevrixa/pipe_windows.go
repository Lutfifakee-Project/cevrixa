//go:build windows

package main

import (
	"errors"
	"syscall"
)

// Windows does not raise SIGPIPE, so a closed pipe surfaces as a write
// error instead of killing the process. ERROR_BROKEN_PIPE (109) is the
// usual one; ERROR_NO_DATA (232) covers a pipe closed as we write.
const (
	errorBrokenPipe = syscall.Errno(109)
	errorNoData     = syscall.Errno(232)
)

func isBrokenPipe(err error) bool {
	return errors.Is(err, errorBrokenPipe) || errors.Is(err, errorNoData)
}
