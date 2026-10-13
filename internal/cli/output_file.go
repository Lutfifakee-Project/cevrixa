package cli

import (
	"io"
	"os"
)

// reportWriter returns the destination for a command's report and a close
// function. With an empty path the report goes to stdout, so piping and
// redirection keep working exactly as before. With a path the report is
// written to that file, created or truncated. Progress and diagnostics are
// never written here: they stay on stderr, so a report file contains only the
// report.
func reportWriter(path string) (io.Writer, func() error, error) {
	if path == "" {
		return os.Stdout, func() error { return nil }, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}
