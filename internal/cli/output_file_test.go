package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReportWriterStdout(t *testing.T) {
	w, closeFn, err := reportWriter("")
	if err != nil {
		t.Fatalf("reportWriter: %v", err)
	}
	if w != os.Stdout {
		t.Fatal("empty path should write to stdout")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("closeFn: %v", err)
	}
}

func TestReportWriterFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report.json")
	w, closeFn, err := reportWriter(p)
	if err != nil {
		t.Fatalf("reportWriter: %v", err)
	}
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("closeFn: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("file = %q, want hello", string(got))
	}
}

func TestReportWriterBadPath(t *testing.T) {
	if _, _, err := reportWriter(filepath.Join(t.TempDir(), "no", "such", "dir", "x.json")); err == nil {
		t.Fatal("expected an error for a non-existent directory")
	}
}

func TestParseDetectOutputFile(t *testing.T) {
	f, err := parseDetectArgs([]string{"nginx", "1.24.0", "--output", "json", "--output-file", "out.json"})
	if err != nil {
		t.Fatalf("parseDetectArgs: %v", err)
	}
	if f.Output != "json" {
		t.Fatalf("Output = %q", f.Output)
	}
	if f.OutFile != "out.json" {
		t.Fatalf("OutFile = %q", f.OutFile)
	}
}

func TestParseScanOutputFile(t *testing.T) {
	f, err := parseScanArgs([]string{"--output-file", "out.sarif", "--output", "sarif"})
	if err != nil {
		t.Fatalf("parseScanArgs: %v", err)
	}
	if f.OutFile != "out.sarif" || f.Output != "sarif" {
		t.Fatalf("got OutFile=%q Output=%q", f.OutFile, f.Output)
	}
}

func TestParseExplainOutputFile(t *testing.T) {
	f, err := parseExplainArgs([]string{"CVE-2021-41773", "--product", "nginx", "--version", "1.24.0", "--output-file", "out.json"})
	if err != nil {
		t.Fatalf("parseExplainArgs: %v", err)
	}
	if f.OutFile != "out.json" {
		t.Fatalf("OutFile = %q", f.OutFile)
	}
}
