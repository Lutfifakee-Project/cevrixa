package engine

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func TestTraceOffByDefault(t *testing.T) {
	report, err := Detect(domain.Target{CPE: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Trace.Steps) != 0 {
		t.Fatalf("trace must be empty unless requested, got %d steps", len(report.Trace.Steps))
	}
}

func TestTraceOnRequest(t *testing.T) {
	report, err := Detect(
		domain.Target{CPE: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
		Options{Trace: true},
	)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Trace.Steps) == 0 {
		t.Fatal("trace must be populated when requested")
	}

	names := make(map[string]bool)
	for _, s := range report.Trace.Steps {
		if s.Status == "" {
			t.Fatalf("trace step %q has no status", s.Name)
		}
		names[s.Name] = true
	}
	for _, want := range []string{"resolve identity", "candidate discovery", "evaluate applicability", "decide"} {
		if !names[want] {
			t.Fatalf("trace missing step %q: %+v", want, report.Trace.Steps)
		}
	}
}

func TestTraceUnresolvedIdentityIsSkipped(t *testing.T) {
	report, err := Detect(
		domain.Target{Product: "Nonexistent Software", Version: "1.0"},
		Options{Trace: true},
	)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	var sawSkipped bool
	for _, s := range report.Trace.Steps {
		if s.Name == "evaluate applicability" && s.Status == domain.TraceSkipped {
			sawSkipped = true
		}
	}
	if !sawSkipped {
		t.Fatalf("an unresolved identity must record a skipped applicability step: %+v", report.Trace.Steps)
	}
}

func TestTracePURL(t *testing.T) {
	report, err := Detect(
		domain.Target{PURL: "pkg:pypi/django@4.2.0"},
		Options{Trace: true},
	)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Trace.Steps) == 0 {
		t.Fatal("package detection must produce a trace")
	}
}
