package cli

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/output"
)

func TestParseExplainArgsMinimal(t *testing.T) {
	got, err := parseExplainArgs([]string{"CVE-2021-41773", "--product", "Apache", "--version", "2.4.49"})
	if err != nil {
		t.Fatalf("parseExplainArgs: %v", err)
	}
	if got.VulnID != "CVE-2021-41773" || got.Product != "Apache" || got.Version != "2.4.49" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseExplainArgsMissingVulnID(t *testing.T) {
	_, err := parseExplainArgs([]string{"--product", "Apache", "--version", "2.4.49"})
	if err == nil {
		t.Fatal("expected error for missing vuln ID")
	}
}

func TestParseExplainArgsMissingIdentity(t *testing.T) {
	_, err := parseExplainArgs([]string{"CVE-2021-41773"})
	if err == nil {
		t.Fatal("expected error for missing identity")
	}
}

func TestParseExplainArgsMultipleIdentities(t *testing.T) {
	_, err := parseExplainArgs([]string{
		"CVE-2021-41773",
		"--product", "Apache", "--version", "2.4.49",
		"--cpe", "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*",
	})
	if err == nil {
		t.Fatal("expected error for multiple identities")
	}
}

func TestParseExplainArgsProductWithoutVersion(t *testing.T) {
	_, err := parseExplainArgs([]string{"CVE-2021-41773", "--product", "Apache"})
	if err == nil {
		t.Fatal("expected error for --product without --version")
	}
}

func TestParseExplainArgsCPE(t *testing.T) {
	got, err := parseExplainArgs([]string{"CVE-2021-41773", "--cpe", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"})
	if err != nil {
		t.Fatalf("parseExplainArgs: %v", err)
	}
	if got.CPE == "" {
		t.Fatal("CPE should be set")
	}
}

func TestParseExplainArgsOutput(t *testing.T) {
	got, err := parseExplainArgs([]string{
		"CVE-2021-41773", "--product", "Apache", "--version", "2.4.49", "--output", "json",
	})
	if err != nil {
		t.Fatalf("parseExplainArgs: %v", err)
	}
	if got.Output != "json" {
		t.Fatalf("Output = %q", got.Output)
	}
}

func TestParseExplainArgsBadOutput(t *testing.T) {
	_, err := parseExplainArgs([]string{
		"CVE-2021-41773", "--product", "Apache", "--version", "2.4.49", "--output", "xml",
	})
	if err == nil {
		t.Fatal("expected error for unsupported output")
	}
}

func TestBuildExplainReportIdentityUnresolved(t *testing.T) {
	flags := explainFlags{VulnID: "CVE-2021-41773", Product: "UnknownThing", Version: "1.0"}
	report, err := buildExplainReport(flags)
	if err != nil {
		t.Fatalf("buildExplainReport: %v", err)
	}
	if !report.IdentityUnresolved {
		t.Fatal("expected IdentityUnresolved for an unresolved product")
	}
	if got := report.Decision(); got != output.ExplainDecisionIdentityUnresolved {
		t.Fatalf("decision = %q, want identity_unresolved", got)
	}
	if report.Decision().Label() != "IDENTITY UNRESOLVED" {
		t.Fatalf("label = %q", report.Decision().Label())
	}
}
