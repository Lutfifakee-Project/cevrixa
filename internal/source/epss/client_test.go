package epss

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func TestParsePlainCSV(t *testing.T) {
	body := "#model_version:v2024.01.01,score_date:2024-01-01T00:00:00Z\n" +
		"cve,epss,percentile\n" +
		"CVE-2021-41773,0.974,0.999\n" +
		"CVE-2021-42013,0.95,0.98\n"

	got, err := Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 scores, got %d", len(got))
	}
	if got[0].CVEID != "CVE-2021-41773" || got[0].Score != 0.974 {
		t.Fatalf("score[0] = %+v", got[0])
	}
	if got[0].Percentile != 0.999 {
		t.Fatalf("percentile = %v", got[0].Percentile)
	}
}

func TestParseGzipCSV(t *testing.T) {
	body := "cve,epss,percentile\nCVE-2021-41773,0.974,0.999\n"
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(body)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	got, err := Parse(&buf)
	if err != nil {
		t.Fatalf("Parse gzip: %v", err)
	}
	if len(got) != 1 || got[0].CVEID != "CVE-2021-41773" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseSkipsHeaderAndJunk(t *testing.T) {
	body := "cve,epss,percentile\n" +
		"not-a-cve,0.5,0.5\n" +
		"CVE-2021-41773,bad,0.9\n" +
		"CVE-2021-42013,0.95,0.98\n"

	got, err := Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 valid score, got %d", len(got))
	}
	if got[0].CVEID != "CVE-2021-42013" {
		t.Fatalf("got %+v", got)
	}
}
