package cli

import (
	"testing"
)

func TestValidateDetectFlags(t *testing.T) {
	tests := []struct {
		name    string
		in      detectFlags
		wantErr bool
	}{
		{"product+version ok", detectFlags{Product: "Apache", Version: "2.4.49"}, false},
		{"cpe ok", detectFlags{CPE: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}, false},
		{"purl ok at validation", detectFlags{PURL: "pkg:pypi/django@4.2.0"}, false},
		{"no identity", detectFlags{}, true},
		{"product without version", detectFlags{Product: "Apache"}, true},
		{"version without product", detectFlags{Version: "2.4.49"}, true},
		{"multiple identities", detectFlags{Product: "Apache", Version: "2.4.49", CPE: "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}, true},
		{"bad output", detectFlags{CPE: "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", Output: "xml"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDetectFlags(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestParseDetectArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    detectFlags
		wantErr bool
	}{
		{"space form", []string{"--product", "Apache", "--version", "2.4.49"}, detectFlags{Product: "Apache", Version: "2.4.49"}, false},
		{"equals form", []string{"--product=Apache", "--version=2.4.49"}, detectFlags{Product: "Apache", Version: "2.4.49"}, false},
		{"with output", []string{"--cpe", "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", "--output", "json"}, detectFlags{CPE: "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", Output: "json"}, false},
		{"with kev", []string{"--cpe", "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", "--with-kev"}, detectFlags{CPE: "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", WithKEV: true}, false},
		{"unknown flag", []string{"--bogus", "x"}, detectFlags{}, true},
		{"missing value", []string{"--product"}, detectFlags{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDetectArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDetectHelpReturnsNoError(t *testing.T) {
	if err := runDetect([]string{"--help"}); err != nil {
		t.Fatalf("detect --help should return nil, got: %v", err)
	}
	if err := runDetect([]string{"-h"}); err != nil {
		t.Fatalf("detect -h should return nil, got: %v", err)
	}
}

func TestParseDetectArgsWithKEV(t *testing.T) {
	got, err := parseDetectArgs([]string{
		"--product", "Apache", "--version", "2.4.49", "--with-kev",
	})
	if err != nil {
		t.Fatalf("parseDetectArgs: %v", err)
	}
	if !got.WithKEV {
		t.Fatal("WithKEV should be true")
	}
	if got.Product != "Apache" || got.Version != "2.4.49" {
		t.Fatalf("got %+v", got)
	}
}

func TestValidateDetectFlagsAcceptsJSONL(t *testing.T) {
	err := validateDetectFlags(detectFlags{
		CPE:    "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
		Output: "jsonl",
	})
	if err != nil {
		t.Fatalf("jsonl should be accepted, got: %v", err)
	}
}

func TestParseDetectArgsFailOn(t *testing.T) {
	got, err := parseDetectArgs([]string{
		"--product", "Apache", "--version", "2.4.49", "--fail-on", "affected",
	})
	if err != nil {
		t.Fatalf("parseDetectArgs: %v", err)
	}
	if got.FailOn != "affected" {
		t.Fatalf("FailOn = %q", got.FailOn)
	}
}

func TestDetectPURLNotRejected(t *testing.T) {
	err := runDetect([]string{"--purl", "pkg:pypi/django@4.2.0"})
	if err != nil {
		t.Fatalf("detect --purl should not error, got: %v", err)
	}
}

func TestParseDetectArgsDBSet(t *testing.T) {
	got, err := parseDetectArgs([]string{
		"--product", "Apache", "--version", "2.4.49", "--db", "",
	})
	if err != nil {
		t.Fatalf("parseDetectArgs: %v", err)
	}
	if !got.DBSet {
		t.Fatal("DBSet should be true when --db given")
	}
	if got.DB != "" {
		t.Fatalf("DB should be empty, got %q", got.DB)
	}
}
