package cli

import "testing"

func TestValidateDetectFlags(t *testing.T) {
	tests := []struct {
		name    string
		in      detectFlags
		wantErr bool
	}{
		{"product+version ok", detectFlags{Product: "Apache", Version: "2.4.49"}, false},
		{"cpe ok", detectFlags{CPE: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}, false},
		{"purl ok", detectFlags{PURL: "pkg:pypi/django@4.2.0"}, false},
		{"no identity", detectFlags{}, true},
		{"product without version", detectFlags{Product: "Apache"}, true},
		{"version without product", detectFlags{Version: "2.4.49"}, true},
		{"multiple identities", detectFlags{Product: "Apache", Version: "2.4.49", CPE: "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}, true},
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
		{"cpe", []string{"--cpe", "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"}, detectFlags{CPE: "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"}, false},
		{"purl", []string{"--purl=pkg:pypi/django@4.2.0"}, detectFlags{PURL: "pkg:pypi/django@4.2.0"}, false},
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
