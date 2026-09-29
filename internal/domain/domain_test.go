package domain

import "testing"

func TestTargetKinds(t *testing.T) {
	tests := []struct {
		name string
		got  TargetKind
		want string
	}{
		{"unknown", TargetKindUnknown, "unknown"},
		{"product", TargetKindProduct, "product"},
		{"cpe", TargetKindCPE, "cpe"},
		{"purl", TargetKindPURL, "purl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.want {
				t.Fatalf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}
