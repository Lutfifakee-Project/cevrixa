package domain

import "testing"

func TestParseCPEValid(t *testing.T) {
	input := "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
	c, err := ParseCPE(input)
	if err != nil {
		t.Fatalf("ParseCPE: %v", err)
	}
	if c.Part != "a" {
		t.Fatalf("Part = %q, want a", c.Part)
	}
	if c.Vendor != "apache" {
		t.Fatalf("Vendor = %q, want apache", c.Vendor)
	}
	if c.Product != "http_server" {
		t.Fatalf("Product = %q, want http_server", c.Product)
	}
	if c.Version != "2.4.49" {
		t.Fatalf("Version = %q, want 2.4.49", c.Version)
	}
}

func TestParseCPEWildcard(t *testing.T) {
	input := "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
	c, err := ParseCPE(input)
	if err != nil {
		t.Fatalf("ParseCPE: %v", err)
	}
	if !c.IsWildcard("version") {
		t.Fatalf("expected version to be wildcard, got %q", c.Version)
	}
}

func TestParseCPERejectsEmpty(t *testing.T) {
	if _, err := ParseCPE(""); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseCPERejectsNon23(t *testing.T) {
	if _, err := ParseCPE("cpe:/a:apache:http_server:2.4.49"); err == nil {
		t.Fatal("expected error for CPE 2.2 format")
	}
}

func TestParseCPERejectsWrongFieldCount(t *testing.T) {
	if _, err := ParseCPE("cpe:2.3:a:apache:http_server"); err == nil {
		t.Fatal("expected error for short field count")
	}
}

func TestCPERoundTrip(t *testing.T) {
	input := "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
	c, err := ParseCPE(input)
	if err != nil {
		t.Fatalf("ParseCPE: %v", err)
	}
	if got := c.String(); got != input {
		t.Fatalf("round-trip mismatch:\n  got:  %q\n  want: %q", got, input)
	}
}
