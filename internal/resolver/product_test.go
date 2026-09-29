package resolver

import "testing"

func TestNormalizeProduct(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"Apache HTTP Server", "apache_http_server"},
		{"apache2", "apache2"},
		{"  OpenSSL  ", "openssl"},
		{"Django-CMS", "django_cms"},
		{"a.b.c", "a_b_c"},
		{"", ""},
		{"   ", ""},
		{"_foo", "foo"},
		{"foo_", "foo"},
		{"foo  bar", "foo_bar"},
		{"Foo_Bar", "foo_bar"},
		{"nginx/1.24.0", "nginx_1_24_0"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := NormalizeProduct(tt.in)
			if got != tt.want {
				t.Fatalf("NormalizeProduct(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestBuildCPE(t *testing.T) {
	tests := []struct {
		base    string
		version string
		want    string
	}{
		{
			"cpe:2.3:a:apache:http_server",
			"2.4.49",
			"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
		},
		{
			"cpe:2.3:a:apache:http_server",
			"",
			"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
		},
		{
			"invalid",
			"1.0",
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.base+"@"+tt.version, func(t *testing.T) {
			got := BuildCPE(tt.base, tt.version)
			if got != tt.want {
				t.Fatalf("BuildCPE(%q, %q) = %q, want %q", tt.base, tt.version, got, tt.want)
			}
		})
	}
}
