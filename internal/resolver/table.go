package resolver

type catalogEntry struct {
	Name    string
	Aliases []string
	CPEBase string
}

func (e catalogEntry) matchesAlias(norm string) bool {
	for _, a := range e.Aliases {
		if a == norm {
			return true
		}
	}
	return false
}

var defaultCatalog = []catalogEntry{
	{
		Name:    "Apache HTTP Server",
		Aliases: []string{"apache_http_server", "httpd", "apache2", "apache_httpd"},
		CPEBase: "cpe:2.3:a:apache:http_server",
	},
	{
		Name:    "Nginx",
		Aliases: []string{"nginx", "nginx_server", "nginx_http_server"},
		CPEBase: "cpe:2.3:a:nginx:nginx",
	},
	{
		Name:    "OpenSSL",
		Aliases: []string{"openssl", "openssl_library"},
		CPEBase: "cpe:2.3:a:openssl:openssl",
	},
	{
		Name:    "OpenSSH",
		Aliases: []string{"openssh", "openbsd_openssh"},
		CPEBase: "cpe:2.3:a:openbsd:openssh",
	},
	{
		Name:    "Django",
		Aliases: []string{"django", "django_project", "djangoproject"},
		CPEBase: "cpe:2.3:a:djangoproject:django",
	},
	{
		Name:    "Lodash",
		Aliases: []string{"lodash", "lodash_js"},
		CPEBase: "cpe:2.3:a:lodash:lodash",
	},
	{
		Name:    "Express",
		Aliases: []string{"express", "expressjs", "express_js"},
		CPEBase: "cpe:2.3:a:expressjs:express",
	},
}
