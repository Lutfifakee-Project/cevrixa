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
	// Web servers
	{Name: "Apache HTTP Server", Aliases: []string{"apache_http_server", "httpd", "apache2", "apache_httpd"}, CPEBase: "cpe:2.3:a:apache:http_server"},
	{Name: "Apache Tomcat", Aliases: []string{"apache_tomcat", "tomcat"}, CPEBase: "cpe:2.3:a:apache:tomcat"},
	{Name: "Nginx", Aliases: []string{"nginx", "nginx_server"}, CPEBase: "cpe:2.3:a:nginx:nginx"},
	{Name: "Microsoft IIS", Aliases: []string{"iis", "microsoft_iis", "internet_information_services"}, CPEBase: "cpe:2.3:a:microsoft:internet_information_services"},

	// Crypto / SSH
	{Name: "OpenSSL", Aliases: []string{"openssl", "openssl_library"}, CPEBase: "cpe:2.3:a:openssl:openssl"},
	{Name: "OpenSSH", Aliases: []string{"openssh", "openbsd_openssh"}, CPEBase: "cpe:2.3:a:openbsd:openssh"},

	// Databases
	{Name: "PostgreSQL", Aliases: []string{"postgresql", "postgres"}, CPEBase: "cpe:2.3:a:postgresql:postgresql"},
	{Name: "MySQL", Aliases: []string{"mysql", "oracle_mysql"}, CPEBase: "cpe:2.3:a:oracle:mysql"},
	{Name: "MariaDB", Aliases: []string{"mariadb"}, CPEBase: "cpe:2.3:a:mariadb:mariadb"},
	{Name: "MongoDB", Aliases: []string{"mongodb", "mongo"}, CPEBase: "cpe:2.3:a:mongodb:mongodb"},
	{Name: "Redis", Aliases: []string{"redis"}, CPEBase: "cpe:2.3:a:redis:redis"},

	// Runtimes
	{Name: "Node.js", Aliases: []string{"nodejs", "node_js", "node"}, CPEBase: "cpe:2.3:a:nodejs:node.js"},
	{Name: "Python", Aliases: []string{"python", "python_lang"}, CPEBase: "cpe:2.3:a:python:python"},
	{Name: "PHP", Aliases: []string{"php"}, CPEBase: "cpe:2.3:a:php:php"},
	{Name: "Ruby", Aliases: []string{"ruby", "ruby_lang"}, CPEBase: "cpe:2.3:a:ruby-lang:ruby"},
	{Name: "OpenJDK", Aliases: []string{"openjdk", "jdk"}, CPEBase: "cpe:2.3:a:oracle:openjdk"},

	// CMS
	{Name: "WordPress", Aliases: []string{"wordpress"}, CPEBase: "cpe:2.3:a:wordpress:wordpress"},
	{Name: "Drupal", Aliases: []string{"drupal"}, CPEBase: "cpe:2.3:a:drupal:drupal"},
	{Name: "Joomla", Aliases: []string{"joomla"}, CPEBase: "cpe:2.3:a:joomla:joomla"},

	// Orchestration / infra
	{Name: "Kubernetes", Aliases: []string{"kubernetes", "k8s"}, CPEBase: "cpe:2.3:a:kubernetes:kubernetes"},
	{Name: "Docker", Aliases: []string{"docker", "docker_engine"}, CPEBase: "cpe:2.3:a:docker:docker"},
	{Name: "GitLab", Aliases: []string{"gitlab"}, CPEBase: "cpe:2.3:a:gitlab:gitlab"},
	{Name: "Jenkins", Aliases: []string{"jenkins"}, CPEBase: "cpe:2.3:a:jenkins:jenkins"},

	// Search / observability
	{Name: "Elasticsearch", Aliases: []string{"elasticsearch"}, CPEBase: "cpe:2.3:a:elastic:elasticsearch"},
	{Name: "Logstash", Aliases: []string{"logstash"}, CPEBase: "cpe:2.3:a:elastic:logstash"},
	{Name: "Kibana", Aliases: []string{"kibana"}, CPEBase: "cpe:2.3:a:elastic:kibana"},
	{Name: "Grafana", Aliases: []string{"grafana"}, CPEBase: "cpe:2.3:a:grafana:grafana"},

	// Message brokers
	{Name: "Apache Kafka", Aliases: []string{"apache_kafka", "kafka"}, CPEBase: "cpe:2.3:a:apache:kafka"},
	{Name: "RabbitMQ", Aliases: []string{"rabbitmq"}, CPEBase: "cpe:2.3:a:rabbitmq:rabbitmq"},

	// Libraries / frameworks
	{Name: "Django", Aliases: []string{"django", "djangoproject"}, CPEBase: "cpe:2.3:a:djangoproject:django"},
	{Name: "Express", Aliases: []string{"express", "expressjs"}, CPEBase: "cpe:2.3:a:expressjs:express"},
	{Name: "Lodash", Aliases: []string{"lodash"}, CPEBase: "cpe:2.3:a:lodash:lodash"},
	{Name: "jQuery", Aliases: []string{"jquery"}, CPEBase: "cpe:2.3:a:jquery:jquery"},
	{Name: "Spring Framework", Aliases: []string{"spring", "spring_framework"}, CPEBase: "cpe:2.3:a:vmware:spring_framework"},
	{Name: "Ruby on Rails", Aliases: []string{"rails", "ruby_on_rails"}, CPEBase: "cpe:2.3:a:rubyonrails:rails"},
}
