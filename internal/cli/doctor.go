package cli

import (
	"fmt"
	"runtime"

	"github.com/Lutfifakee-Project/cevrixa/internal/engine"
	"github.com/Lutfifakee-Project/cevrixa/internal/resolver"
)

func runDoctor(args []string) error {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Println("Usage: cevrixa doctor\n\nRun environment and data health checks.")
			return nil
		}
	}

	fmt.Println("Cevrixa Doctor")
	fmt.Println()

	pass := func(msg string) { fmt.Printf("[PASS] %s\n", msg) }
	warn := func(msg string) { fmt.Printf("[WARN] %s\n", msg) }
	fail := func(msg string) { fmt.Printf("[FAIL] %s\n", msg) }

	// 1. Go version
	pass(fmt.Sprintf("Go runtime: %s", runtime.Version()))

	// 2. Embedded fixtures
	n := engine.EmbeddedFixtureCount()
	if n > 0 {
		pass(fmt.Sprintf("Embedded fixtures: %d records", n))
	} else {
		fail("Embedded fixtures: none loaded")
	}

	// 3. Catalog
	cat := resolver.CatalogSize()
	if cat >= 30 {
		pass(fmt.Sprintf("Product catalog: %d products", cat))
	} else if cat > 0 {
		warn(fmt.Sprintf("Product catalog: %d products (expected >= 30)", cat))
	} else {
		fail("Product catalog: empty")
	}

	// 4. Store
	dbPath, err := defaultDBPath()
	if err != nil {
		warn(fmt.Sprintf("Default store path: %v", err))
	} else {
		if s, err := openStoreIfDB(dbPath); err == nil && s != nil {
			defer s.Close()
			v, _ := s.CountVulnerabilities()
			k, _ := s.CountKEV()
			pass(fmt.Sprintf("Store: %s", dbPath))
			fmt.Printf("       vulnerabilities=%d kev=%d\n", v, k)
			if v == 0 {
				warn("Store is empty — run 'cevrixa sync nvd --days 30'")
			}
		} else {
			warn(fmt.Sprintf("Store not present at %s — run 'cevrixa sync kev'", dbPath))
		}
	}

	// 5. Config
	if _, err := loadConfigIfPresent(); err != nil {
		warn(fmt.Sprintf("Config: %v", err))
	} else {
		pass("Config: OK (or defaults if missing)")
	}

	return nil
}
