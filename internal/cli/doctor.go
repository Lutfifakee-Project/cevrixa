package cli

import (
	"fmt"
	"runtime"

	"github.com/Lutfifakee-Project/cevrixa/internal/engine"
	"github.com/Lutfifakee-Project/cevrixa/internal/resolver"
)

func runDoctor(args []string) error {
	dbPath := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "-h" || arg == "--help" {
			fmt.Println("Usage: cevrixa doctor [--db <path>]")
			fmt.Println()
			fmt.Println("Run environment and data health checks.")
			return nil
		}
		if arg == "--db" {
			if i+1 >= len(args) {
				return fmt.Errorf("doctor: --db requires a value")
			}
			dbPath = args[i+1]
			i++
			continue
		}
		return fmt.Errorf("doctor: unknown argument %q", arg)
	}

	fmt.Println("Cevrixa Doctor")
	fmt.Println()

	pass := func(msg string) { fmt.Printf("[PASS] %s\n", msg) }
	warn := func(msg string) { fmt.Printf("[WARN] %s\n", msg) }
	fail := func(msg string) { fmt.Printf("[FAIL] %s\n", msg) }

	pass(fmt.Sprintf("Go runtime: %s", runtime.Version()))

	n := engine.EmbeddedFixtureCount()
	if n > 0 {
		pass(fmt.Sprintf("Embedded fixtures: %d records", n))
	} else {
		fail("Embedded fixtures: none loaded")
	}

	cat := resolver.CatalogSize()
	if cat >= 30 {
		pass(fmt.Sprintf("Product catalog: %d products", cat))
	} else if cat > 0 {
		warn(fmt.Sprintf("Product catalog: %d products (expected >= 30)", cat))
	} else {
		fail("Product catalog: empty")
	}

	if dbPath == "" {
		p, err := defaultDBPath()
		if err != nil {
			warn(fmt.Sprintf("Default store path: %v", err))
		} else {
			dbPath = p
		}
	}
	if dbPath != "" {
		if s, err := openStoreIfDB(dbPath); err == nil && s != nil {
			defer s.Close()
			v, _ := s.CountVulnerabilities()
			k, _ := s.CountKEV()
			pass(fmt.Sprintf("Store: %s", dbPath))
			fmt.Printf("       vulnerabilities=%d kev=%d\n", v, k)
			if v == 0 {
				warn("Store is empty — run 'cevrixa sync nvd --days 30'")
			} else if cov, err := s.ApplicabilityCoverage(); err == nil {
				switch {
				case cov.Unmatchable == 0:
					pass(fmt.Sprintf("Store applicability: all %d records carry matchable criteria", cov.Total))
				default:
					warn(fmt.Sprintf(
						"Store applicability: %d of %d records carry no matchable criteria (%d with CPE, %d package-only)",
						cov.Unmatchable, cov.Total, cov.WithCPE, cov.WithPackage,
					))
					fmt.Println("       Those records cannot match any target. Re-sync to repair:")
					fmt.Println("       cevrixa sync nvd --days 120   (or --full)")
				}
			}
		} else {
			warn(fmt.Sprintf("Store not present at %s — run 'cevrixa sync kev'", dbPath))
		}
	}

	if _, err := loadConfigIfPresent(); err != nil {
		warn(fmt.Sprintf("Config: %v", err))
	} else {
		pass("Config: OK (or defaults if missing)")
	}

	return nil
}
