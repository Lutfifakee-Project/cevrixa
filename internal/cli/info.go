package cli

import (
	"fmt"

	"github.com/Lutfifakee-Project/cevrixa/internal/engine"
	"github.com/Lutfifakee-Project/cevrixa/internal/resolver"
)

func runInfo(args []string) error {
	dbPath := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "-h" || arg == "--help" {
			fmt.Println("Usage: cevrixa info [--db <path>]\n\nShow environment and data status.")
			return nil
		}
		if arg == "--db" {
			if i+1 >= len(args) {
				return fmt.Errorf("info: --db requires a value")
			}
			dbPath = args[i+1]
			i++
			continue
		}
		return fmt.Errorf("info: unknown argument %q", arg)
	}

	if dbPath == "" {
		p, err := defaultDBPath()
		if err == nil {
			dbPath = p
		}
	}

	fmt.Println("Cevrixa Info")
	fmt.Println()

	fmt.Println("Version")
	fmt.Printf("  cevrixa %s\n", Version)
	fmt.Printf("  commit: %s\n", Commit)
	fmt.Printf("  built:  %s\n", Date)
	fmt.Println()

	fmt.Println("Catalog")
	fmt.Printf("  products: %d\n", resolver.CatalogSize())
	fmt.Println()

	fmt.Println("Fixtures (embedded)")
	fmt.Printf("  vulnerabilities: %d\n", engine.EmbeddedFixtureCount())
	fmt.Println()

	fmt.Println("Store")
	fmt.Printf("  path: %s\n", dbPath)
	if s, err := openStoreIfDB(dbPath); err == nil && s != nil {
		defer s.Close()
		n, _ := s.CountVulnerabilities()
		k, _ := s.CountKEV()
		en, _ := s.CountEnrichments()
		fmt.Printf("  vulnerabilities: %d\n", n)
		fmt.Printf("  kev entries: %d\n", k)
		fmt.Printf("  enrichments: %d\n", en)
		if meta, err := s.GetSyncMetadata("nvd"); err == nil {
			fmt.Printf("  last nvd sync: %s (%d records)\n", meta.LastSyncISO, meta.RecordsSynced)
		}
	} else {
		fmt.Println("  (not present — run 'cevrixa sync kev' to initialize)")
	}
	fmt.Println()

	fmt.Println("Sources")
	fmt.Println("  nvd: configured")
	fmt.Println("  osv: configured")
	fmt.Println("  dbcve: configured")
	fmt.Println("  kev: configured")

	return nil
}
