package cli

import (
	"fmt"

	"github.com/Lutfifakee-Project/cevrixa/internal/engine"
	"github.com/Lutfifakee-Project/cevrixa/internal/resolver"
)

func runInfo(args []string) error {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Println("Usage: cevrixa info\n\nShow environment and data status.")
			return nil
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

	dbPath, _ := defaultDBPath()
	fmt.Println("Store")
	fmt.Printf("  path: %s\n", dbPath)
	if s, err := openStoreIfDB(dbPath); err == nil && s != nil {
		defer s.Close()
		n, _ := s.CountVulnerabilities()
		k, _ := s.CountKEV()
		fmt.Printf("  vulnerabilities: %d\n", n)
		fmt.Printf("  kev entries: %d\n", k)
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
