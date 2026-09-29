package resolver

// CatalogSize returns the number of products in the default catalog.
func CatalogSize() int {
	return len(defaultCatalog)
}
