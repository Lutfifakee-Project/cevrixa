package resolver

import (
	"fmt"
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

type Result struct {
	CPE    string
	Source string
}

type ErrAmbiguous struct {
	Product    string
	Candidates []string
	Names      []string
}

func (e *ErrAmbiguous) Error() string {
	return fmt.Sprintf(
		"resolver: product %q is ambiguous; candidates: %s",
		e.Product, strings.Join(e.Names, ", "),
	)
}

type Resolver struct {
	catalog []catalogEntry
}

func New() *Resolver {
	return &Resolver{catalog: defaultCatalog}
}

func (r *Resolver) Resolve(t domain.Target) (Result, error) {
	if t.CPE != "" {
		return Result{CPE: t.CPE, Source: "explicit"}, nil
	}
	if strings.TrimSpace(t.Product) == "" {
		return Result{}, nil
	}
	return r.ResolveProduct(t.Product, t.Version)
}

func (r *Resolver) ResolveProduct(product, version string) (Result, error) {
	norm := NormalizeProduct(product)
	if norm == "" {
		return Result{}, nil
	}

	var matches []catalogEntry
	for _, e := range r.catalog {
		if e.matchesAlias(norm) {
			matches = append(matches, e)
		}
	}

	switch len(matches) {
	case 0:
		return Result{}, nil
	case 1:
		cpe := BuildCPE(matches[0].CPEBase, version)
		return Result{CPE: cpe, Source: "catalog"}, nil
	default:
		names := make([]string, len(matches))
		cpes := make([]string, len(matches))
		for i, m := range matches {
			names[i] = m.Name
			cpes[i] = m.CPEBase
		}
		return Result{}, &ErrAmbiguous{
			Product:    product,
			Candidates: cpes,
			Names:      names,
		}
	}
}
