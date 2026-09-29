package domain

import versionpkg "github.com/Lutfifakee-Project/cevrixa/internal/version"

// Version is the canonical Cevrixa version type.
// Version parsing and comparison semantics live in internal/version so the
// domain model can reuse one implementation across detection and sources.
type Version = versionpkg.Version
