# Cevrixa Phase 1 — Version Intelligence

Phase 1 introduces the first real intelligence layer: parsing, comparing, and
matching software versions against contiguous version ranges.

## Implemented

- Numeric dotted version parsing
- Optional `v` / `V` prefix
- SemVer-compatible prerelease ordering
- Build metadata accepted and ignored for precedence
- Numeric comparison (`2.10` > `2.9`)
- Inclusive/exclusive range boundaries
- Exact ranges
- AND-style range expressions such as `>=2.4.0,<2.4.51`
- Invalid input validation
- Table-driven tests and boundary tests

## Intentionally deferred

- NVD / OSV integration
- CPE parsing
- PURL parsing
- OR (`||`) ranges
- Debian/RPM ecosystem-specific ordering
- Vulnerability applicability evaluation
- CLI detection results

## Validation

Run from the root repository:

```bash
gofmt -l .
go test ./...
go test -race ./...
go build ./...
go vet ./...
```

Expected: all commands succeed and `gofmt -l .` prints nothing.
