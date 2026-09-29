# Cevrixa Phase 2C — Package Intelligence Adapter

Phase 2C adds a provider adapter for package/version vulnerability queries.
The adapter is isolated from the Cevrixa core model and supports package name +
ecosystem, unversioned PURL + version, versioned PURL, commit queries, and page tokens.

## Implemented

- Provider-neutral query fields for package/PURL/version/commit/page token
- Package vulnerability adapter
- Canonical package applicability model
- Alias/reference mapping
- Pagination token propagation
- Request validation
- `httptest` coverage for request/response mapping and HTTP failures

## Intentionally deferred

- CLI integration
- SQLite/local cache
- Real detection decisions
- Package ecosystem version semantics
- Batch queries
- SBOM ingestion
- Additional upstream adapters

## Validation

Run from the repository root:

```bash
gofmt -l .
go test ./...
go test -race ./...
go build ./...
go vet ./...
```

Expected: all commands succeed and `gofmt -l .` prints nothing.
