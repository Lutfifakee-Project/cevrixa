# Cevrixa Phase 2D — Enrichment Adapter

Phase 2D adds a provider-neutral enrichment layer and one concrete adapter for supplemental vulnerability intelligence.

## Implemented

- Generic `VulnerabilityEnricher` interface
- Canonical `domain.Enrichment` model
- Weakness/CWE representation
- Attribution/provenance representation
- Enrichment HTTP client
- Response mapping
- HTTP error handling
- Unit tests with `httptest`

## Scope

The enrichment layer is intentionally separate from vulnerability applicability.
It enriches an existing vulnerability identifier with contextual information such as:

- technical summary
- mitigation guidance
- enrichment confidence
- PoC reference, when present
- patch/fix reference, when present
- weakness metadata
- upstream attribution

It does not decide whether a target version is affected.

## Upstream data handling

The adapter consumes the provider's documented JSON API and maps it into Cevrixa's own canonical model. Cevrixa does not copy or embed the provider's implementation.

The upstream enrichment data is CC-BY-4.0 and requires attribution. The mapped model therefore preserves the returned attribution block instead of discarding it.

## Intentionally deferred

- CLI integration
- automatic enrichment during detection
- local persistence
- source correlation
- confidence synthesis across multiple sources
- exploitation/KEV source integration

## Validation

From the repository root:

```bash
gofmt -l .
go test ./...
go test -race ./...
go build ./...
go vet ./...
git diff --check
```
