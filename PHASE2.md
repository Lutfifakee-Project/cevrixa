# Cevrixa Phase 2A/2B — Vulnerability Model and Upstream Adapter

This phase introduces a source-agnostic vulnerability model and the first upstream adapter.

## Implemented

- Canonical vulnerability model with source provenance
- Applicability condition model
- CPE match range model using raw version boundaries
- Generic upstream source interface
- NVD CVE API 2.0 client
- NVD response mapper into the Cevrixa canonical model
- Pagination support
- API key support through configuration, without making it mandatory
- HTTP timeout and response-size protection
- Unit tests using local HTTP fixtures

## Intentionally deferred

- SQLite/local database
- Incremental synchronization
- OSV adapter
- DBCVE adapter
- KEV adapter
- Detection engine
- CPE resolution from product names
- Full CPE range evaluation
- Evidence scoring/correlation

## Design rule

Upstream sources are data providers only. Their schemas must not leak into the core Cevrixa detection engine.
