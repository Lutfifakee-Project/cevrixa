# Cevrixa
Know WHY a vulnerability applies.
**Evidence-first vulnerability applicability engine.**

Cevrixa is an open-source security CLI focused on determining whether a specific software or package version is affected by known vulnerabilities, with an emphasis on explainable applicability and evidence.

## Status

**Phase 0 — Project Foundation**

The current milestone contains the Go CLI foundation, domain models, tests, and CI infrastructure. Vulnerability sources, version-range matching, and the detection engine are intentionally not implemented yet.

## Planned Direction

Cevrixa is designed around:

- Evidence-first vulnerability detection
- Version-centric applicability matching
- Explainable decisions
- Conflict-aware source correlation
- Local-first intelligence
- Reproducible results
- Composable CLI workflows

## Development

Requirements:

- Go 1.27+

Commands:

```bash
make build
make test
make vet
make check
```

## Current CLI

```bash
cevrixa version
cevrixa help
cevrixa detect --help
```

`detect` currently validates input and deliberately returns a not-implemented error. It does not fabricate vulnerability results.

## License

MIT
