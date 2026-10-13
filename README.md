![Cevrixa](assets/banner.png)

# Cevrixa - Know why a vulnerability applies

> Evidence-first vulnerability applicability intelligence.

[![CI](https://github.com/Lutfifakee-Project/cevrixa/actions/workflows/ci.yml/badge.svg)](https://github.com/Lutfifakee-Project/cevrixa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Lutfifakee-Project/cevrixa)](https://github.com/Lutfifakee-Project/cevrixa/releases)
[![License](https://img.shields.io/github/license/Lutfifakee-Project/cevrixa)](LICENSE)

Cevrixa determines whether a specific software or package version is
affected by a known vulnerability, and explains why. It is not a generic
CVE scanner: it decides applicability against a concrete version, shows
the evidence, and states what remains unknown.

## Features

- Version-aware applicability: affected, not_affected, or inconclusive, never guessed
- CPE and PURL targets, plus SBOM input (CycloneDX and SPDX)
- Evidence-first results with source provenance
- Candidate relevance: unrelated CVEs are not reported as findings
- Machine-readable output: JSON, JSONL, and SARIF
- Local, reproducible dataset; offline-friendly
- Concise default output, full reasoning with `--verbose`

## Installation

### go install

```bash
go install github.com/Lutfifakee-Project/cevrixa/cmd/cevrixa@v1.0.3
```

Verify the install:

```bash
cevrixa -h
```

### From source

```bash
git clone https://github.com/Lutfifakee-Project/cevrixa.git
cd cevrixa
go build ./cmd/cevrixa
```

## Quick Start

Check a product and version:

```bash
cevrixa detect nginx 1.24.0
```

Check a package (PURL):

```bash
cevrixa detect pkg:pypi/django@4.2.0
```

Check an SBOM (CycloneDX or SPDX):

```bash
cevrixa detect --sbom app.cdx.json
```

Explain one CVE against a target:

```bash
cevrixa explain CVE-2021-41773 --product "Apache HTTP Server" --version 2.4.49
```

If the CVE is not in the local dataset, `explain` tries to fetch that
single record from NVD. A network or API failure is reported differently
from "NVD has no record for this CVE". A fetched record is used for that
run only; it is not saved to your database.

### Output

Machine-readable output:

```bash
cevrixa detect pkg:pypi/django@4.2.0 --output json
```

Write a report to a file (the file holds only the report, never progress
or diagnostics):

```bash
cevrixa scan targets.json --output sarif --output-file results.sarif
```

Add `--verbose` for evidence counts, inconclusive question lists,
and per-source conflicts.

## Understanding Results

Each report carries one overall decision:

- `affected` - at least one finding proved the target is affected
- `inconclusive` - a candidate exists but applicability could not be decided
- `no_data` - no matching candidate in the current dataset; this does
  not prove the target is safe
- `identity_unresolved` - the target could not be resolved to a reliable
  identity, so nothing was evaluated

Within a finding, `not_affected` means applicability was evaluated and
the target does not meet the affected condition. An `inconclusive`
question is never reported as `not_affected`.

## Updating Vulnerability Data

```bash
cevrixa sync
```

updates every source using the default workflow. For a bounded NVD window:

```bash
cevrixa sync nvd --days 7
```

`--days` is capped at 120, the NVD API limit per request. Cevrixa does
not bundle the entire NVD history by default; the local dataset reflects
what you have synced.

## Data Sources

- [NVD](https://nvd.nist.gov/) - CVE records and CPE applicability statements
- [OSV](https://osv.dev/) - package vulnerability ranges
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - known exploited vulnerabilities

Cevrixa preserves source provenance and does not hide conflicting source
information.

## Documentation

Run `cevrixa help` for the command list, or `cevrixa help <command>` for
one command.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Cevrixa is licensed under the [MIT License](LICENSE).
