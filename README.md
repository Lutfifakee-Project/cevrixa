![Cevrixa](assets/banner.png)

# Cevrixa - Know why a vulnerability applies

> Evidence-first vulnerability applicability intelligence.

[![CI](https://github.com/Lutfifakee-Project/cevrixa/actions/workflows/ci.yml/badge.svg)](https://github.com/Lutfifakee-Project/cevrixa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Lutfifakee-Project/cevrixa)](https://github.com/Lutfifakee-Project/cevrixa/releases)
[![License](https://img.shields.io/github/license/Lutfifakee-Project/cevrixa)](LICENSE)

Cevrixa determines whether a specific software or package version is affected by known vulnerabilities.

It focuses on __why a vulnerability applies__, providing evidence and source provenance behind each result.

## Features

- Version-aware vulnerability applicability
- Evidence-first detection
- CPE and PURL support
- Multiple vulnerability intelligence sources
- Source provenance
- Conflict-aware results
- Local and reproducible data
- JSON, JSONL, and SARIF output
- Offline-friendly workflow

## Installation

### Go Install

```bash
go install github.com/Lutfifakee-Project/cevrixa/cmd/cevrixa@latest
```

Then verify:

```bash
cevrixa -h
```

### From Source

```bash
git clone https://github.com/Lutfifakee-Project/cevrixa.git
cd cevrixa
go build ./cmd/cevrixa
```

## Usage

Check a software version:

```bash
cevrixa detect --product "nginx" --version 1.24.0
```

Check a package:

```bash
cevrixa detect --purl "pkg:pypi/django@4.2.0"
```

Check an SBOM:

```bash
cevrixa detect --sbom app.cdx.json
```

Explain a result:

```bash
cevrixa explain CVE-2021-41773 --product "Apache HTTP Server" --version 2.4.49
```

Update vulnerability data:

```bash
cevrixa sync
```

When no local dataset exists, Cevrixa offers to sync it on first run. Use
`--no-sync` for non-interactive and CI environments.

Use machine-readable output:

```bash
cevrixa detect --purl "pkg:pypi/django@4.2.0" --output json
```

Run `cevrixa --help` or `cevrixa detect --help` for the complete command
reference.

> `why` and `why-not` are deprecated but still work; they print a
> warning and point at `explain`. The top-level `sbom` command is
> deprecated too; use `detect --sbom`.

## How It Works

```text
Input
  ↓
Identity Resolution
  ↓
Vulnerability Correlation
  ↓
Version Applicability
  ↓
Evidence Evaluation
  ↓
Result
```

Cevrixa evaluates vulnerability intelligence against the identified software or package version instead of relying on a simple product or CVE match.

A report carries one overall decision:

- `affected` — at least one finding proved the target is affected.
- `inconclusive` — a candidate exists but applicability could not be decided reliably.
- `no_data` — the target was evaluated but the dataset held no matching candidate. This does not prove the target is safe.
- `identity_unresolved` — the target could not be mapped to a reliable identity, so nothing was evaluated.

Within a finding, `not_affected` means applicability was evaluated and the target does not satisfy the affected condition. A question Cevrixa cannot answer is never reported as a clean result.

## Supported Sources

- [NVD](https://nvd.nist.gov/) — CVE records and CPE applicability statements
- [OSV](https://osv.dev/) — package vulnerability ranges
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — known exploited vulnerabilities

Cevrixa preserves source provenance and does not silently hide conflicting source information.

## Contributing

Contributions are welcome.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution guidelines.

## License

Cevrixa is licensed under the [MIT License](LICENSE).
