# Cevrixa

> Vulnerability intelligence and detection engine for software packages, CPEs, PURLs, and vulnerability data.

[![Status](https://img.shields.io/badge/status-development-orange.svg)](CHANGELOG.md)
[![CI](https://github.com/Lutfifakee-Project/cevrixa/actions/workflows/ci.yml/badge.svg)](https://github.com/Lutfifakee-Project/cevrixa/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

Cevrixa is a vulnerability intelligence and detection engine. Given a software
product, package, or system component, it determines whether that specific
version is affected by known vulnerabilities, and returns the evidence behind
the decision.

The problem it addresses: a list of CVEs for a product name is easy to produce
and hard to act on. Cevrixa answers the narrower question — is *this version*
affected, on what evidence, and what is the fixed version?

It combines product identification, CPE and PURL resolution, version comparison,
vulnerability data from multiple sources, and applicability evaluation into a
single detection result. Every decision is computed from version boundaries
rather than inferred from a product name.

Detection results are explicit. A question Cevrixa cannot answer is reported as
`inconclusive`, never as `not_affected`.

Cevrixa is not a network scanner, not an exploit framework, and not a CVE lookup
wrapper.

## Features

Detection:

- Product resolution from a product name to a CPE identifier
- CPE-based vulnerability matching, including `AND` / `OR` configuration nodes,
  negated nodes, and `vulnerable: false` requirements
- PURL and package identity across PyPI, npm, Go, Maven, Debian, Alpine, and RPM
- Version parsing and comparison: numeric core, pre-release identifiers,
  post-release letter suffixes, and epoch or revision prefixes
- Affected-version evaluation for CPE criteria and package ranges
  (`introduced`, `fixed`, `last_affected`)
- Fixed-version detection
- Detection status: `affected`, `not_affected`, `inconclusive`
- Detection confidence: `exact`, `strong`, `moderate`, `weak`
- Explainable findings with the identity, range, evidence, and reasoning steps
  behind a decision
- Cross-source conflict reporting for severity, CVSS, KEV, and status
- Dataset coverage on every report: records searched, sources, and whether
  embedded fixtures contributed

Data:

- NVD (API 2.0), OSV, and CISA KEV data
- Local SQLite database with incremental `sync`
- Detection runs against the local dataset, with no network access needed

Interfaces:

- Human, JSON, JSONL, and SARIF output
- Multi-target scan from a file or stdin
- CycloneDX SBOM input
- CI gates through `--fail-on`

## Detection Results

Cevrixa does not reduce every detection to an affected / not-affected answer.

| Status | Meaning |
|---|---|
| `affected` | The available evidence indicates that the target matches an affected condition. |
| `not_affected` | The available evidence indicates that the target does not match the affected condition. |
| `inconclusive` | The available information is insufficient or cannot be evaluated reliably. |

`inconclusive` covers, for example: a configuration that requires a component
other than the target, a negated configuration, a version that cannot be
compared, and a package whose version does not match any evaluable range. An
inconclusive finding carries the reason and the question that would resolve it.

This distinction keeps an unresolved identity, an unsupported version syntax, or
an incomplete applicability statement from being read as a clean result.

The finding model also defines `unknown`, which is currently reserved and not
produced by the detection paths.

## Architecture

```text
Input
  │
  ├── Product + version
  ├── CPE
  ├── PURL
  └── CycloneDX SBOM / stdin
        │
        ▼
Product Resolver
        │
        ▼
CPE / Package Identity
        │
        ▼
Local Vulnerability Database            NVD · OSV · KEV
        │
        ▼
Applicability Matching
        │
        ├── CPE configuration nodes      AND · OR · negate
        └── Package ranges               introduced · fixed · last_affected
        │
        ▼
Version Evaluation
        │
        ▼
Finding
        │
        ├── Affected
        ├── Not Affected
        └── Inconclusive
              │
              ▼
Output                                  human · JSON · JSONL · SARIF
```

## Installation

Requires Go 1.27 or newer.

```bash
git clone https://github.com/Lutfifakee-Project/cevrixa
cd cevrixa
make build
```

The binary is written to `bin/cevrixa`.

Fetch vulnerability data into the local database before detecting:

```bash
./bin/cevrixa sync kev --live
./bin/cevrixa sync nvd --days 30
```

## Usage

Detect a single target:

```bash
cevrixa detect --product "Apache HTTP Server" --version 2.4.49
cevrixa detect --cpe "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
cevrixa detect --purl "pkg:pypi/django@4.2.0" --output json
```

Explain a specific vulnerability against a target:

```bash
cevrixa explain CVE-2021-41773 --product "Apache HTTP Server" --version 2.4.49
cevrixa explain CVE-2021-41773 --cpe "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"
```

Detect for multiple targets from a file or stdin:

```bash
cevrixa scan targets.json
cat targets.jsonl | cevrixa scan -
```

Detect for every component of a CycloneDX SBOM:

```bash
cevrixa sbom app.cdx.json --output sarif
cat app.cdx.json | cevrixa sbom -
```

Synchronise vulnerability data:

```bash
cevrixa sync kev --live
cevrixa sync nvd --days 30
cevrixa sync osv --purl pkg:pypi/django
cevrixa sync all --days 7
```

Environment and data status:

```bash
cevrixa info
cevrixa doctor
cevrixa version
```

Common flags:

| Flag | Applies to | Meaning |
|---|---|---|
| `--db <path>` | detect, scan, sbom, explain, sync, info | Local database (default `~/.cevrixa/cevrixa.db`) |
| `--output <fmt>` | detect, scan, sbom | `human` (default), `json`, `jsonl`, `sarif` |
| `--output <fmt>` | explain | `human` (default), `json` |
| `--fail-on <gate>` | detect, scan, sbom | `none`, `any`, `affected`, `inconclusive`, `kev`, `low`, `medium`, `high`, `critical` |
| `--with-kev` | detect, scan, sbom | Enrich findings with CISA KEV data |
| `--verbose` | detect, explain | Show the full reasoning steps |
| `--quiet` | detect, explain | Print only the identifier and status |

Input formats for `scan` and stdin are a JSON array or JSONL, one target per
entry, using `product` and `version`, `cpe`, or `purl`:

```json
[{"product": "Apache HTTP Server", "version": "2.4.49"}]
{"purl": "pkg:pypi/django@4.2.0"}
{"cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
```

`sbom` reads CycloneDX JSON. Components must carry a PURL; components without
one are skipped, because Cevrixa cannot resolve their identity.

## Example Output

```text
$ cevrixa detect --product "Apache HTTP Server" --version 2.4.49

[+] Target
    Product      Apache HTTP Server
    Version      2.4.49
    Resolved     cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*

[*] Findings: 2
    [*] Dataset      local store 7310 record(s) + embedded fixtures 9 record(s), TEST DATA [nvd, osv]

    [+] CVE-2021-41773
        [*] Status       AFFECTED
        [*] Severity     HIGH
        [*] CVSS         7.5 (v3.1)
        [*] Confidence   STRONG
        [*] Matched      >=2.4.0 <2.4.51
        [*] Fixed        2.4.51
        [*] Evidence     6

    [+] CVE-2021-42013
        [*] Status       AFFECTED
        [*] Severity     CRITICAL
        [*] CVSS         9.8 (v3.1)
        [*] Confidence   STRONG
        [*] Matched      >=2.4.0 <2.4.51
        [*] Fixed        2.4.51
        [*] Evidence     6
```

A question that cannot be answered is reported as such, with the reason:

```text
$ cevrixa explain CVE-2008-4128 --cpe "cpe:2.3:o:cisco:ios:12.4:*:*:*:*:*:*:*"

[+] CVE-2008-4128

    [+] Decision
        [*] Status       INCONCLUSIVE
        [!] No verdict was produced: AND configuration requires an additional component that is not the target

    [+] Identity
        [*] CPE          cpe:2.3:o:cisco:ios:12.4:*:*:*:*:*:*:*

    [+] Why
        • AND configuration requires an additional component that is not the target
```

Machine-readable output is available for automation:

```bash
cevrixa detect --product "Apache HTTP Server" --version 2.4.49 --output json
cevrixa detect --product "Apache HTTP Server" --version 2.4.49 --output jsonl
cevrixa detect --product "Apache HTTP Server" --version 2.4.49 --output sarif
```

## Data Sources

Cevrixa works with vulnerability information from multiple sources:

- **NVD** — CVE records and CPE applicability statements, through API 2.0
- **OSV** — package vulnerability ranges
- **CISA KEV** — known exploited vulnerabilities, used as enrichment

Coverage depends on which datasets have been synchronised. Every report states
how many records were searched and which sources contributed, so a result can be
read in the context of the data behind it.

NVD requests are rate limited and spaces them automatically; an API key in
`~/.cevrixa/config.json` raises the limit. Configuration is optional:

```json
{
  "log_level": "info",
  "default_output": "human",
  "nvd_api_key": ""
}
```

When no local database is present, Cevrixa falls back to a small set of embedded
fixtures so the detection pipeline can be exercised without syncing first. Those
records are test data, and every report that includes them labels them as such.

## Project Status

Cevrixa is under active development. The latest tagged release is `v0.2.2`; see
[CHANGELOG.md](CHANGELOG.md) for what changed.

Core detection is being built incrementally: product resolution, CPE resolution,
affected-version matching, fixed-version detection, finding generation, detection
explanations, and data-source integration.

Current limitations:

- Detection reads the entire local dataset for each target; there is no candidate
  filter by vendor and product yet.
- Version semantics are generic. Ecosystem-specific semantics are not applied per
  ecosystem yet, so some version syntaxes compare approximately.
- `explain` does not evaluate package targets: `--purl` reports `inconclusive`.
- `sbom` supports CycloneDX only.
- Embedded fixtures are used when no local database is present. They are test
  data, not vulnerability intelligence.

## Roadmap

- [x] Initial project architecture
- [x] Version intelligence
- [x] CPE support
- [x] PURL support
- [x] Initial vulnerability database integration
- [x] Basic detection engine
- [x] Inconclusive detection state
- [x] Explainable detection results
- [ ] Product resolver improvements
- [ ] CPE resolution improvements
- [ ] Ecosystem-specific version semantics
- [ ] Improved candidate filtering
- [ ] Expanded SBOM support, starting with SPDX
- [ ] Additional vulnerability data sources
- [ ] Detection performance improvements
- [ ] Reproducible detection tied to a database snapshot

## Documentation

Documentation currently lives in this README, [CHANGELOG.md](CHANGELOG.md), and
[CONTRIBUTING.md](CONTRIBUTING.md). Detailed documentation is planned in a
`docs/` directory:

- Detection architecture
- Version semantics
- Vulnerability database format
- CPE resolution
- PURL resolution
- Finding model
- CLI reference
- Development guide

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit message format, the
changelog categories, and the checks a change must keep green.

## License

MIT. See [LICENSE](LICENSE).
