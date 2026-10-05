<img src="assets/banner.png" alt="Cevrixa" width="600">

# Cevrixa

> Evidence-first vulnerability applicability intelligence.
> Know why a vulnerability applies.

<a href="https://github.com/Lutfifakee-Project/cevrixa/actions/workflows/ci.yml"><img src="https://github.com/Lutfifakee-Project/cevrixa/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/Lutfifakee-Project/cevrixa/releases"><img src="https://img.shields.io/github/v/release/Lutfifakee-Project/cevrixa" alt="Release"></a>
<img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
<img src="https://img.shields.io/badge/go-1.27-00ADD8.svg" alt="Go">

## Overview

Cevrixa is a vulnerability applicability engine. Given a product, package, or
system component, it determines whether that *exact version* is affected by
known vulnerabilities, and returns the evidence behind the decision.

A list of CVEs for a product name is easy to produce and hard to act on.
Cevrixa answers the narrower question: is this version affected, on what
evidence, and what is the fixed version?

Every decision is computed from version boundaries, not inferred from a product
name. A question Cevrixa cannot answer is reported as `inconclusive`, never as
`not_affected`.

Cevrixa is not a network scanner, an exploit framework, or a CVE lookup wrapper.

## Features

**Detection**

- Product resolution from a name to a CPE identifier
- CPE matching, including `AND` / `OR` configuration nodes, negated nodes,
  and `vulnerable: false` requirements
- PURL and package identity across PyPI, npm, Go, Maven, Debian, Alpine, RPM
- Version comparison: numeric core, pre-release identifiers, post-release
  suffixes, epoch and revision prefixes
- Affected-version evaluation for CPE criteria and package ranges
  (`introduced`, `fixed`, `last_affected`)
- Fixed-version detection
- Status: `affected`, `not_affected`, `inconclusive`
- Confidence: `exact`, `strong`, `moderate`, `weak`
- Explainable findings: identity, range, evidence, and reasoning steps
- Cross-source conflict reporting for severity, CVSS, KEV, and status
- Decision trace: the ordered reasoning path behind a verdict
- Dataset coverage on every report

**Data**

- NVD (API 2.0), OSV, and CISA KEV sources
- Local SQLite store with incremental `sync`
- Detection runs against the local dataset, with no network access

**Interfaces**

- Human, JSON, JSONL, and SARIF output
- Single-target `detect`, multi-target `scan`, and CycloneDX `sbom` input
- `explain`, `why`, and `why-not` for a specific vulnerability
- CI gates through `--fail-on`

## Installation

Requires Go 1.27 or newer.

```bash
git clone https://github.com/Lutfifakee-Project/cevrixa
cd cevrixa
make build
```

The binary is written to `bin/cevrixa`. Prebuilt binaries are published for
Linux, macOS, and Windows on `amd64` and `arm64`. To cross-compile every
target from any host:

```bash
make build-all
```

Fetch vulnerability data before detecting:

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

Explain a specific vulnerability, and ask why or why-not:

```bash
cevrixa explain CVE-2021-41773 --product "Apache HTTP Server" --version 2.4.49
cevrixa why CVE-2021-41773 --cpe "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
cevrixa why-not CVE-2021-41773 --cpe "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"
```

Show the decision trace behind a result:

```bash
cevrixa detect --product "Apache HTTP Server" --version 2.4.49 --trace
```

Scan many targets, or every component of a CycloneDX SBOM:

```bash
cevrixa scan targets.json
cat targets.jsonl | cevrixa scan -
cevrixa sbom app.cdx.json --output sarif
```

Synchronise vulnerability data:

```bash
cevrixa sync kev --live
cevrixa sync nvd --days 30
cevrixa sync osv --purl pkg:pypi/django
```

Common flags:

| Flag | Applies to | Meaning |
|---|---|---|
| `--db <path>` | most commands | Local database (default `~/.cevrixa/cevrixa.db`) |
| `--output <fmt>` | detect, scan, sbom | `human`, `json`, `jsonl`, `sarif` |
| `--fail-on <gate>` | detect, scan, sbom | `none`, `any`, `affected`, `inconclusive`, `kev`, or a severity |
| `--with-kev` | detect, scan, sbom | Enrich findings with CISA KEV data |
| `--trace` | detect | Show the decision trace |
| `--verbose` / `--quiet` | detect, explain | Full reasoning / identifier only |

## How It Works

The detection pipeline turns an input into an evidence-backed decision:

```text
Input  (product + version | CPE | PURL | CycloneDX | stdin)
  |
  v
Resolve identity        product -> CPE; PURL -> package identity
  |
  v
Applicability           CPE configuration nodes; package ranges
  |
  v
Version evaluation      boundary comparison
  |
  v
Evidence + conflicts    cross-source correlation
  |
  v
Decision                affected | not_affected | inconclusive
  |
  v
Output                  human | JSON | JSONL | SARIF
```

A decision is never reduced to true or false:

| Status | Meaning |
|---|---|
| `affected` | The evidence indicates the target matches an affected condition. |
| `not_affected` | The evidence indicates the target does not match an affected condition. |
| `inconclusive` | The information is insufficient or cannot be evaluated reliably. |

An unresolved identity, an unsupported version syntax, or an incomplete
applicability statement is reported as `inconclusive` with its reason, never as
a clean result.

A worked example:

```text
 cevrixa detect --product "Apache HTTP Server" --version 2.4.49

[+] Target
    Product      Apache HTTP Server
    Version      2.4.49
    Resolved     cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*

[*] Findings: 1
    [+] CVE-2021-41773
        [*] Status       AFFECTED
        [*] Confidence   STRONG
        [*] Matched      >=2.4.0 <2.4.51
        [*] Fixed        2.4.51
```

When the answer cannot be determined, Cevrixa says so:

```text
 cevrixa explain CVE-2008-4128 --cpe "cpe:2.3:o:cisco:ios:12.4:*:*:*:*:*:*:*"

    [+] Decision
        [*] Status       INCONCLUSIVE
        [!] No verdict was produced: AND configuration requires an additional
            component that is not the target
```

## Supported Sources

| Source | Provides |
|---|---|
| **NVD** | CVE records and CPE applicability statements (API 2.0) |
| **OSV** | Package vulnerability ranges |
| **CISA KEV** | Known exploited vulnerabilities (enrichment) |

Coverage depends on which datasets have been synchronised. Every report states
how many records were searched and which sources contributed. When no local
database is present, Cevrixa falls back to a small set of embedded fixtures so
the pipeline can be exercised; those records are labelled as test data.

## Contributing

See <a href="CONTRIBUTING.md">CONTRIBUTING.md</a> for the commit message format, the
changelog categories, and the checks a change must keep green.

## License

MIT. See <a href="LICENSE">LICENSE</a>.
