# Cevrixa

**Evidence-first vulnerability applicability engine.**

Cevrixa determines whether a specific software or package version is
affected by known vulnerabilities, explains why, and returns
machine-readable evidence.

## What Cevrixa is not

- Not a network scanner
- Not an exploit framework or payload generator
- Not a CVE lookup wrapper

Cevrixa focuses on **applicability**: given a target, is it affected, and
why?

## Status

Current implemented capabilities:

- **Version intelligence** — parsing, comparison, contiguous ranges
- **Source adapters** — NVD (CVE + CPE), OSV (packages), DBCVE (enrichment), CISA KEV
- **Source correlation** — evidence collection with provenance, scalar conflict detection
- **Detection engine** — CPE matching (product/version) and PURL matching (PyPI, npm, Go, Maven)
- **Confidence scoring** — EXACT / STRONG / MODERATE / WEAK / UNKNOWN
- **KEV enrichment** — known-exploited status via `--with-kev`
- **Output formats** — human, JSON, JSONL, SARIF 2.1.0

Not yet implemented:

- Live data sources (currently uses embedded sample fixtures)
- Local database and `cevrixa sync`
- SBOM input
- `cevrixa explain` / `why` / `why-not`

## Install

    go build -o bin/cevrixa ./cmd/cevrixa

Or:

    make build

The resulting `bin/cevrixa` binary is self-contained and portable.

## Usage

CPE-based detection:

    cevrixa detect --product "Apache HTTP Server" --version "2.4.49"
    cevrixa detect --cpe "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

Package-based detection:

    cevrixa detect --purl "pkg:pypi/django@4.2.0"
    cevrixa detect --purl "pkg:npm/lodash@4.17.20"

KEV enrichment:

    cevrixa detect --product "Apache HTTP Server" --version "2.4.49" --with-kev

Output formats:

    cevrixa detect ... --output human    # default
    cevrixa detect ... --output json
    cevrixa detect ... --output jsonl
    cevrixa detect ... --output sarif

## Output example

    Cevrixa

    Target
      Product : Apache HTTP Server
      Version : 2.4.49
      Resolved: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*

    Findings: 1

    CVE-2021-41773
      Status     : AFFECTED
      Confidence : STRONG
      Matched    : >=2.4.0 <2.4.51
      Fixed      : 2.4.51
      Why        : 2.4.49 in >=2.4.0 <2.4.51
      KEV        : YES (added 2021-11-03)
      Evidence   : 3

## Configuration

Cevrixa optionally reads `~/.cevrixa/config.json`:

    {
      "log_level": "info",
      "default_output": "human",
      "nvd_api_key": ""
    }

A missing config file is not an error.

## Data sources

Cevrixa consumes public vulnerability intelligence from multiple upstream
sources. Source adapters are independent of the detection engine and
preserve provenance for every piece of evidence.

Currently implemented adapters:

- NVD — CVE and CPE applicability
- OSV — package vulnerability databases
- DBCVE — technical enrichment
- CISA KEV — known exploited vulnerabilities

Cevrixa does not claim data ownership. Every finding carries evidence
provenance back to its source.

## Development

    make build    # build binary
    make test     # run tests
    make vet      # run go vet
    make check    # fmt + vet + test

## License

MIT
