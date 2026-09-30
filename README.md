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

**v0.2.2** — detection reliability. See [CHANGELOG.md](CHANGELOG.md) for what
changed and why.

## Install

    git clone https://github.com/Lutfifakee-Project/cevrixa
    cd cevrixa
    make build

The resulting `bin/cevrixa` binary is self-contained and portable.

Requires Go 1.27+.

## Quick start

    # Sync the KEV catalog (live from CISA, no API key required)
    ./bin/cevrixa sync kev --live

    # Detect a CPE-based target
    ./bin/cevrixa detect --product "Apache HTTP Server" --version "2.4.49"

    # Detect a package via PURL
    ./bin/cevrixa detect --purl "pkg:pypi/django@4.2.0"

    # Explain why a specific CVE applies
    ./bin/cevrixa explain CVE-2021-41773 --product "Apache HTTP Server" --version "2.4.49"

## Commands

| Command | Purpose |
|---|---|
| `detect` | Detect whether a single target is affected |
| `scan` | Read multiple targets from a file or stdin |
| `sbom` | Read a CycloneDX SBOM and detect affected components |
| `sync` | Download and persist vulnerability data to local store |
| `explain` | Explain why a vulnerability does or does not apply |
| `info` | Show environment and data status |
| `doctor` | Run environment and data health checks |
| `version` | Print version information |
| `help` | Show help |

## Input types

Cevrixa accepts three identity formats:

**CPE** (product + version):

    ./bin/cevrixa detect --product "Apache HTTP Server" --version "2.4.49"
    ./bin/cevrixa detect --cpe "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

**PURL** (package ecosystem):

    ./bin/cevrixa detect --purl "pkg:pypi/django@4.2.0"
    ./bin/cevrixa detect --purl "pkg:npm/lodash@4.17.20"
    ./bin/cevrixa detect --purl "pkg:golang/github.com/gin-gonic/gin@v1.9.0"
    ./bin/cevrixa detect --purl "pkg:maven/org.apache.commons/commons-lang3@3.12.0"

**SBOM** (CycloneDX JSON):

    ./bin/cevrixa sbom app.cdx.json
    ./bin/cevrixa sbom - < app.cdx.json --output sarif

## Output formats

Human (default):

    ./bin/cevrixa detect ...

JSON:

    ./bin/cevrixa detect ... --output json

JSONL (one finding per line, pipe-friendly):

    ./bin/cevrixa detect ... --output jsonl

SARIF 2.1.0 (for CI/CD, GitHub Code Scanning, VS Code):

    ./bin/cevrixa detect ... --output sarif

## Example output

    Cevrixa

    Target
      Product     Apache HTTP Server
      Version     2.4.49
      Resolved    cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*

    Findings: 2
    Dataset     local store 1204882 record(s) [nvd, osv]

    CVE-2021-41773
      Status     : AFFECTED
      Confidence : STRONG
      Matched    : >=2.4.0 <2.4.51
      Fixed      : 2.4.51
      Why        : 2.4.49 in >=2.4.0 <2.4.51
      KEV        : YES (added 2021-11-03)
      Evidence   : 3

    CVE-2021-42013
      Status     : AFFECTED
      Confidence : STRONG
      Matched    : >=2.4.0 <2.4.51
      Fixed      : 2.4.51
      Why        : 2.4.49 in >=2.4.0 <2.4.51
      Evidence   : 3

## Local store

Cevrixa can persist vulnerability data to a local SQLite database for
fast, offline, reproducible detection.

    # Sync KEV from CISA (~1700 entries)
    ./bin/cevrixa sync kev --live

    # Sync recent NVD CVE records (30 days)
    ./bin/cevrixa sync nvd --days 30

    # Sync OSV vulnerabilities for a package
    ./bin/cevrixa sync osv --purl pkg:pypi/django

    # Sync all applicable sources
    ./bin/cevrixa sync all --days 7

By default, the local DB lives at `~/.cevrixa/cevrixa.db`. Override with
`--db <path>`.

Once a DB exists, `detect`, `scan`, `sbom`, and `explain` use it
automatically without needing an explicit `--db` flag.

### NVD rate limits

The NVD public API enforces 5 requests per 30 seconds. Cevrixa handles
this automatically by spacing requests ~6 seconds apart — no API key
required. If you set an NVD API key in `~/.cevrixa/config.json` (see
below), Cevrixa uses the faster 50-req/30s limit.

### Full history

To fetch the entire NVD history (~250k CVE), use:

    ./bin/cevrixa sync nvd --full

This is slow (hours without an API key). Prefer `--days N` for regular
updates.

## Configuration

Optional. Cevrixa reads `~/.cevrixa/config.json`:

    {
      "log_level": "info",
      "default_output": "human",
      "nvd_api_key": ""
    }

A missing config file is not an error.

## CI/CD

Cevrixa exits non-zero when findings match a given threshold:

    ./bin/cevrixa detect ... --fail-on affected
    ./bin/cevrixa detect ... --fail-on kev
    ./bin/cevrixa detect ... --fail-on critical
    ./bin/cevrixa detect ... --fail-on inconclusive
    ./bin/cevrixa scan targets.json --fail-on any

Accepted gates: `none`, `any`, `affected`, `inconclusive`, `kev`, and the
severity labels `low`, `medium` (`moderate`), `high`, `critical`. An
unrecognised gate is rejected instead of silently disabling the check.

SARIF output can be uploaded directly to GitHub Code Scanning:

    ./bin/cevrixa detect ... --output sarif > cevrixa.sarif

## Data sources

Cevrixa consumes public vulnerability intelligence from multiple upstream
sources. Source adapters are independent of the detection engine and
preserve provenance for every piece of evidence.

- **NVD** — CVE and CPE applicability (`services.nvd.nist.gov`)
- **OSV** — package vulnerability databases (`api.osv.dev`)
- **CISA KEV** — Known Exploited Vulnerabilities catalog

Cevrixa does not claim data ownership. Every finding carries evidence
provenance back to its source.

## Design principles

1. **Evidence-first** — every claim carries provenance
2. **Version-centric** — applicability is computed, not guessed
3. **Explainable** — decisions come with reasoning steps
4. **Conflict-aware** — sources disagreements are surfaced, never hidden, and
   wording differences between sources are normalised so that a difference in
   vocabulary is never reported as a difference in meaning
5. **Local-first** — detection works offline once synced
6. **Reproducible** — results state which dataset they came from: the number of
   records searched, the sources, and whether embedded test fixtures contributed
7. **Composable** — JSON / JSONL / SARIF outputs, stdin inputs
8. **Minimal** — small dependency surface, standard library when possible
9. **Never guesses** — when a configuration cannot be decided from a single
   target (`AND` groups that need another component, negated nodes, unusable
   versions), Cevrixa reports `inconclusive` with the reason instead of
   reporting `affected`

## Development

    make build    # build binary into bin/
    make test     # run all tests
    make vet      # run go vet
    make check    # fmt + vet + test
    make fmt      # gofmt -s -w .

## Roadmap

Implemented in v0.2.2:

- NVD API 2.0 configuration nodes are read from `nodes` rather than `children`,
  so synced records carry CPE criteria and CPE detection works against real data
  instead of silently finding nothing (see the operational note in
  [CHANGELOG.md](CHANGELOG.md) if you already have a database)

Implemented in v0.2.1:

- Package versions with a letter suffix are parsed instead of rejected
  (`openssl 1.1.1c`), and Debian revisions and RPM releases sort after the plain
  version instead of below it
- A package whose version cannot be compared is reported as `inconclusive` with
  the reason, instead of being dropped from the results

Implemented in v0.2.0 (detection reliability):

- CPE configuration semantics: `AND` and `OR` are evaluated as NVD defines
  them, `negate` is reported instead of silently ignored, and
  `vulnerable: false` entries are treated as requirements rather than dropped
- A version pinned inside a criteria string is honoured (previously every
  version of the product matched such a criterion)
- Version ranges are evaluated with the correct boundary inclusivity, and a
  criterion that pins an exact version now yields `exact` confidence instead of
  `wildcard`
- Undecidable applicability is reported as `inconclusive` with a reason, never
  as `affected`
- `explain` no longer prints `NOT AFFECTED` for a question it did not evaluate
  (package targets, unresolved identities, unusable versions)
- Cross-source conflicts are reachable from `detect`, and conflict values are
  normalised so wording differences are not reported as disagreement
- Dataset coverage is part of every report, and embedded test fixtures are
  labelled as test data
- `--fail-on` accepts severity gates and rejects unknown values instead of
  silently disabling the gate

Implemented in v0.1.0:

- Version intelligence (CPE + PURL, SemVer, Debian, RPM)
- NVD, OSV, CISA KEV adapters
- Detection engine with confidence scoring
- Local SQLite store with `sync` (kev, nvd, osv, all)
- `detect`, `scan`, `sbom`, `explain`, `info`, `doctor`
- Human / JSON / JSONL / SARIF output
- `--fail-on` for CI gates

Deferred:

- Distinct zero-result outcomes (`NOT_AFFECTED` vs `NO_DATA` vs
  `IDENTITY_UNRESOLVED`); dataset coverage is reported, but the outcome values
  themselves are not emitted yet
- Candidate prefilter by CPE vendor/product — every stored record is currently
  scanned for each target
- Candidate matching that reports *why* a candidate was considered and rejected
- Package applicability inside `explain` (`--purl` reports `inconclusive`)
- Vendor advisory adapters (vendor-specific)
- `why` / `why-not` as separate commands
- SPDX SBOM support (currently CycloneDX only)
- Snapshot rollback / named snapshots
- Rules engine and plugin sources

## License

MIT
