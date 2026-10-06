![Cevrixa](assets/banner.png)

# Cevrixa

> Evidence-first vulnerability applicability intelligence.
> Know why a vulnerability applies.

<p align="center">

[![CI](https://github.com/Lutfifakee-Project/cevrixa/actions/workflows/ci.yml/badge.svg)](https://github.com/Lutfifakee-Project/cevrixa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Lutfifakee-Project/cevrixa)](https://github.com/Lutfifakee-Project/cevrixa/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</p>

## What Cevrixa does

Cevrixa is a vulnerability applicability engine. Given a product, package, or
component, it determines whether that exact version is affected by known
vulnerabilities, and returns the evidence behind the decision.

A list of CVEs for a product name is easy to produce and hard to act on.
Cevrixa answers the narrower question: is this version affected, on what
evidence, and what is the fixed version?

Every decision is computed from version boundaries, not inferred from a product
name. A question Cevrixa cannot answer is reported as `inconclusive`, never as
`not_affected`.

Cevrixa is not a network scanner, an exploit framework, or a CVE lookup wrapper.

## Installation

Cevrixa requires Go 1.27 or later.

Install with:

```bash
go install github.com/Lutfifakee-Project/cevrixa/cmd/cevrixa@latest
```

Verify the installation:

```bash
cevrixa -h
```

> If `cevrixa` is not found, add your Go bin directory to your `PATH`.
> Run `go env GOPATH` (the binary lives in its bin dir), or `go env GOBIN` if set.

## Quick start

Detect a product version:

```bash
cevrixa detect --product "Apache HTTP Server" --version 2.4.49
```

Detect a package:

```bash
cevrixa detect --purl "pkg:pypi/django@4.2.0"
```

Detect an SBOM:

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

Cevrixa automatically offers to sync vulnerability data when no local dataset
is available. Use `--no-sync` for non-interactive and CI environments.

That is enough to get started. To see everything else, run `cevrixa -h` or
`cevrixa detect -h`.

## Commands

| Command | Purpose |
| --- | --- |
| `detect` | Detect whether one target is affected (product, CPE, PURL, or SBOM) |
| `scan` | Read many targets from a file or stdin |
| `explain` | Explain why a vulnerability does or does not apply |
| `sync` | Download vulnerability data (all sources by default) |
| `doctor` | Check the environment and dataset health |
| `info` | Show environment and dataset status |
| `version` | Print version and build information |
| `snapshot` | Freeze and list reproducible intelligence states |

`why`, `why-not`, and the top-level `sbom` command are deprecated
but still work; they print a warning and point at `explain` and
`detect --sbom`.

## How it works

The detection pipeline turns an input into an evidence-backed decision:

```text
Input  (product + version | CPE | PURL | SBOM | stdin)
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

A finding is never reduced to true or false, and the report carries its own
overall decision:

| Report decision | Meaning |
|---|---|
| `affected` | At least one finding proved the target is affected. |
| `inconclusive` | A candidate exists but applicability could not be decided reliably. |
| `no_data` | The target was evaluated but the dataset held no matching candidate. This does not prove the target is safe. |
| `identity_unresolved` | The target could not be mapped to a reliable identity, so nothing was evaluated. |

Within a finding, `not_affected` means the applicability question was actually
evaluated and the target does not satisfy the affected condition. An unresolved
identity, an unsupported version syntax, or an incomplete applicability
statement is never reported as a clean result.

`--fail-on` accepts `no_data` and `identity_unresolved` as report-level gates,
so a CI job can fail when the dataset could not answer or the target could not
be identified.

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

Show the decision trace behind a result:

```bash
cevrixa detect --product "Apache HTTP Server" --version 2.4.49 --trace
```

## Supported sources

| Source | Provides |
| --- | --- |
| NVD | CVE records and CPE applicability statements |
| OSV | Package vulnerability ranges |
| CISA KEV | Known exploited vulnerabilities |

Coverage depends on the datasets synchronised locally. Reports identify
the sources and records used for each result.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit message format, the
changelog categories, and the checks a change must keep green.

## License

MIT. See [LICENSE](LICENSE).
