# Changelog

All notable changes to Cevrixa are documented in this file. It records
Cevrixa's own changes only: no external tracker links and no notes about how a
change was found.

Categories:

- **Added** — new capability
- **Changed** — behaviour or architecture change
- **Improved** — performance or accuracy gain
- **Fixed** — defect corrected
- **Security** — a change that affects how far Cevrixa can be trusted not to
  under-report: fail-open gates, swallowed errors, unverified claims
- **Detection** — product resolution, CPE resolution, affected matching,
  fixed-version detection, or the finding model
- **Database** — vulnerability source, mapping, or store change
- **Removed** — capability taken away
- **Breaking** — requires action from the user

Versions follow Semantic Versioning.

## [Unreleased]

## [v0.9.0] — 2026-10-06

Researcher experience. explain shows more of the record and its reasoning.

### Added

- explain now prints a vulnerability metadata section: source, source record
  identifier, aliases, published and modified dates, and the summary.
- explain accepts --trace, recording the reasoning path (resolve identity,
  load vulnerability, evaluate applicability, collect evidence) in the human
  output and in JSON, matching detect.
- explain --verbose now expands the applicability statements behind each
  evidence item, showing the criteria and version bounds.

### Changed

- explain JSON now carries source_identifier, aliases, published,
  modified, and trace alongside the decision.

## [v0.8.0] — 2026-10-06

Integration. Commands read from a frozen snapshot, and detect accepts a target
from stdin, so Cevrixa composes cleanly in a pipeline.

### Added

- `scan` and `sbom` now accept `--snapshot <name>`, matching `detect`, so a batch
  or an SBOM can be evaluated against a frozen intelligence state.
- `detect -` reads one target JSON object from stdin, for pipelines such as
  `generate-target | cevrixa detect -`.

### Changed

- `--db` and `--snapshot` are mutually exclusive on `scan` and `sbom`, as they
  already were on `detect`.

## [v0.7.0] — 2026-10-06

Remediation intelligence. An affected finding now states what to do about it.

### Added

- Added a derived remediation to every affected finding: an `upgrade` action
  with the fixed version when one is known, or a `monitor` action when no
  fixed version is available. A not_affected or inconclusive finding has no
  remediation. The guidance is derived from data the engine already holds; it
  never invents a fixed version.
- `detect` and `scan` output now shows the fix action, and JSON carries a
  `remediation` object.

## [v0.6.0] — 2026-10-06

EPSS and prioritization. Findings are now ranked by urgency using KEV,
severity, and EPSS, without ever changing applicability.

### Added

- Added an EPSS source: `sync epss` downloads the FIRST.org EPSS feed and
  stores per-CVE probability scores. The feed is read gzip or plain, and is
  parsed defensively.
- Added `priority` to every finding. Only an affected finding has a priority;
  the level is `critical`, `high`, `medium`, or `low`, with the factors
  that produced it recorded (known exploitation, severity, EPSS).
- Findings now carry the EPSS score and percentile when one is stored.

### Changed

- `sync all` now includes EPSS as a fourth step.

## [v0.5.0] — 2026-10-05

SPDX input. `sbom` now reads SPDX JSON as well as CycloneDX, and detects
the format from the document.

### Added

- Added SPDX 2.x JSON support to `sbom`. Packages are read from their
  `purl` external reference; a package without a PURL is skipped.
- `sbom` now detects the SBOM format automatically (CycloneDX or SPDX).
  An unrecognised document is an error, never a guess that silently yields no
  targets.

## [v0.4.0] — 2026-10-05

Snapshot and offline intelligence store. A detection result can now be tied to
a frozen intelligence state, so it can be reproduced.

### Added

- Added the `snapshot` command. `snapshot create <name>` freezes the
  current store into `~/.cevrixa/snapshots/<name>.db` and stamps it with
  metadata and a digest; `snapshot list` enumerates snapshots.
- Added `--snapshot <name>` to `detect`, to run against a frozen state
  instead of the live store. A missing snapshot is an error, never a silent
  fallback to the current data.
- Every report now states its intelligence state: the dataset carries the
  snapshot name and a deterministic SHA-256 digest of the records searched.
- Added a store digest: a stable hash over the stored vulnerability records, so
  two reports can be shown to come from the same state.

## [v0.3.2] — 2026-10-05

### Added

- Added `why` and `why-not` commands. `why` answers why a target is
  affected; `why-not` answers why it is not. Both use the same reasoning
  path as `explain`, so the three cannot disagree, and neither invents a
  reason that contradicts the verdict: when the question does not match the
  decision, the command says so and prints the real decision instead.

## [v0.3.1] — 2026-10-05

### Added

- Added a decision trace to `detect` via `--trace`. The trace records the
  ordered reasoning path behind a result — identity resolution, candidate
  discovery, applicability evaluation, and the decision — so a reader can see
  how a verdict was reached, not only its result. It is also carried in
  `--output json`. The trace is off unless requested.

## [v0.3.0] — 2026-10-05

Evidence and explainability release. `explain` now evaluates package
(PURL) targets and shows the evidence behind a decision.

### Added

- `explain` now evaluates package targets. A `--purl` target is run
  through the same package matcher as `detect`, so the two cannot disagree.
  Previously every package target was reported as `INCONCLUSIVE` with a
  "not evaluated yet" note.
- `explain` now prints the correlated evidence tree: the status, severity,
  CVSS, references, and applicability statements behind a decision, not just
  the reference list.
- `explain` now reports cross-source conflicts when sources disagree, using
  the same correlation that `detect` uses.
- `explain --output json` now carries `why`, `evidence`, and
  `conflicts` alongside the decision.

### Detection

- A package target whose vulnerability carries no package applicability naming
  that package is reported as `inconclusive`, not `not_affected`: an
  unanswerable question is a gap in the record, not a clean result.

## [v0.2.4] — 2026-10-05

### Changed

- Removed dead code: `defaultKEVDBPath`, an unused duplicate of
  `defaultDBPath`; `engine.Options.Source`, a field set by three commands
  but never read by the engine; and `errNotImplemented` with its unused
  `errors` import. No behaviour change.

## [v0.2.3] — 2026-10-05

Portability and reliability release. Cevrixa now builds for Linux, macOS, and
Windows (amd64 and arm64) from any host, ships a release workflow, and fixes a
set of defects found by auditing the whole tree.

### Security

- Fixed an undecidable CPE configuration being silently dropped from `detect`
  and `scan`. A finding whose applicability could not be decided (an `AND`
  group that needs a component other than the target, a negated node, or a
  version range that cannot be compared) has `matched` false, and was
  discarded before it reached the report. The core promise — a question
  Cevrixa cannot answer is `inconclusive`, never `not_affected` — now holds on
  the CPE path, not only the package path.
- Fixed severity `--fail-on` gates firing on findings the target is not
  affected by. A `not_affected` or `inconclusive` finding still carries the
  vulnerability's severity for context, and `--fail-on high` treated that as a
  build failure. Severity gates now apply only to `affected` findings.
- Fixed `scan` and `sbom` accepting an unrecognised `--fail-on` gate, which
  disabled the check and exited successfully on a vulnerable target. Every
  command that accepts the flag now validates it against the same set of gates.
- Added a store applicability check to `doctor`. A record count alone implied a
  healthy store even when most records carried no criteria and could not match
  any target. `doctor` now measures how many stored records carry matchable
  criteria and warns with the re-sync command when some do not.

### Detection

- Fixed the CycloneDX reader ignoring `metadata.component` and nested
  `components`. Real SBOMs nest dependencies, and those components were
  silently skipped. The reader now walks the tree and deduplicates by PURL.
- Improved OSV range parsing to keep a `fixed` or `last_affected` event that
  appears before any `introduced` event, instead of dropping it.

### Database

- Fixed OSV sync stopping after the first page. The client already returned a
  pagination token, but the sync ignored it, so a package with many advisories
  was stored only in part. `sync osv` now follows the token to completion and
  records sync metadata.
- Fixed NVD backfill using a hardcoded end date. `backfill` now starts from the
  current time, so it keeps covering the present as time passes.

### Fixed

- Fixed `embed.FS` reads failing on Windows. Fixture paths were built with
  `filepath.Join`, which produces backslashes on Windows, but `embed.FS`
  always uses forward slashes. Every fixture-backed test in `internal/engine`
  failed on Windows.
- Fixed the config loader ignoring `HOME` on Windows. `os.UserHomeDir` reads
  `USERPROFILE` there, so a redirected `HOME` had no effect and tests read the
  real machine config. The loader now prefers `HOME`, then falls back.
- Fixed SARIF output serialising an empty report as `"results": null` and
  `"rules": null`. The SARIF schema expects arrays, so an empty run now emits
  `[]`.

### Improved

- Added retry with exponential backoff to the NVD, OSV, and KEV HTTP clients,
  capped at a per-client maximum, so a transient 429 or 5xx no longer fails a
  sync outright.
- Improved correlation grouping with union by rank, keeping the identifier
  trees shallow for large datasets.

### Added

- Added cross-platform builds. `scripts/build.go` compiles every supported
  target from any host without a Unix shell, and `make build-all` runs it.
- Added `scripts/fmtcheck.go`, a portable `gofmt` check that does not rely on a
  Unix shell, used by `make check` and CI.
- Added an OS matrix to CI (Ubuntu, Windows, macOS) that runs `vet` and the
  test suite on each, plus a cross-build job that produces all six binaries.
- Added `.github/workflows/release.yml`. Pushing a `v*` tag builds every
  platform, writes a `checksums.txt`, and publishes a GitHub Release.
- Documented the supported platforms in the README.

## [v0.2.2] — 2026-09-30

### Detection

- Fixed evaluation of configurations that pin a version inside the CPE string:
  the version is compared instead of being treated as an unbounded range.
- Fixed the reason reported for an unmet `AND` requirement. It claimed that no
  part of the configuration matched even when a part did match; it now names the
  component that is missing.
- Improved version comparison for pre-release identifiers that carry a leading
  zero, such as `12.4.3-02854`. These versions previously failed to parse, which
  made the whole range uncomparable and forced an `inconclusive` verdict.

### Database

- Changed NVD configuration modelling to the API 2.0 shape: nodes are read from
  `nodes`. The previous mapping read `children`, so every configuration was
  discarded while storing and each record carried no CPE match criteria. CPE
  matching could not produce findings from the local database.
- Fixed duplicate NVD references. A URL is now stored once with its tags merged,
  instead of once per contributing source.

### Improved

- Improved stored NVD records: configuration nodes, CPE criteria, and version
  bounds are now persisted, so detection works against synced data.

### Breaking

- Records stored by an earlier version keep their empty applicability and are
  not repaired by upgrading, because a record is keyed on identifier and source
  and an unchanged vulnerability is never fetched again. Re-sync with
  `cevrixa sync nvd --days N` (or `--full`), or remove the database file.

## [v0.2.1] — 2026-09-30

### Detection

- Added post-release identifiers to the version model. A trailing letter suffix
  is parsed and sorts after the plain version, so `1.1.1 < 1.1.1c < 1.1.2`, and
  a package revision sorts after the version instead of before it.
- Added an explicit uncomparable-version outcome to package matching. A target
  whose version cannot be compared is reported as `inconclusive` with a reason
  instead of being dropped from the results.
- Fixed package matching silently discarding a target when its version could not
  be parsed, which reported an affected package as clean.

### Fixed

- Fixed package revisions sorting below the version they belong to. Revisions
  were attached as pre-release identifiers, which inverted `2.4.7-1` and
  `2.4.7` for Debian and RPM versions.

## [v0.2.0] — 2026-09-30

### Detection

- Added `AND` and `OR` configuration evaluation as NVD defines it. A
  configuration that requires another component is no longer treated as a flat
  `OR`, which was the main source of false positives.
- Added treatment of `vulnerable: false` entries as requirements instead of
  ignoring them.
- Added evaluation of versions pinned inside a CPE criteria string.
- Added `inconclusive` as a finding status, with a reason and the open question
  that would resolve it. An undecidable configuration is never reported as
  affected.
- Added an explicit undecided outcome to the matcher, so a configuration that
  cannot be decided is a first-class result rather than a silent non-match.
- Added range and fixed version to decided non-matches, so `explain` can answer
  why a target is not affected instead of only why it is.
- Changed the confidence model to express boundary precision (`exact`, `strong`,
  `moderate`, `weak`), so the label no longer reads as a blended score.
- Improved confidence labelling for criteria that pin one exact version.
- Fixed `explain` printing `NOT AFFECTED` for questions it never evaluated.
  Package targets, unresolved identities, and unusable versions now report
  `INCONCLUSIVE` with the reason.
- Fixed cross-source conflict detection never firing, because correlation was
  given a single vulnerability and no enrichments.
- Fixed conflict detection comparing raw strings, which reported a difference in
  wording (`MODERATE` against `medium`) as a difference in meaning.
- Fixed negated configurations being ignored; they are now reported as
  inconclusive instead of being treated as ordinary configurations.

### Added

- Added dataset coverage to every report: records searched, sources, and whether
  embedded fixtures contributed. Fixture records are labelled as test data.
- Added questions to the reasoning of an inconclusive finding.
- Added severity gates to `--fail-on`: `low`, `medium`, `high`, `critical`.
- Added `store.ListEnrichments`, so every source for a vulnerability can be
  correlated.

### Security

- Changed `--fail-on` to reject an unknown gate instead of silently disabling
  the check and exiting successfully on a vulnerable target.
- Fixed a local dataset that could not be read being silently replaced by
  embedded test fixtures. The read error is now reported.

### Improved

- Improved evidence for correlation: a vulnerability's own risk data is part of
  the evidence set, so a disagreement with another source can be observed.

## [v0.1.0]

### Detection

- Added product resolution from a product name to a CPE identifier.
- Added package identity from a PURL.
- Added affected-version range evaluation with inclusive and exclusive bounds.
- Added fixed-version detection from range boundaries and advisory events.
- Added a structured finding model with status, confidence, evidence, and
  reasoning steps.

### Added

- Added NVD, OSV, and CISA KEV source adapters.
- Added a local SQLite store with incremental `sync`.
- Added `detect`, `scan`, `sbom`, `explain`, `info`, `doctor`, and `version`.
- Added human, JSON, JSONL, and SARIF output.
- Added `--fail-on` for CI gates.
