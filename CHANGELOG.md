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

Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- Fixed `scan` and `sbom` accepting an unrecognised `--fail-on` gate, which
  disabled the check and exited successfully on a vulnerable target. Every
  command that accepts the flag now validates it against the same set of gates.
- Added a store applicability check to `doctor`. A record count alone implied a
  healthy store even when most records carried no criteria and could not match
  any target. `doctor` now measures how many stored records carry matchable
  criteria and warns with the re-sync command when some do not.

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
