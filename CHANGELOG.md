# Changelog

All notable changes to Cevrixa are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [v0.2.2] — 2026-09-30

The NVD CPE branch was never functional against real synced data.

### Fixed

- **CPE configuration nodes were read from the wrong JSON field.** NVD API 2.0
  nests configuration nodes under `nodes`:

      "configurations": [
        {"operator": "AND", "nodes": [
          {"operator": "OR", "negate": false, "cpeMatch": [ ... ]}
        ]}
      ]

  but the response type only declared `json:"children"`. Every real NVD
  configuration was therefore discarded while mapping, so each synced record was
  stored with no CPE criteria at all. Measured against a real 7121 record
  dataset: **0 records contained a `criteria` value**, and 2034 records had an
  `applicability` node with no matches. `detect` and `explain` could not match
  anything for CPE targets; every "AFFECTED" result seen before this release came
  from the embedded test fixtures rather than from synced data. Both `nodes` and
  the legacy `children` field are now accepted.
- **An unmet `AND` requirement reported the wrong reason.** When one part of an
  `AND` group matched and another did not, the verdict was correctly
  `inconclusive` but the reason read "no part of the AND configuration matched
  the target", which is false. The reason now names the missing component.
- **Versions with leading zeros in a pre-release identifier were rejected.**
  Firmware versions such as `12.4.3-02854` failed to parse, which made the whole
  range uncomparable and the finding `inconclusive`. `ParseLenient` now tolerates
  those zeros so the range can still be compared.
- **Duplicate references inflated the evidence list.** NVD lists the same
  advisory once per contributing source; a real record showed the same five URLs
  repeated twice. References are now deduplicated by URL with their tags merged.

### Changed

- The NVD client test now uses the real API 2.0 shape (an `AND` wrapper with a
  nested `OR` node) instead of a hand written shape that hid the defect.
- `internal/source/nvd/mapper_test.go` adds coverage for the real shape, the
  legacy shape, and end-to-end mapping through `mapVulnerability`.

### Operational note

- **Upgrading does not repair an existing database.** Records are keyed on
  `(id, source)` and an unchanged CVE is never re-fetched, so rows written by an
  earlier version keep their empty applicability. Re-run
  `cevrixa sync nvd --days N` (or `--full`), or delete the database file, to
  populate CPE criteria.

### Known gaps

- A hyphenated number such as `12.4.3-02854` is still read as a pre-release, so
  it sorts *before* `12.4.3`. Firmware and distro build numbers sort after. This
  needs per-ecosystem version semantics (dispatch on the PURL type), which is not
  implemented yet; the comparison is decidable but that ordering can be wrong.

## [v0.2.1] — 2026-09-30

Silent false negative in package matching, found during manual verification of
v0.2.0.

### Fixed

- **Package versions with a letter suffix were rejected, and that failure was
  swallowed.** Debian style upstream versions such as `openssl 1.1.1c` failed to
  parse, so `pkg:deb/debian/openssl@1.1.1c-1ubuntu1` returned zero findings with
  exit code 0 even though the version sits inside an affected range. The parser
  now accepts a trailing letter suffix as a post-release identifier
  (`1.1.1 < 1.1.1c < 1.1.2`), and a version that still cannot be compared is
  reported as `inconclusive` instead of being dropped.
- **`ParseDebian` and `ParseRPM` ordering was inverted.** Package revisions were
  attached as pre-release identifiers, so `2.4.7-1` sorted *below* `2.4.7` — the
  opposite of Debian and RPM ordering, and the opposite of what their own
  documentation claimed. Revisions and RPM releases are now post-release
  identifiers: `2.4.7 < 2.4.7-1 < 2.4.7-2` and `1.2.3 < 1.2.3-4.el8`.
- **A package whose ranges could not be evaluated was skipped in silence.** A
  range with unparseable bounds is now reported as `inconclusive` as well.

### Added

- `engine.PackageMatchResult.Undecided` and `Reason`.
- `version.Version` post-release identifiers, compared after the numeric core and
  the pre-release part.
- Regression tests for `openssl@1.1.1c-1ubuntu1` at matcher and engine level, and
  ordering tests for Debian revisions and RPM releases.

### Known gaps

- Version semantics are still not dispatched per ecosystem: a Debian PURL is
  compared with the generic parser instead of `ParseDebian`, so a version that
  combines a letter suffix with a `-` part (for example `1.1.1c-1ubuntu1`
  compared against a bound of exactly `1.1.1`) can still compare incorrectly.
  `ParseDebian` and `ParseRPM` remain unused outside their own tests.

## [v0.2.0] — 2026-09-30

Detection reliability. No new data sources were added: the goal of this release
is to make the answers Cevrixa already produces trustworthy.

### Fixed

- **False positives from NVD `AND` configurations.** Every child node and CPE
  match was evaluated as if the configuration were a flat `OR`, and the
  `operator` field was ignored entirely. A configuration that means "affected
  only when this other component is also present" was therefore reported as
  affected for the component alone. `AND` groups are now evaluated as
  requirements, and a configuration that cannot be satisfied from a single
  target is reported as `inconclusive` with the unmet requirement named. This is
  the same defect class as anchore/grype#1349.
- **`vulnerable: false` entries were dropped.** Inside an `AND` group they are
  requirements, so dropping them removed the constraint that made the
  configuration narrow.
- **`negate` was silently ignored.** `ApplicabilityNode.Negate` was parsed and
  stored but never evaluated, so a negated configuration was treated as an
  ordinary one. Negated nodes now produce `inconclusive` with a reason.
- **Versions pinned in a criteria string were ignored.** NVD criteria such as
  `cpe:2.3:a:django_project:django:0.91:*:*:*:*:*:*:*` carry the affected
  version inside the CPE. Only `part`, `vendor`, and `product` were compared, so
  the resulting unbounded range matched *every* version of the product. The
  pinned version is now compared and yields `exact` confidence.
- **`confidence` was inverted for exact criteria.** A criterion that pins a
  single version was classified `wildcard` (weak). It is now `exact`.
- **`explain` could report `NOT AFFECTED` without evaluating anything.**
  `--purl` never reached a matcher, because `resolver.Resolve` returns no CPE
  for a package-only target, so the decision fell through to "not affected". An
  unresolved identity and an unusable version behaved the same way, and the
  error from `matcher.MatchCPE` was discarded. All three now produce
  `INCONCLUSIVE` with the reason.
- **`explain` never explained a non-match.** `MatchCPE` returned an empty result
  on failure, so a version above the fixed boundary produced no range and no
  fixed version, and `BuildWhy` described every outcome as "in range".
- **Cross-source conflicts could never fire.** `detect` correlated a single
  vulnerability with `nil` enrichments, so conflict detection never saw two
  sources. Enrichments are now loaded and correlated, and a vulnerability's own
  `Risk` is part of the evidence set.
- **Vocabulary differences were reported as conflicts.** `MODERATE` and
  `medium` are the same severity, but conflict values were compared as raw
  strings. Values are normalised before comparison.
- **`--fail-on` failed open.** An unrecognised gate returned exit code 0
  without a word. Severity gates are now supported and unknown gates are
  rejected at parse time.
- **Store errors were swallowed.** A dataset that could not be read was
  silently replaced by embedded test fixtures. The error is now returned.

### Added

- `matcher.Result.Undecided` and `Result.Reason`, so an undecidable
  configuration is a first-class outcome rather than a silent non-match.
- `domain.FindingStatusInconclusive`, replacing the unused
  `FindingStatusConflict` status; conflicts remain evidence, not a status.
- `domain.DatasetInfo` on every `Report`: `store_records`, `fixture_records`,
  and `sources`. Human output labels embedded fixtures as `TEST DATA`.
- `domain.Why.Questions`, so an inconclusive answer can state what would resolve
  it.
- `store.ListEnrichments`, returning every enrichment for a vulnerability.
- `domain.ValidGate` and `domain.CanonicalSeverity`.

### Changed

- `buildFinding` and `buildPackageFinding` now take the enrichments to
  correlate, and map an undecidable result to `inconclusive`.
- `--fail-on` accepts `none`, `any`, `affected`, `inconclusive`, `kev`, and the
  severity labels `low`, `medium` (`moderate`), `high`, `critical`.
- Human output prints dataset coverage after the finding count, and prints the
  reason and open question for an inconclusive finding.

### Known gaps

- Zero-result outcomes are still not distinguished: a run that searched no data
  and a run that searched data and found nothing both report zero findings.
  Dataset coverage is reported, which is only a partial mitigation.
- Detection still loads every stored record and matches in memory; there is no
  candidate prefilter by vendor/product yet.
- `explain --purl` reports `inconclusive`, because package applicability is not
  evaluated on that path yet.

## [v0.1.0]

First milestone: version intelligence (CPE, PURL, SemVer, Debian, RPM),
NVD/OSV/KEV adapters, local SQLite store with `sync`, detection engine with
confidence scoring, `detect`/`scan`/`sbom`/`explain`/`info`/`doctor`, and
human/JSON/JSONL/SARIF output.
