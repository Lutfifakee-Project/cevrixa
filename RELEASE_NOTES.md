## What's New in v1.0.3

Cevrixa v1.0.3 improves vulnerability applicability matching, CLI reporting, and on-demand CVE lookup.

### Highlights

- **More relevant matching:** improves candidate relevance so vulnerability configurations that do not identify the target as a vulnerable component are excluded where appropriate.
- **Fetch missing CVEs:** `explain` can query NVD when a requested CVE ID is missing from the local dataset. NVD no-record responses are distinguished from API and network failures.
- **Safer NVD sync windows:** `sync nvd --days` now enforces a maximum of 120 days per request.
- **Output to files:** `detect`, `scan`, and `explain` support writing reports to a file with `--output-file`.
- **Clearer human-readable results:** concise summaries are shown by default, with additional details available through `--verbose`.
- **Improved pipe handling:** avoids misleading write-error messages in tested broken-pipe scenarios, with platform-specific exit behavior documented.

### Downloads

Prebuilt binaries are available for:

- Linux: AMD64 and ARM64
- macOS: AMD64 and ARM64
- Windows: AMD64 and ARM64

`checksums.txt` contains SHA-256 checksums for the six binary artifacts.

### Important Notes

- Local vulnerability coverage depends on the data available in the local dataset. This release does not claim complete historical NVD coverage.
- On-demand CVE data fetched by `explain` is used for that execution and is not automatically persisted to the local database.
- `inconclusive` results must not be interpreted as `not_affected`.

See the [README](https://github.com/Lutfifakee-Project/cevrixa/blob/main/README.md) for installation and usage instructions.

**Full Changelog:** https://github.com/Lutfifakee-Project/cevrixa/compare/v1.0.2...v1.0.3
