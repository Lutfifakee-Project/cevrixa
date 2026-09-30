# Contributing

## Commit messages

Cevrixa uses the Conventional Commits subset below. Write the summary in the
imperative mood, in lower case, without a trailing period.

    <type>: <summary>

    <optional body: why this change, not a restatement of the diff>

    <optional footer>

Allowed types:

| Type | Use for |
|---|---|
| `feat` | a new capability |
| `fix` | a defect |
| `perf` | a performance or accuracy gain |
| `refactor` | a behaviour preserving restructure |
| `docs` | documentation only |
| `test` | tests only |
| `build` | build, dependencies, release plumbing |
| `ci` | CI configuration |
| `chore` | anything else |

Examples:

    feat: add product resolver
    feat: add CPE resolution
    feat: add affected version matching
    feat: add fixed version detection

    fix: prevent duplicate findings
    fix: normalise package versions before comparison

    perf: index CPE criteria by vendor and product
    refactor: separate product resolution from detection
    docs: update detection architecture

When a change alters matching outcomes, say which detection stage it touches in
the summary or the body: product resolution, CPE resolution, affected matching,
fixed-version detection, or the finding model.

A commit should be one logical change and keep `make check` green.

## Changelog

`CHANGELOG.md` records Cevrixa's own changes and nothing else. Do not link to
external trackers and do not describe how a change was found: write what changed
and why it matters to someone using Cevrixa.

Each change is listed in exactly one section, chosen by what it affects:

- a matching or decision change belongs in **Detection**,
- a source, mapping, or store change belongs in **Database**,
- a change that stops Cevrixa from under-reporting belongs in **Security**,
- anything else uses Added, Changed, Improved, Fixed, Removed, or Breaking.

Release entries are cut from the commit log: take the commits since the previous
tag, group them into the sections above, and tag the release.

## Checks

    make check    # gofmt, vet, tests
    make build    # build bin/cevrixa with version metadata
