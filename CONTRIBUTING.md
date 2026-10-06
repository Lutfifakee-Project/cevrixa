# Contributing

Thanks for helping improve Cevrixa. This guide is short on purpose.

## Setup

Cevrixa needs Go 1.27 or later.

bash
git clone https://github.com/Lutfifakee-Project/cevrixa
cd cevrixa
go build ./...


## Before you commit

Run the checks and keep them green:

bash
make check   # gofmt, go vet, tests


If you do not have make, run the same steps directly:

bash
go run scripts/fmtcheck.go
go vet ./...
go test ./... -count=1


## Commit messages

Use Conventional Commits, imperative mood, lower case, no trailing period:

text
<type>: <summary>

<optional body: why this change>


Allowed types:

| Type | Use for |
|---|---|
| feat | a new capability |
| fix | a defect |
| perf | a performance or accuracy gain |
| refactor | a behaviour-preserving restructure |
| docs | documentation only |
| test | tests only |
| build | build, dependencies, release plumbing |
| ci | CI configuration |
| chore | anything else |

One commit is one logical change. Do not put a version number in a commit
message; version numbers belong to tags and releases.

## Changelog

CHANGELOG.md records what changed and why it matters to a user. Add your
change under Unreleased, in the section that fits: Added, Changed, Improved,
Fixed, Security, Detection, Database, Removed, or Breaking.

When a release is cut, the Unreleased entries move under the new version and
the release is tagged.
