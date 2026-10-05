BINARY  := cevrixa
PKG     := ./cmd/cevrixa
VERSION ?= v0.7.0
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)

LDFLAGS := -X 'github.com/Lutfifakee-Project/cevrixa/internal/cli.Version=$(VERSION)' -X 'github.com/Lutfifakee-Project/cevrixa/internal/cli.Commit=$(COMMIT)' -X 'github.com/Lutfifakee-Project/cevrixa/internal/cli.Date=$(DATE)'

.PHONY: build build-all test test-race vet fmt fmt-check check clean

# Build for the host platform.
build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

# Cross-compile every supported platform (linux/darwin/windows, amd64/arm64).
# Runs on any OS; it does not require a Unix shell.
build-all:
	go run scripts/build.go --all --out bin

test:
	go test ./... -count=1

test-race:
	go test -race ./... -count=1

vet:
	go vet ./...

fmt:
	gofmt -s -w .

# Portable gofmt check; does not rely on a Unix shell.
fmt-check:
	go run scripts/fmtcheck.go

check: fmt-check vet test

clean:
	rm -rf bin
