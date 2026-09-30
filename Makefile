BINARY  := cevrixa
PKG     := ./cmd/cevrixa
VERSION ?= v0.2.1
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X 'github.com/Lutfifakee-Project/cevrixa/internal/cli.Version=$(VERSION)' \
           -X 'github.com/Lutfifakee-Project/cevrixa/internal/cli.Commit=$(COMMIT)' \
           -X 'github.com/Lutfifakee-Project/cevrixa/internal/cli.Date=$(DATE)'

.PHONY: build test test-race vet fmt fmt-check check clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test ./... -count=1

test-race:
	go test -race ./... -count=1

vet:
	go vet ./...

fmt:
	gofmt -s -w .

fmt-check:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

check: fmt-check vet test

clean:
	rm -rf bin
