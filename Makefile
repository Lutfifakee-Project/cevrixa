BINARY := cevrixa
PKG := ./cmd/cevrixa
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X 'github.com/Lutfifakee-Project/cevrixa/internal/cli.Version=$(VERSION)' \
           -X 'github.com/Lutfifakee-Project/cevrixa/internal/cli.Commit=$(COMMIT)' \
           -X 'github.com/Lutfifakee-Project/cevrixa/internal/cli.Date=$(DATE)'

.PHONY: build test vet fmt check clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

check: fmt test vet build

clean:
	rm -rf bin
