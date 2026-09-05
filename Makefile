.DEFAULT_GOAL := help

GO ?= go
BINARY ?= bin/routeros-extract
VERSION ?= dev
LDFLAGS ?= -X main.version=$(VERSION)

.PHONY: help all build test vet fmt clean

help: ## Show all targets and build options (default)
	@printf 'Usage: make [target] [VARIABLE=value ...]\n\nTargets:\n'
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-8s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\nBuild options:\n  GO       Go executable (default: go)\n  BINARY   Output path (default: bin/routeros-extract)\n  VERSION  Embedded version (default: dev)\n  LDFLAGS  Linker flags (default: -X main.version=$$(VERSION))\n\nExamples:\n  make build VERSION=v0.1.0\n  GOOS=windows GOARCH=amd64 make build BINARY=bin/routeros-extract.exe\n'

all: build ## Build the CLI (alias for build)

build: ## Build the CLI binary
	mkdir -p $(dir $(BINARY))
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/routeros-extract

test: ## Test the project and both bundled Go modules
	$(GO) test ./...
	cd third_party/xz && $(GO) test ./...
	cd third_party/squashfs && $(GO) test ./...

vet: ## Vet the project and both bundled Go modules
	$(GO) vet ./...
	cd third_party/xz && $(GO) vet ./...
	cd third_party/squashfs && $(GO) vet ./...

fmt: ## Format Go source in the project and bundled modules
	gofmt -w cmd internal tools third_party/xz third_party/squashfs

clean: ## Remove the selected binary
	rm -f $(BINARY)
