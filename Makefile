# Development tasks for hostlint. Run `make help` to list them.

BINARY  := hostlint
MODULE  := github.com/with-developer/hostlint
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE    ?= $(shell git log -1 --format=%cI 2>/dev/null)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.version=$(VERSION) \
	-X $(MODULE)/internal/version.commit=$(COMMIT) \
	-X $(MODULE)/internal/version.date=$(DATE)

GOVULNCHECK_VERSION := v1.9.0

.DEFAULT_GOAL := help
.PHONY: help build test lint fmt tidy vuln clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-8s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build a static binary (cross-compile with GOOS=linux GOARCH=arm64)
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/hostlint

test: ## Run unit tests with the race detector
	go test -race ./...

lint: ## Run golangci-lint and check that go.mod is tidy
	golangci-lint run
	go mod tidy -diff

fmt: ## Format code
	golangci-lint fmt

tidy: ## Tidy go.mod and go.sum
	go mod tidy

vuln: ## Scan dependencies for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

clean: ## Remove build output
	rm -rf $(BINARY) dist/
