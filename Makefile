# Development tasks for vmsctl. Run `make help` to list them.

BINARY := vmsctl
MODULE := $(shell go list -m)

# Version stamp. Release builds get it from the tag; anything else is a dev build.
GIT_DIRTY := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo -dirty)
VERSION := $(shell git describe --tags --always 2>/dev/null || echo dev)$(GIT_DIRTY)
COMMIT := $(shell git rev-parse HEAD 2>/dev/null)
DATE := $(shell TZ=UTC git log -1 --no-show-signature --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd 2>/dev/null)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.version=$(VERSION) \
	-X $(MODULE)/internal/version.commit=$(COMMIT) \
	-X $(MODULE)/internal/version.date=$(DATE)

# Tools are built from source with the current Go toolchain, so they always
# understand the Go version in use. One version pin each, used locally and in CI.
TOOLS := $(CURDIR)/.tools
GOLANGCI_LINT_VERSION := v2.15.0
GOLANGCI_LINT := $(TOOLS)/golangci-lint-$(GOLANGCI_LINT_VERSION)
GOVULNCHECK_VERSION := v1.9.0
GORELEASER_VERSION := v2.18.3
GORELEASER := $(TOOLS)/goreleaser-$(GORELEASER_VERSION)
# Steps a snapshot skips: signing needs the release workflow's identity, and
# SBOMs need syft (CI installs it; locally use SNAPSHOT_SKIP=sign,sbom).
SNAPSHOT_SKIP ?= sign

.DEFAULT_GOAL := help
.PHONY: help build build-web web demo-site test lint lint-guards fmt tidy vuln snapshot docs e2e clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z0-9-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build ./vmsctl (static on Linux; cross-compile with GOOS=linux GOARCH=arm64)
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/vmsctl

web: ## Build the dashboard into internal/server/webdist (needs Node 22)
	cd web && npm ci --ignore-scripts && npm run build

build-web: web ## Build ./vmsctl with the dashboard embedded in `vmsctl server`
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -tags web -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/vmsctl

demo-site: build ## Build the static live demo into site/demo (the dashboard with recorded answers of `vmsctl server demo`)
	./scripts/build-demo.sh

test: ## Run unit tests with the race detector
	go test -race ./...

# Lint as linux/amd64 everywhere, so a laptop and CI see the same code.
LINT_ENV := GOOS=linux GOARCH=amd64

lint: $(GOLANGCI_LINT) lint-guards ## Lint for linux/amd64 (incl. ADR 0004 guards) and check go.mod is tidy
	$(LINT_ENV) $(GOLANGCI_LINT) run
	go mod tidy -diff

lint-guards: $(GOLANGCI_LINT) ## Prove the ADR 0004 lint guards fire
	$(LINT_ENV) ./scripts/lint-guards.sh $(GOLANGCI_LINT)

fmt: $(GOLANGCI_LINT) ## Format code
	$(GOLANGCI_LINT) fmt

tidy: ## Tidy go.mod and go.sum
	go mod tidy

vuln: ## Scan dependencies for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

snapshot: $(GORELEASER) ## Build the release artifacts into dist/ without publishing (docs/RELEASING.md)
	$(GORELEASER) release --snapshot --clean --skip=$(SNAPSHOT_SKIP)

docs: ## Regenerate docs/rules.md and docs/facts.md from rules/, profiles/ and the collectors
	go test ./internal/rulesdoc -run 'TestRulesDocIsUpToDate|TestRulesKoDocIsUpToDate|TestKISASiteKoIsUpToDate|TestFactsDocIsUpToDate' -update

# E2E_RUN selects distributions (e.g. debian-12); E2E_UPDATE=1 rewrites their goldens.
E2E_RUN ?=
E2E_UPDATE ?=

e2e: ## Scan every supported distribution in Docker, stock and hardened, against e2e/testdata
	cd e2e && go test -tags e2e -count=1 -timeout 60m $(if $(E2E_RUN),-run 'TestE2E/$(E2E_RUN)-') $(if $(E2E_UPDATE),-update) .

clean: ## Remove build output and downloaded tools
	rm -rf $(BINARY) dist/ $(TOOLS)

$(GOLANGCI_LINT):
	GOBIN=$(TOOLS)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	mv $(TOOLS)/bin/golangci-lint $@

$(GORELEASER):
	GOBIN=$(TOOLS)/bin go install github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)
	mv $(TOOLS)/bin/goreleaser $@
