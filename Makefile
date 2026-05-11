.DEFAULT_GOAL := help

GO_IMAGE_BUILD    := golang:1.26-alpine
GO_IMAGE_TEST     := golang:1.26
LINT_IMAGE        := golangci/golangci-lint:v2.12.2-alpine
DOCKER_RUN        := docker run --rm -v "$(PWD)":/src -w /src
GO_RUN_BUILD      := $(DOCKER_RUN) -e CGO_ENABLED=0 $(GO_IMAGE_BUILD)
GO_RUN_TEST       := $(DOCKER_RUN) -e CGO_ENABLED=1 $(GO_IMAGE_TEST)
LINT_RUN          := $(DOCKER_RUN) $(LINT_IMAGE)

# Inject version from VERSION file (created on tagged releases) or fall back to "dev".
VERSION           := $(shell cat VERSION 2>/dev/null || echo dev)
LDFLAGS           := -s -w -buildid= -X main.version=$(VERSION)
BUILD_FLAGS       := -trimpath -ldflags "$(LDFLAGS)"

BINARY            := netbrain-beacon
PKG               := ./cmd/netbrain-beacon

.PHONY: help
help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: lint
lint: ## Run golangci-lint via Docker
	$(LINT_RUN) golangci-lint run --timeout 5m ./...

.PHONY: test
test: ## Run go test with race detector + coverage (uses golang:1.26 — needs CGo for -race)
	$(GO_RUN_TEST) sh -c 'go test -race -coverprofile=coverage.txt -covermode=atomic ./...'

.PHONY: test-short
test-short: ## Run unit tests only (alpine image, no -race, fast)
	$(GO_RUN_BUILD) go test -short ./...

.PHONY: coverage
coverage: test ## Generate coverage.html from last test run
	$(GO_RUN_TEST) sh -c 'go tool cover -html=coverage.txt -o coverage.html'

.PHONY: build
build: ## Build host-arch binary into ./bin
	$(GO_RUN_BUILD) sh -c 'mkdir -p bin && go build $(BUILD_FLAGS) -o bin/$(BINARY) $(PKG)'

.PHONY: build-linux
build-linux: ## Build linux/amd64 binary
	$(DOCKER_RUN) -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 $(GO_IMAGE) \
		sh -c 'mkdir -p bin && go build $(BUILD_FLAGS) -o bin/$(BINARY)-linux-amd64 $(PKG)'

.PHONY: build-windows
build-windows: ## Build windows/amd64 binary
	$(DOCKER_RUN) -e CGO_ENABLED=0 -e GOOS=windows -e GOARCH=amd64 $(GO_IMAGE) \
		sh -c 'mkdir -p bin && go build $(BUILD_FLAGS) -o bin/$(BINARY)-windows-amd64.exe $(PKG)'

.PHONY: build-all
build-all: build-linux build-windows ## Cross-compile linux + windows

.PHONY: docker-build
docker-build: ## Build the distroless Docker image
	docker build -t netbrain-beacon:$(VERSION) .

.PHONY: govulncheck
govulncheck: ## Scan for known vulnerable Go dependencies
	$(GO_RUN_BUILD) sh -c 'go install golang.org/x/vuln/cmd/govulncheck@latest && /go/bin/govulncheck ./...'

.PHONY: tidy
tidy: ## go mod tidy
	$(GO_RUN_BUILD) go mod tidy

OAPI_VERSION   := v2.5.0
NETBRAIN_SPEC  := ../netbrain/services/api-gateway/openapi/beacon-v1.yaml

.PHONY: generate
generate: ## Regenerate the OpenAPI client (internal/api/zz_generated.go)
	@test -f "$(NETBRAIN_SPEC)" || (echo "ERROR: spec not found at $(NETBRAIN_SPEC)"; exit 1)
	cp "$(NETBRAIN_SPEC)" internal/api/beacon-v1.yaml
	$(DOCKER_RUN) -e CGO_ENABLED=0 $(GO_IMAGE_BUILD) sh -c '\
		go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_VERSION) && \
		cd internal/api && /go/bin/oapi-codegen -config api-config.yaml beacon-v1.yaml'
	@echo "regenerated internal/api/zz_generated.go from $(NETBRAIN_SPEC)"

.PHONY: clean
clean: ## Remove build output
	rm -rf bin dist coverage.txt coverage.html

.PHONY: all
all: lint test build ## Lint + test + build (the CI-equivalent local check)
