# Gibson Framework Makefile
# Following k9s patterns for comprehensive testing and build automation

.PHONY: help build test test-unit test-integration test-e2e test-coverage test-short test-all
.PHONY: lint lint-fix fmt vet security deps-check
.PHONY: clean install uninstall
.PHONY: docker docker-build docker-test
.PHONY: ci release release-local
.PHONY: deb rpm homebrew
.PHONY: package package-all
.PHONY: checksums sign-checksums
.PHONY: docs docs-api docs-generate
.PHONY: generate-schema sdk-test sdk-update

# Default target
.DEFAULT_GOAL := help

# Variables
BINARY_NAME := gibson
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT_SHA ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GO_VERSION ?= $(shell go version | cut -d' ' -f3)

# Directories
BUILD_DIR := build
COVERAGE_DIR := coverage
REPORTS_DIR := reports
DIST_DIR := dist
PACKAGE_DIR := packages
DOCS_DIR := docs

# Go build flags
LDFLAGS := -X main.version=$(VERSION) \
           -X main.commit=$(COMMIT_SHA) \
           -X main.buildDate=$(BUILD_DATE) \
           -X main.goVersion=$(GO_VERSION)

# Test flags
TEST_FLAGS := -race -v
INTEGRATION_FLAGS := -tags=integration
E2E_FLAGS := -tags=e2e
COVERAGE_FLAGS := -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic
COVERAGE_THRESHOLD := 70

## help: Show this help message
help:
	@echo "Gibson Framework - Build and Test Commands"
	@echo ""
	@echo "Build Commands:"
	@echo "  build          Build the gibson binary"
	@echo "  build-all      Build binaries for all platforms"
	@echo "  install        Build and install gibson binary to GOPATH/bin"
	@echo "  clean          Clean build artifacts"
	@echo ""
	@echo "Test Commands:"
	@echo "  test           Run all tests with reasonable defaults"
	@echo "  test-unit      Run unit tests only"
	@echo "  test-integration  Run integration tests"
	@echo "  test-e2e       Run end-to-end tests"
	@echo "  test-short     Run quick tests (for development)"
	@echo "  test-coverage  Run tests with coverage report"
	@echo "  test-all       Run all test suites"
	@echo ""
	@echo "Quality Commands:"
	@echo "  fmt            Format code with gofmt and goimports"
	@echo "  lint           Run comprehensive linting"
	@echo "  lint-fix       Run linting with auto-fix where possible"
	@echo "  vet            Run go vet"
	@echo "  security       Run security analysis with gosec"
	@echo ""
	@echo "CI Commands:"
	@echo "  ci             Run complete CI pipeline"
	@echo "  deps-check     Check for dependency issues"
	@echo ""
	@echo "Release Commands:"
	@echo "  release        Create complete release with all artifacts"
	@echo "  release-local  Create local release for testing"
	@echo "  checksums      Generate checksums for release artifacts"
	@echo "  sign-checksums Sign checksums with GPG"
	@echo ""
	@echo "Package Commands:"
	@echo "  package-all    Create all distribution packages"
	@echo "  deb            Create Debian package"
	@echo "  rpm            Create RPM package"
	@echo "  homebrew       Generate Homebrew formula"
	@echo ""
	@echo "Documentation Commands:"
	@echo "  docs           Build all documentation"
	@echo "  docs-generate  Generate API documentation"
	@echo ""
	@echo "Schema Commands:"
	@echo "  generate-schema  Generate JSON Schema from PayloadDB struct"
	@echo ""
	@echo "SDK Commands:"
	@echo "  sdk-test       Test SDK integration"
	@echo "  sdk-update     Update SDK dependency"
	@echo ""
	@echo "Docker Commands:"
	@echo "  docker-build   Build Docker image"
	@echo "  docker-test    Run tests in Docker container"
	@echo ""

## build: Build the gibson binary
build:
	@echo "Building gibson binary..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./main.go
	@echo "✓ Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

## build-all: Build binaries for all platforms
build-all: clean
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	@# Linux AMD64
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./main.go
	@# Linux ARM64
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./main.go
	@# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./main.go
	@# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./main.go
	@# Windows AMD64
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./main.go
	@echo "✓ Multi-platform build complete"
	@ls -la $(BUILD_DIR)

## install: Build and install gibson binary to GOPATH/bin
install:
	@echo "Installing gibson..."
	go install -ldflags "$(LDFLAGS)" ./main.go
	@echo "✓ gibson installed to $(shell go env GOPATH)/bin/gibson"

## test: Run all tests with reasonable defaults (unit + integration)
test: setup-test-dirs
	@echo "Running unit and integration tests..."
	go test $(TEST_FLAGS) $(COVERAGE_FLAGS) ./...
	go test $(TEST_FLAGS) $(INTEGRATION_FLAGS) ./...
	@echo "✓ Tests completed"

## test-unit: Run unit tests only
test-unit: setup-test-dirs
	@echo "Running unit tests..."
	go test $(TEST_FLAGS) $(COVERAGE_FLAGS) ./internal/model ./internal/plugin ./internal/watch ./internal/pool
	@echo "✓ Unit tests completed"

## test-integration: Run integration tests with build tags
test-integration: setup-test-dirs
	@echo "Running integration tests..."
	go test $(TEST_FLAGS) $(INTEGRATION_FLAGS) -timeout=5m ./internal/...
	@echo "✓ Integration tests completed"

## test-e2e: Run end-to-end tests
test-e2e: build setup-test-dirs
	@echo "Running end-to-end tests..."
	go test $(TEST_FLAGS) $(E2E_FLAGS) -timeout=10m ./tests/e2e/...
	@echo "✓ E2E tests completed"

## test-short: Run quick tests for development
test-short: setup-test-dirs
	@echo "Running short tests..."
	go test -short $(TEST_FLAGS) ./...
	@echo "✓ Short tests completed"

## test-coverage: Generate and display test coverage report
test-coverage: setup-test-dirs
	@echo "Running tests with coverage..."
	go test $(TEST_FLAGS) $(COVERAGE_FLAGS) ./...
	go tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	go tool cover -func=$(COVERAGE_DIR)/coverage.out | tail -1
	@echo "Coverage report: $(COVERAGE_DIR)/coverage.html"
	@# Check coverage threshold
	@coverage=$$(go tool cover -func=$(COVERAGE_DIR)/coverage.out | tail -1 | awk '{print $$3}' | sed 's/%//'); \
	if [ "$$(echo "$$coverage < $(COVERAGE_THRESHOLD)" | bc -l)" -eq 1 ]; then \
		echo "❌ Coverage $$coverage% is below threshold $(COVERAGE_THRESHOLD)%"; \
		exit 1; \
	else \
		echo "✓ Coverage $$coverage% meets threshold $(COVERAGE_THRESHOLD)%"; \
	fi

## test-all: Run all test suites (unit, integration, e2e)
test-all: test-unit test-integration test-e2e
	@echo "✓ All test suites completed"

## fmt: Format code with gofmt and goimports
fmt:
	@echo "Formatting code..."
	@# Install goimports if not present
	@which goimports > /dev/null || go install golang.org/x/tools/cmd/goimports@latest
	@# Format with gofmt
	gofmt -s -w .
	@# Organize imports with goimports
	goimports -w .
	@echo "✓ Code formatted"

## vet: Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...
	@echo "✓ Vet completed"

## lint: Run comprehensive linting with golangci-lint
lint:
	@echo "Running linting..."
	@# Install golangci-lint if not present
	@which golangci-lint > /dev/null || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin latest
	golangci-lint run --config .golangci.yml --timeout=5m
	@echo "✓ Linting completed"

## lint-fix: Run linting with auto-fix where possible
lint-fix:
	@echo "Running linting with auto-fix..."
	@which golangci-lint > /dev/null || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin latest
	golangci-lint run --config .golangci.yml --fix --timeout=5m
	@echo "✓ Linting with auto-fix completed"

## security: Run security analysis with gosec
security: setup-test-dirs
	@echo "Running security analysis..."
	@# Install gosec if not present
	@which gosec > /dev/null || go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	gosec -fmt json -out $(REPORTS_DIR)/security.json ./...
	gosec ./...
	@echo "✓ Security analysis completed"
	@echo "Security report: $(REPORTS_DIR)/security.json"

## deps-check: Check for dependency issues
deps-check:
	@echo "Checking dependencies..."
	@# Check for unused dependencies
	go mod tidy
	@# Verify dependencies
	go mod verify
	@# Check for known vulnerabilities
	@which govulncheck > /dev/null || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...
	@echo "✓ Dependency check completed"

## ci: Run complete CI pipeline
ci: fmt vet lint test-coverage security deps-check sdk-test
	@echo "✓ CI pipeline completed successfully"

## clean: Clean build artifacts and test outputs
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(COVERAGE_DIR)
	rm -rf $(REPORTS_DIR)
	rm -rf $(DIST_DIR)
	rm -rf $(PACKAGE_DIR)
	rm -rf $(DOCS_DIR)/api
	go clean -cache -testcache -modcache
	@echo "✓ Clean completed"

## uninstall: Remove gibson binary from GOPATH/bin
uninstall:
	@echo "Uninstalling gibson..."
	rm -f $(shell go env GOPATH)/bin/gibson
	@echo "✓ gibson uninstalled"

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t gibson:$(VERSION) .
	docker tag gibson:$(VERSION) gibson:latest
	@echo "✓ Docker image built: gibson:$(VERSION)"

## docker-test: Run tests in Docker container
docker-test:
	@echo "Running tests in Docker..."
	docker run --rm -v $(PWD):/workspace -w /workspace golang:1.24 make test
	@echo "✓ Docker tests completed"

## release: Create a complete release with all artifacts
release: clean test-all build-all package-all checksums
	@echo "✓ Complete release created successfully"
	@echo "Release artifacts:"
	@ls -la $(DIST_DIR)/

## release-local: Create a local release for testing
release-local: clean test-short build-all
	@echo "Creating local release artifacts..."
	@mkdir -p $(DIST_DIR)
	@cd $(BUILD_DIR) && \
		for binary in gibson-*; do \
			if [[ $$binary == *.exe ]]; then \
				zip -r ../$(DIST_DIR)/$${binary%.exe}.zip $$binary; \
			else \
				tar -czf ../$(DIST_DIR)/$$binary.tar.gz $$binary; \
			fi; \
		done
	@echo "✓ Local release artifacts created in $(DIST_DIR)/"
	@ls -la $(DIST_DIR)/

## package-all: Create all distribution packages
package-all: deb rpm
	@echo "✓ All packages created"

## deb: Create Debian package
deb: build
	@echo "Creating Debian package..."
	@mkdir -p $(PACKAGE_DIR)/deb/gibson_$(VERSION)/DEBIAN
	@mkdir -p $(PACKAGE_DIR)/deb/gibson_$(VERSION)/usr/bin
	@mkdir -p $(PACKAGE_DIR)/deb/gibson_$(VERSION)/etc/gibson
	@mkdir -p $(PACKAGE_DIR)/deb/gibson_$(VERSION)/usr/share/doc/gibson
	@mkdir -p $(PACKAGE_DIR)/deb/gibson_$(VERSION)/etc/systemd/system
	@# Copy binary
	@cp $(BUILD_DIR)/gibson-linux-amd64 $(PACKAGE_DIR)/deb/gibson_$(VERSION)/usr/bin/gibson
	@chmod +x $(PACKAGE_DIR)/deb/gibson_$(VERSION)/usr/bin/gibson
	@# Create control file
	@echo "Package: gibson" > $(PACKAGE_DIR)/deb/gibson_$(VERSION)/DEBIAN/control
	@echo "Version: $(VERSION)" >> $(PACKAGE_DIR)/deb/gibson_$(VERSION)/DEBIAN/control
	@echo "Section: utils" >> $(PACKAGE_DIR)/deb/gibson_$(VERSION)/DEBIAN/control
	@echo "Priority: optional" >> $(PACKAGE_DIR)/deb/gibson_$(VERSION)/DEBIAN/control
	@echo "Architecture: amd64" >> $(PACKAGE_DIR)/deb/gibson_$(VERSION)/DEBIAN/control
	@echo "Maintainer: Gibson Security Team <gibson@example.com>" >> $(PACKAGE_DIR)/deb/gibson_$(VERSION)/DEBIAN/control
	@echo "Description: Gibson Framework - AI/ML Security Testing CLI" >> $(PACKAGE_DIR)/deb/gibson_$(VERSION)/DEBIAN/control
	@echo " A comprehensive security testing framework for AI/ML systems" >> $(PACKAGE_DIR)/deb/gibson_$(VERSION)/DEBIAN/control
	@echo " with plugin-based architecture and automated scanning capabilities." >> $(PACKAGE_DIR)/deb/gibson_$(VERSION)/DEBIAN/control
	@# Copy documentation
	@cp README.md $(PACKAGE_DIR)/deb/gibson_$(VERSION)/usr/share/doc/gibson/
	@# Copy systemd service if exists
	@if [ -f scripts/gibson.service ]; then \
		cp scripts/gibson.service $(PACKAGE_DIR)/deb/gibson_$(VERSION)/etc/systemd/system/; \
	fi
	@# Build package
	@mkdir -p $(DIST_DIR)
	@dpkg-deb --build $(PACKAGE_DIR)/deb/gibson_$(VERSION) $(DIST_DIR)/gibson_$(VERSION)_amd64.deb
	@echo "✓ Debian package created: $(DIST_DIR)/gibson_$(VERSION)_amd64.deb"

## rpm: Create RPM package
rpm: build
	@echo "Creating RPM package..."
	@mkdir -p $(PACKAGE_DIR)/rpm/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	@mkdir -p $(PACKAGE_DIR)/rpm/BUILD/gibson-$(VERSION)/usr/bin
	@mkdir -p $(PACKAGE_DIR)/rpm/BUILD/gibson-$(VERSION)/etc/gibson
	@mkdir -p $(PACKAGE_DIR)/rpm/BUILD/gibson-$(VERSION)/usr/share/doc/gibson
	@mkdir -p $(PACKAGE_DIR)/rpm/BUILD/gibson-$(VERSION)/etc/systemd/system
	@# Copy binary
	@cp $(BUILD_DIR)/gibson-linux-amd64 $(PACKAGE_DIR)/rpm/BUILD/gibson-$(VERSION)/usr/bin/gibson
	@chmod +x $(PACKAGE_DIR)/rpm/BUILD/gibson-$(VERSION)/usr/bin/gibson
	@# Copy documentation
	@cp README.md $(PACKAGE_DIR)/rpm/BUILD/gibson-$(VERSION)/usr/share/doc/gibson/
	@# Copy systemd service if exists
	@if [ -f scripts/gibson.service ]; then \
		cp scripts/gibson.service $(PACKAGE_DIR)/rpm/BUILD/gibson-$(VERSION)/etc/systemd/system/; \
	fi
	@# Create spec file
	@echo "Name: gibson" > $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "Version: $(VERSION)" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "Release: 1" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "Summary: Gibson Framework - AI/ML Security Testing CLI" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "License: MIT" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "Group: Applications/System" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "BuildArch: x86_64" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "%description" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "A comprehensive security testing framework for AI/ML systems" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "with plugin-based architecture and automated scanning capabilities." >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "%files" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "/usr/bin/gibson" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@echo "/usr/share/doc/gibson/README.md" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec
	@if [ -f scripts/gibson.service ]; then \
		echo "/etc/systemd/system/gibson.service" >> $(PACKAGE_DIR)/rpm/SPECS/gibson.spec; \
	fi
	@# Create tarball for rpmbuild
	@cd $(PACKAGE_DIR)/rpm/BUILD && tar -czf ../SOURCES/gibson-$(VERSION).tar.gz gibson-$(VERSION)
	@# Build RPM (requires rpmbuild, will skip if not available)
	@if command -v rpmbuild >/dev/null 2>&1; then \
		rpmbuild --define "_topdir $(PWD)/$(PACKAGE_DIR)/rpm" -bb $(PACKAGE_DIR)/rpm/SPECS/gibson.spec; \
		mkdir -p $(DIST_DIR); \
		cp $(PACKAGE_DIR)/rpm/RPMS/x86_64/gibson-$(VERSION)-1.x86_64.rpm $(DIST_DIR)/; \
		echo "✓ RPM package created: $(DIST_DIR)/gibson-$(VERSION)-1.x86_64.rpm"; \
	else \
		echo "⚠ rpmbuild not available, skipping RPM creation"; \
	fi

## checksums: Generate checksums for all release artifacts
checksums:
	@echo "Generating checksums..."
	@mkdir -p $(DIST_DIR)
	@if [ -d $(DIST_DIR) ] && [ "$$(ls -A $(DIST_DIR))" ]; then \
		cd $(DIST_DIR) && \
		for file in *; do \
			if [ -f "$$file" ] && [ "$$file" != "checksums.txt" ] && [ "$$file" != "checksums.sha256" ]; then \
				sha256sum "$$file" >> checksums.sha256; \
			fi; \
		done && \
		echo "✓ Checksums generated in $(DIST_DIR)/checksums.sha256"; \
	else \
		echo "No files to checksum in $(DIST_DIR)"; \
	fi

## sign-checksums: Sign checksums (requires GPG key)
sign-checksums: checksums
	@echo "Signing checksums..."
	@if [ -f $(DIST_DIR)/checksums.sha256 ] && command -v gpg >/dev/null 2>&1; then \
		cd $(DIST_DIR) && \
		gpg --detach-sign --armor checksums.sha256 && \
		echo "✓ Checksums signed: $(DIST_DIR)/checksums.sha256.asc"; \
	else \
		echo "⚠ GPG not available or no checksums to sign"; \
	fi

## homebrew: Generate Homebrew formula
homebrew:
	@echo "Generating Homebrew formula..."
	@mkdir -p $(DIST_DIR)
	@if [ -f $(DIST_DIR)/gibson-darwin-amd64.tar.gz ] && [ -f $(DIST_DIR)/gibson-darwin-arm64.tar.gz ]; then \
		DARWIN_AMD64_SHA=$$(sha256sum $(DIST_DIR)/gibson-darwin-amd64.tar.gz | cut -d' ' -f1); \
		DARWIN_ARM64_SHA=$$(sha256sum $(DIST_DIR)/gibson-darwin-arm64.tar.gz | cut -d' ' -f1); \
		sed -e "s/{{VERSION}}/$(VERSION)/g" \
		    -e "s/{{DARWIN_AMD64_SHA}}/$$DARWIN_AMD64_SHA/g" \
		    -e "s/{{DARWIN_ARM64_SHA}}/$$DARWIN_ARM64_SHA/g" \
		    scripts/gibson.rb.template > $(DIST_DIR)/gibson.rb; \
		echo "✓ Homebrew formula generated: $(DIST_DIR)/gibson.rb"; \
	else \
		echo "⚠ Darwin binaries not found, cannot generate Homebrew formula"; \
	fi

## docs-generate: Generate API documentation
docs-generate:
	@echo "Generating API documentation..."
	@mkdir -p $(DOCS_DIR)/api
	@# Generate Go docs
	@go doc -all ./... > $(DOCS_DIR)/api/go-docs.txt
	@# Generate package documentation
	@if command -v godoc >/dev/null 2>&1; then \
		echo "Godoc available, generating HTML docs..."; \
		godoc -http=:6060 & \
		GODOC_PID=$$!; \
		sleep 3; \
		curl -s http://localhost:6060/pkg/github.com/gibson-sec/gibson-framework-2/ > $(DOCS_DIR)/api/index.html || true; \
		kill $$GODOC_PID 2>/dev/null || true; \
	fi
	@echo "✓ API documentation generated in $(DOCS_DIR)/api/"

## docs: Build all documentation
docs: docs-generate
	@echo "Building complete documentation..."
	@# This would typically run a documentation generator like GitBook, Sphinx, etc.
	@echo "✓ Documentation build completed"

# Internal targets
setup-test-dirs:
	@mkdir -p $(COVERAGE_DIR) $(REPORTS_DIR)

# Check if required tools are installed
check-tools:
	@echo "Checking required tools..."
	@which go > /dev/null || (echo "Go is not installed" && exit 1)
	@echo "Go version: $(GO_VERSION)"

# Development helpers
dev-setup: check-tools
	@echo "Setting up development environment..."
	go mod download
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "✓ Development environment ready"

# Quick development cycle
dev: fmt vet test-short build
	@echo "✓ Development cycle completed"

# Continuous testing (watches for changes)
watch-test:
	@echo "Starting continuous testing (Ctrl+C to stop)..."
	@which fswatch > /dev/null || (echo "Please install fswatch for watch functionality" && exit 1)
	fswatch -o . | xargs -n1 -I{} make test-short

## generate-schema: Generate JSON Schema from PayloadDB struct
generate-schema:
	@echo "Generating JSON Schema from PayloadDB struct..."
	@go run ./cmd/tools/schema-generator/main.go ./cmd/tools/schema-generator/parser.go ./cmd/tools/schema-generator/mapper.go ./cmd/tools/schema-generator/version.go
	@if [ -f schemas/payload_schema.json ]; then \
		echo "✓ Schema generated at schemas/payload_schema.json"; \
		echo "✓ Schema version: $$(cat schemas/payload_schema.json | grep '"version"' | head -1 | sed 's/.*"version": *"\([^"]*\)".*/\1/')"; \
	else \
		echo "✗ Schema generation failed"; \
		exit 1; \
	fi

## sdk-test: Test SDK integration
sdk-test:
	@echo "Testing SDK integration..."
	@# Test that SDK modules can be imported
	@go list -m github.com/zero-day-ai/gibson-sdk
	@# Run basic compilation test
	@go build -o /tmp/gibson-test ./main.go
	@rm -f /tmp/gibson-test
	@echo "✓ SDK integration test completed"

## sdk-update: Update SDK dependency to latest version
sdk-update:
	@echo "Updating SDK dependency..."
	@go get -u github.com/zero-day-ai/gibson-sdk
	@go mod tidy
	@echo "✓ SDK dependency updated"

.PHONY: setup-test-dirs check-tools dev-setup dev watch-test generate-schema sdk-test sdk-update