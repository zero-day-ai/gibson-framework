.PHONY: help install install-dev build binary test test-cov test-unit test-integration lint format check clean dev run docker-build docker-run

# Variables
PYTHON := python3
PIP := pip
PACKAGE_NAME := gibson
SRC_DIR := gibson
TEST_DIR := tests
BINARY_NAME := gibson
DIST_DIR := dist
VENV := venv

# Colors for output
CYAN := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m # No Color

help: ## Show this help message
	@echo '${CYAN}Usage:${NC}'
	@echo '  make ${GREEN}<target>${NC}'
	@echo ''
	@echo '${CYAN}Available targets:${NC}'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  ${GREEN}%-20s${NC} %s\n", $$1, $$2}'

install: ## Install production dependencies
	@echo "${CYAN}Installing production dependencies...${NC}"
	$(PIP) install -e .

install-dev: ## Install development dependencies
	@echo "${CYAN}Installing development dependencies...${NC}"
	$(PIP) install -e ".[dev]"
	$(PIP) install pytest pytest-cov pytest-asyncio black ruff mypy

build: ## Build distribution packages (wheel and sdist)
	@echo "${CYAN}Building distribution packages...${NC}"
	@echo "${CYAN}Checking schema synchronization...${NC}"
	@$(PYTHON) scripts/sync_schemas.py --dry-run --ci || (echo "${RED}Schema sync required before build${NC}" && exit 1)
	$(PIP) install --upgrade build
	$(PYTHON) -m build

binary: ## Build standalone binary using PyInstaller
	@echo "${CYAN}Building standalone binary...${NC}"
	@echo "${CYAN}Installing PyInstaller and compatible dependencies...${NC}"
	$(PIP) install pyinstaller
	@echo "${CYAN}Ensuring typer/click compatibility...${NC}"
	$(PIP) install --upgrade "typer==0.9.0" "click==8.1.7" "rich==13.7.0"
	@echo "${CYAN}Building with spec file...${NC}"
	pyinstaller gibson.spec --clean --noconfirm
	@echo "${GREEN}Binary created at: dist/$(BINARY_NAME)${NC}"

binary-simple: ## Build standalone binary with simple PyInstaller config
	@echo "${CYAN}Building standalone binary (simple mode)...${NC}"
	@echo "${CYAN}Installing dependencies...${NC}"
	$(PIP) install pyinstaller nuitka
	@echo "${CYAN}Creating binary with Nuitka...${NC}"
	python -m nuitka \
		--standalone \
		--onefile \
		--output-filename=$(BINARY_NAME) \
		--include-package=gibson \
		--include-package=typer \
		--include-package=rich \
		--include-package=click \
		--include-package=pydantic \
		--include-package=sqlalchemy \
		--include-package=aiosqlite \
		--include-data-dir=configs=configs \
		--assume-yes-for-downloads \
		gibson/main.py
	@echo "${GREEN}Binary created: $(BINARY_NAME)${NC}"

test: ## Run all tests
	@echo "${CYAN}Running all tests...${NC}"
	pytest $(TEST_DIR) -v

test-cov: ## Run tests with coverage report
	@echo "${CYAN}Running tests with coverage...${NC}"
	pytest $(TEST_DIR) \
		--cov=$(SRC_DIR) \
		--cov-report=term-missing \
		--cov-report=html \
		--cov-report=xml \
		-v
	@echo "${GREEN}Coverage report generated in htmlcov/index.html${NC}"

test-unit: ## Run unit tests only
	@echo "${CYAN}Running unit tests...${NC}"
	pytest $(TEST_DIR)/unit -v

test-integration: ## Run integration tests only
	@echo "${CYAN}Running integration tests...${NC}"
	pytest $(TEST_DIR)/integration -v

lint: ## Run linting (ruff + mypy)
	@echo "${CYAN}Running ruff linter...${NC}"
	ruff check $(SRC_DIR) $(TEST_DIR)
	@echo "${CYAN}Running mypy type checker...${NC}"
	mypy $(SRC_DIR)

format: ## Format code (black + ruff)
	@echo "${CYAN}Formatting with black...${NC}"
	black $(SRC_DIR) $(TEST_DIR)
	@echo "${CYAN}Fixing with ruff...${NC}"
	ruff check --fix $(SRC_DIR) $(TEST_DIR)

check: ## Run all checks (lint + test)
	@echo "${CYAN}Running all checks...${NC}"
	@$(MAKE) lint
	@$(MAKE) test

clean: ## Clean build artifacts and cache
	@echo "${CYAN}Cleaning build artifacts...${NC}"
	rm -rf $(DIST_DIR)
	rm -rf build/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache
	rm -rf .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "${GREEN}Cleaned!${NC}"

dev: ## Run in development mode
	@echo "${CYAN}Running in development mode...${NC}"
	$(PYTHON) -m $(PACKAGE_NAME).main

run: ## Run the application
	@echo "${CYAN}Running Gibson...${NC}"
	$(PYTHON) -m $(PACKAGE_NAME).main

docker-build: ## Build Docker image
	@echo "${CYAN}Building Docker image...${NC}"
	docker build -t $(PACKAGE_NAME):latest .

docker-run: ## Run Docker container
	@echo "${CYAN}Running Docker container...${NC}"
	docker run -it --rm $(PACKAGE_NAME):latest

# Database migration targets
migrate: ## Apply pending database migrations
	@echo "${CYAN}Applying database migrations...${NC}"
	$(PYTHON) -m $(PACKAGE_NAME).main database migrate

migration-status: ## Check migration status
	@echo "${CYAN}Checking migration status...${NC}"
	$(PYTHON) -m $(PACKAGE_NAME).main database status

migration-create: ## Create new migration from model changes
	@echo "${CYAN}Creating migration from model changes...${NC}"
	@read -p "Enter migration message: " msg; \
	$(PYTHON) scripts/auto_migrate.py "$$msg"

migration-check: ## Check if migrations are needed
	@echo "${CYAN}Checking for pending migrations...${NC}"
	@$(PYTHON) scripts/check_migrations.py

migration-rollback: ## Rollback last migration
	@echo "${CYAN}Rolling back last migration...${NC}"
	$(PYTHON) -m $(PACKAGE_NAME).main database rollback 1

db-backup: ## Create database backup
	@echo "${CYAN}Creating database backup...${NC}"
	$(PYTHON) -m $(PACKAGE_NAME).main database backup

db-init: ## Initialize database
	@echo "${CYAN}Initializing database...${NC}"
	$(PYTHON) -m $(PACKAGE_NAME).main database init

# Development shortcuts
fmt: format ## Alias for format
cov: test-cov ## Alias for test-cov

# Installation verification
verify: ## Verify installation and run smoke tests
	@echo "${CYAN}Verifying installation...${NC}"
	$(PYTHON) -c "import gibson; print('Gibson imported successfully')"
	$(PYTHON) -m gibson --version || echo "Gibson CLI not yet installed"
	@echo "${GREEN}Installation verified!${NC}"

# Update dependencies
update: ## Update dependencies to latest versions
	@echo "${CYAN}Updating dependencies...${NC}"
	$(PIP) install --upgrade pip
	$(PIP) install --upgrade -e ".[dev]"
	@echo "${GREEN}Dependencies updated!${NC}"

# Security check
security: ## Check for security vulnerabilities
	@echo "${CYAN}Checking for security vulnerabilities...${NC}"
	$(PIP) install pip-audit bandit
	pip-audit || true
	bandit -r $(SRC_DIR) || true

# Generate requirements files
requirements: ## Generate requirements.txt files
	@echo "${CYAN}Generating requirements files...${NC}"
	$(PIP) freeze > requirements.txt
	@echo "${GREEN}Requirements file generated!${NC}"

# Schema synchronization
sync-schemas: ## Synchronize database schemas with PayloadModel
	@echo "${CYAN}Synchronizing database schemas...${NC}"
	$(PYTHON) scripts/sync_schemas.py
	@echo "${GREEN}Schema synchronization complete!${NC}"

check-schemas: ## Check if schemas are in sync
	@echo "${CYAN}Checking schema synchronization...${NC}"
	$(PYTHON) scripts/sync_schemas.py --dry-run
	@echo "${GREEN}Schema check complete!${NC}"

generate-schemas: ## Generate all schema formats (JSON, TypeScript, etc.)
	@echo "${CYAN}Generating schemas...${NC}"
	$(PYTHON) -m gibson.cli.main schema generate
	@echo "${GREEN}Schemas generated!${NC}"

schema-sync-force: ## Force schema sync even with breaking changes
	@echo "${YELLOW}WARNING: Forcing schema sync with breaking changes...${NC}"
	$(PYTHON) scripts/sync_schemas.py --force
	@echo "${GREEN}Schema synchronization complete!${NC}"

schema-history: ## Show schema migration history
	@echo "${CYAN}Schema migration history:${NC}"
	$(PYTHON) -m gibson.cli.main schema history

schema-version: ## Show current schema version
	@echo "${CYAN}Current schema version:${NC}"
	$(PYTHON) -m gibson.cli.main schema version

# Virtual environment management
venv: ## Create virtual environment
	@echo "${CYAN}Creating virtual environment...${NC}"
	$(PYTHON) -m venv $(VENV)
	@echo "${GREEN}Virtual environment created! Activate with: source $(VENV)/bin/activate${NC}"

venv-clean: ## Remove virtual environment
	@echo "${CYAN}Removing virtual environment...${NC}"
	rm -rf $(VENV)
	@echo "${GREEN}Virtual environment removed!${NC}"