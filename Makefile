.PHONY: help install install-dev format lint typecheck test test-slow test-all test-cov \
        css build publish tag clean docker-up docker-down docker-logs \
        docker-release run version

# Project paths
SRC := src/authmcp_gateway
TESTS := tests
TESTS_UNIT := tests/unit
TESTS_INTEGRATION := tests/integration
CSS_IN := $(SRC)/static/input.css
CSS_OUT := $(SRC)/static/tailwind.css

# Extract version from pyproject.toml
VERSION := $(shell grep '^version' pyproject.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## ----- Setup -----

install: ## Install package in editable mode
	pip install -e .

install-dev: ## Install package with dev dependencies
	pip install -e ".[dev]"

## ----- Code quality -----

format: ## Auto-format code (black + isort)
	black $(SRC) $(TESTS)
	isort $(SRC) $(TESTS)

lint: ## Run flake8 (critical errors only) + black/isort checks
	black --check $(SRC) $(TESTS)
	isort --check-only $(SRC) $(TESTS)
	flake8 $(SRC) $(TESTS) --select=E9,F63,F7,F82 --show-source

typecheck: ## Run mypy
	mypy $(SRC) --ignore-missing-imports

## ----- Tests -----
# Tests are split into:
#   - tests/unit/        — fast, no real SQLite init (run by `make test`)
#   - tests/integration/ — uses initialized_db / mcp_db fixtures (~4.5s setup
#                          per test on this NAS volume); run by `make test-slow`

test: ## Run unit tests only (fast, default for releases)
	pytest $(TESTS_UNIT) -v

test-slow: ## Run integration tests only (heavy fixtures, slow on NAS)
	pytest $(TESTS_INTEGRATION) -v

test-all: ## Run unit + integration (full suite)
	pytest $(TESTS) -v

test-cov: ## Run full suite with coverage report
	pytest $(TESTS) --cov=$(SRC) --cov-report=term-missing --cov-report=html

## ----- Build -----

css: ## Rebuild Tailwind CSS
	@if command -v tailwindcss >/dev/null 2>&1; then \
		tailwindcss -i $(CSS_IN) -o $(CSS_OUT) --minify; \
	else \
		npx --yes tailwindcss@3.4.17 -i $(CSS_IN) -o $(CSS_OUT) --minify; \
	fi

build: css ## Build Python package (rebuilds CSS first)
	rm -rf dist/ build/
	python -m build --no-isolation

## ----- Release -----

publish: build ## Build and upload to PyPI (then run `make tag`)
	@echo "==> Publishing v$(VERSION) to PyPI..."
	twine upload dist/authmcp_gateway-$(VERSION)*
	@echo "==> Done. Run 'make tag' to push git tag v$(VERSION)."

tag: ## Create and push git tag for current version
	@echo "==> Tagging v$(VERSION)..."
	@git tag "v$(VERSION)" 2>/dev/null && git push --tags || echo "    Tag v$(VERSION) already exists, skipping"

version: ## Show current version
	@echo $(VERSION)

## ----- Run -----

run: ## Start gateway locally
	authmcp-gateway start

## ----- Docker -----

docker-up: ## Start docker compose stack (detached)
	docker-compose up -d

docker-down: ## Stop docker compose stack
	docker-compose down

docker-logs: ## Tail authmcp-gateway logs
	docker-compose logs -f authmcp-gateway

docker-release: ## Rebuild & restart container with current git commit (post-publish step)
	@COMMIT=$$(git rev-parse --short HEAD); \
	echo "==> Rebuilding container with GIT_COMMIT=$$COMMIT, version $(VERSION)..."; \
	GIT_COMMIT=$$COMMIT docker compose build; \
	GIT_COMMIT=$$COMMIT docker compose up -d

## ----- Cleanup -----

clean: ## Remove build artifacts and caches
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	rm -rf .pytest_cache .mypy_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
