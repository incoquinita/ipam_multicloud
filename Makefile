.PHONY: help install dev test lint format migrate build up down clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install backend dependencies
	cd backend && pip install -e ".[dev]"

dev: ## Start development environment
	docker compose up -d db redis
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test: ## Run tests
	cd backend && pytest -v

lint: ## Lint backend code
	cd backend && ruff check . && ruff format --check .

format: ## Format backend code
	cd backend && ruff check --fix . && ruff format .

migrate: ## Run database migrations
	cd backend && alembic upgrade head

migrate-new: ## Create new migration
	cd backend && alembic revision --autogenerate -m "$(name)"

build: ## Build Docker images
	docker compose build

up: ## Start all services
	docker compose up -d

down: ## Stop all services
	docker compose down

clean: ## Clean up caches
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage coverage.xml htmlcov/
