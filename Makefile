# Sentinel IAM & Audit Service - developer commands.
#
# Requirements: Docker with Compose v2, GNU make, and Python 3 for `make env`.
# Every quality check runs inside the dev container, so the host needs no Python
# packages. Run `make help` to list the targets.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help
MAKEFLAGS += --no-print-directory

COMPOSE ?= docker compose
PYTHON ?= python3
SERVICE ?=
ENV_ARGS ?=
# Optional PyPI mirror for `make lock`, e.g. make lock PIP_INDEX_URL=https://mirror.example/simple
PIP_INDEX_URL ?=

# The dev container runs as the host user so files it writes (migrations,
# coverage reports, openapi.yaml) stay owned by you.
export DEV_UID := $(shell id -u)
export DEV_GID := $(shell id -g)

DEV_RUN := $(COMPOSE) --profile dev run --rm dev
MANAGE := $(COMPOSE) exec web python manage.py

LOCK_IMAGE := python:3.12.15-slim-trixie
UV_VERSION := 0.13.5
UV_COMPILE := /tmp/.local/bin/uv pip compile --quiet --generate-hashes \
	--python-version 3.12 --python-platform x86_64-unknown-linux-gnu \
	--custom-compile-command "make lock"

.PHONY: help env lock build up down destroy ps logs migrate makemigrations \
	superuser shell dbshell test lint format typecheck check schema audit ci

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_.-]+:.*## / {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

env: ## Create .env with generated secrets (ENV_ARGS="--set KEY=VALUE ...")
	$(PYTHON) scripts/generate_env.py $(ENV_ARGS)

lock: ## Re-resolve and hash-pin requirements*.txt (Python 3.12, Linux)
	docker run --rm --volume "$(CURDIR):/src" --workdir /src \
		--user "$(DEV_UID):$(DEV_GID)" --env HOME=/tmp \
		$(if $(PIP_INDEX_URL),--env PIP_INDEX_URL=$(PIP_INDEX_URL) --env UV_DEFAULT_INDEX=$(PIP_INDEX_URL)) \
		$(LOCK_IMAGE) sh -c '\
		pip install --quiet --user uv==$(UV_VERSION) && \
		$(UV_COMPILE) requirements.in --output-file requirements.txt && \
		$(UV_COMPILE) requirements-dev.in --output-file requirements-dev.txt'

build: ## Build the runtime and dev images
	$(COMPOSE) build
	$(COMPOSE) --profile dev build dev

up: ## Build, migrate and start the stack; waits for health checks
	$(COMPOSE) up --detach --build --wait

down: ## Stop the stack (data volumes are kept)
	$(COMPOSE) --profile dev down --remove-orphans

destroy: ## Stop the stack and DELETE the PostgreSQL data volume
	@read -r -p "This permanently deletes all Sentinel data. Type 'yes' to continue: " answer; \
		[[ "$$answer" == "yes" ]] || { echo "Aborted."; exit 1; }
	$(COMPOSE) --profile dev down --volumes --remove-orphans

ps: ## Show service status
	$(COMPOSE) ps

logs: ## Follow logs (SERVICE=web|worker|beat|postgres|redis to filter)
	$(COMPOSE) logs --follow --tail=200 $(SERVICE)

migrate: ## Apply database migrations as the schema-owner role
	$(COMPOSE) run --rm migrate

makemigrations: ## Generate migrations for model changes
	$(DEV_RUN) python manage.py makemigrations

superuser: ## Create a Django admin superuser in the running stack
	$(MANAGE) createsuperuser

shell: ## Open a Django shell in the running stack
	$(MANAGE) shell

dbshell: ## Open psql as the bootstrap superuser
	$(COMPOSE) exec postgres sh -c 'psql --username "$$POSTGRES_USER" --dbname "$$POSTGRES_DB"'

test: ## Run the test suite with coverage against real PostgreSQL and Redis
	$(DEV_RUN) pytest --cov --cov-report=term-missing:skip-covered

lint: ## Ruff lint and format verification
	$(DEV_RUN) sh -c 'ruff check . && ruff format --check .'

format: ## Apply Ruff fixes and formatting
	$(DEV_RUN) sh -c 'ruff check --fix . && ruff format .'

typecheck: ## Static type checking with mypy
	$(DEV_RUN) mypy .

check: ## Django system checks and migration drift detection
	$(DEV_RUN) sh -c 'python manage.py check --fail-level WARNING && python manage.py makemigrations --check --dry-run'

schema: ## Validate the OpenAPI schema and export it to openapi.yaml
	$(DEV_RUN) python manage.py spectacular --validate --fail-on-warn --file openapi.yaml

audit: ## Check locked runtime dependencies for known vulnerabilities
	$(DEV_RUN) pip-audit --requirement requirements.txt --require-hashes --disable-pip --strict

ci: lint typecheck check schema test audit ## Run the same checks as CI
