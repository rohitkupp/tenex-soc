.DEFAULT_GOAL := help
# Migration change 13 specifies 1000 files. That is ~2.5 GB of .log — override for a
# quicker local run (`make gen-data FILES=50`) rather than editing this file.
FILES ?= 1000
SHELL := /bin/bash

COMPOSE := docker compose
BACKEND := $(COMPOSE) exec -T api

.PHONY: help up down logs ps migrate revision seed gen-data gen-data-quick train eval test lint fmt clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-14s\033[0m %s\n", $$1, $$2}'

up: ## Bring up the full local topology
	$(COMPOSE) up -d --build
	@echo "api  → http://localhost:8000/api/health"
	@echo "web  → http://localhost:3000"
	@echo "mq   → http://localhost:15672 (tenex/tenex)"
	@echo "minio→ http://localhost:9001 (tenexminio/tenexminio123)"

down: ## Tear down containers (volumes preserved)
	$(COMPOSE) down

logs: ## Tail logs for all services
	$(COMPOSE) logs -f --tail=100

ps: ## Show container status
	$(COMPOSE) ps

migrate: ## Apply database migrations
	$(BACKEND) alembic upgrade head

revision: ## Autogenerate a migration: make revision m="add events"
	$(BACKEND) alembic revision --autogenerate -m "$(m)"

seed: ## Create the live tenant, demo user, seeded feedback history, Tier 2 peer signatures, and the historical baseline
	$(BACKEND) python -m app.scripts.seed
	$(BACKEND) python -m app.scripts.seed_feedback
	$(BACKEND) python -m app.scripts.seed_tier2
	$(BACKEND) python -m app.baseline.loader

# `python -m datagen split`, not the old `datagen/generate_corpus.py`. That second generator
# was deleted: it emitted `"%Y-%m-%d %H:%M:%S"` timestamps while `app/parsers/zscaler.py`
# accepts only the ISO `...THH:MM:SSZ` form `datagen/emitters/zscaler.py` writes, so every file
# it ever produced was 100% unparseable — `make gen-data` silently generated a corpus the
# product could not read. One generator now decides a log line's shape, so the two cannot drift
# apart again. See `datagen/labeled_corpus.py`'s docstring for the full consolidation.
gen-data: ## Regenerate the 1000-file corpus + 6-month baseline (FILES=n to shrink)
	$(BACKEND) python -m datagen split --out data --files $(FILES)

gen-data-quick: ## Small corpus, no baseline — for a fast local check
	$(BACKEND) python -m datagen split --out data --files 20 --skip-baseline

train: ## Train all models, writing artifacts to backend/data/models/
	$(BACKEND) python -m app.detection.train

eval: ## Run the golden dataset; exits 1 on regression
	$(BACKEND) python -m evals.run

test: ## Run backend and frontend test suites
	$(BACKEND) pytest -q
	cd frontend && npm test --silent --if-present

lint: ## Ruff + mypy + eslint + tsc
	$(BACKEND) ruff check app datagen evals tests
	$(BACKEND) ruff format --check app datagen evals tests
	$(BACKEND) mypy app/detection app/agent app/graph
	cd frontend && npm run lint && npx tsc --noEmit

fmt: ## Autoformat backend and frontend
	$(BACKEND) ruff check --fix app datagen evals tests
	$(BACKEND) ruff format app datagen evals tests
	cd frontend && npm run format --if-present

clean: ## Tear down containers AND delete volumes
	$(COMPOSE) down -v
