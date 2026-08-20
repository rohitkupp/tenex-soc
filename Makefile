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

# `app.scripts.seed_feedback` is deliberately NOT run here any more. Commit ed9b024
# ("remove duplicate detection and the learning loop") deleted `app/learning/` — all 23
# modules — but left that script behind still importing four of them, so `make seed`
# died with `ModuleNotFoundError: No module named 'app.learning'` on any machine that
# did not already have the pre-deletion bytecode lying around. Nothing reads seeded
# feedback now: feedback is one endpoint that writes the analyst's words to a text file
# and nothing reads it back. The calibrators that script used to refit are optional by
# design — `CalibratorStore` treats a missing artifact exactly as it treats a detector
# that was never fitted (`calibrate` falls back to `clamp01`).
# `backend/app/scripts/seed_feedback.py` itself is now orphaned and can be deleted.
#
# `app.scripts.seed_demo_baselines` is the last step and it is load-bearing. `app.baseline.loader`
# above loads `data/baseline/`, which `make gen-data` builds from `build_split_org(train)` — the
# *northwind.example* org. Every committed log a reviewer actually uploads (`data/samples/`,
# `data/demo5/`, `data/demo5_tiny/`) belongs to a different org on *corp.example*, so none of its
# principals have a single baseline row and every percentile annotation renders
# `insufficient history (n=0)`. The demo logs' own org cannot be regenerated (their recorded
# `org_fingerprint` predates today's generator), so this script derives the six-month history
# from the benign remainder of the demo logs themselves, keyed to the principals those logs
# actually contain. Both baselines coexist: the loader's rows are keyed by northwind entities,
# this script's by corp.example ones, and `load_baseline` upserts.
seed: ## Create the live tenant, demo user, Tier 2 peer signatures, and both historical baselines
	$(BACKEND) python -m app.scripts.seed
	$(BACKEND) python -m app.scripts.seed_tier2
	$(BACKEND) python -m app.baseline.loader
	$(BACKEND) python -m app.scripts.seed_demo_baselines

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
	# `app.detection.train` never existed — this target has always failed with
	# ModuleNotFoundError. The real entrypoints are the two below.
	$(BACKEND) python -m app.detection.evidence.dga_train
	$(BACKEND) python -m app.detection.ml.train

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
