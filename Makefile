.DEFAULT_GOAL := help
SHELL := /bin/bash

COMPOSE := docker compose
BACKEND := $(COMPOSE) exec -T api

.PHONY: help up down logs ps migrate revision seed gen-data train eval test lint fmt clean

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

seed: ## Create the demo tenant, user, and seeded feedback history
	$(BACKEND) python -m app.scripts.seed
	$(BACKEND) python -m app.scripts.seed_feedback

gen-data: ## Regenerate the synthetic corpus, eval scenarios, and demo file
	$(BACKEND) python -m datagen all

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
