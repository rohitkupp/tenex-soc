FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Build deps for scientific wheels that may not ship arm64 binaries.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential curl libgomp1 \
 && rm -rf /var/lib/apt/lists/*

# Dependency layer, cached independently of source.
COPY pyproject.toml ./
# torch is deliberately absent. It was a direct dependency for the L3 autoencoder, which the
# v2 migration removed (change 19) — its jobs were absorbed by the evidence extractors and by
# EIF's oblique splits. Nothing imports it now, and pyod/shap only require it under optional
# extras we do not install, so the CPU-only-wheel install that used to live here (added after
# the CUDA build exhausted the deploy VM's disk) is no longer needed at all. Deleting a
# dependency beats pinning a lighter build of it.
RUN pip install --upgrade pip && pip install -e ".[dev]"

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
