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
# torch first, from the CPU-only index. The default PyPI wheel bundles the full CUDA runtime —
# roughly 2.5 GB of nvidia/* libraries per image — and nothing in this system runs on a GPU: the
# autoencoder is a 53→32→8→32→53 MLP that fits in seconds on CPU. Multiplied across the service
# images `deploy/gcp/compose.prod.yml` builds, those unused libraries are what exhausted the disk
# on the deploy VM. Installing it explicitly before the project pins it in place, so the
# `pip install -e .` below resolves `torch>=2.5` as already satisfied rather than pulling the
# CUDA build back in.
RUN pip install --upgrade pip \
 && pip install --index-url https://download.pytorch.org/whl/cpu "torch>=2.5" \
 && pip install -e ".[dev]"

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
