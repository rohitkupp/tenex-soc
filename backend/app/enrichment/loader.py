"""Dataset location + shared path constants for `app/enrichment`.

Every dataset this package reads is a file bundled in the image (docs/03-PARSERS-OCSF.md
"Enrichment": "Do not make network calls at runtime; everything is offline datasets bundled
in the image"). This module only resolves *where* those files live; each submodule owns
its own `functools.lru_cache`-wrapped loader so a dataset is parsed at most once per
process and a missing/malformed file degrades to "no data" (see each loader) rather than
crashing import.
"""

from __future__ import annotations

from pathlib import Path

# app/enrichment/loader.py -> app/enrichment -> app -> backend
_BACKEND_ROOT = Path(__file__).resolve().parents[2]

DATA_ENRICHMENT_DIR = _BACKEND_ROOT / "data" / "enrichment"
DATA_TAGS_DIR = _BACKEND_ROOT / "data" / "tags"

# Reused, not duplicated -- see domain_enrichment.py's module docstring. `datagen` is a
# sibling package this module only ever *reads a bundled text file from*; it never imports
# datagen's Python code (which is a separate team's ownership, docs/13 M2).
DATAGEN_DATA_DIR = _BACKEND_ROOT / "datagen" / "data"
