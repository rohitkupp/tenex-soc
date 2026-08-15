"""One module per stage's business logic — what `app.pipeline.base_worker.StageWorker`
plugs in as its `handler`. Transport, retry, and dead-lettering live in the base
worker; everything here is "what does this stage actually do."
"""

from __future__ import annotations
