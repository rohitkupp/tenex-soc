"""RabbitMQ topology, connections, and publish helpers for the M4 pipeline (docs/01).

This package owns *transport* only: declaring queues/exchanges, opening connections,
and putting bytes on the wire. Message shape (`StageMessage`) and what a stage does
with one live in `app.pipeline`.
"""

from __future__ import annotations
