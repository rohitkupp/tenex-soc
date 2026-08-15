"""Log emitters — one module per source, each implementing `datagen.types.LogEmitter`.

Package marker only. Emitters are imported explicitly by the generator driver rather than
auto-discovered: there are three of them, they are not user-extensible, and an explicit import
keeps the emission order in the driver visible.
"""

from __future__ import annotations
