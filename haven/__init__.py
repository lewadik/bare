"""Haven — deduplicating client/server backup for Linux servers.

Layout
------
``haven.chunker``    content-defined chunking (gear hash)
``haven.codec``      per-chunk compression
``haven.packfile``   append-only pack file container
``haven.manifest``   signed snapshot manifests
``haven.backup``     client-side snapshot creation
``haven.restore``    client-side restore
``haven.retention``  GFS retention policy
``haven.cli``        ``haven`` command line entry point
``haven.server``     ``havend`` repository daemon
"""

from __future__ import annotations

__version__ = "1.0.0"
PROTOCOL_VERSION = 1
