"""
Relic's V10.0 Specification for SGA files.
"""
from relic.sga.v10.definitions import (
    version,
)

from relic.sga.v10.serialization import essence_fs_serializer as EssenceFSHandler

__version__ = "1.0.0"

__all__ = [
    "EssenceFSHandler",
    "version",
]
