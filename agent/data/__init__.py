"""CyberDefender structured data read-model foundation.

The SQL read model is intentionally non-authoritative. Security admission,
replay protection, durable spool and audit JSONL remain separate trust and
reliability boundaries.
"""

from .repository import DataRepository
from .sqlite_repository import SQLiteDataRepository

__all__ = ["DataRepository", "SQLiteDataRepository"]
