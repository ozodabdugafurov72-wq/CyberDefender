"""CyberDefender v6 architecture contracts.

This package is intentionally non-executing. It documents and validates the
security constitution, authority model, and plane boundaries. Importing it
must never grant OS authority or change runtime behavior.
"""

from .constitution import SECURITY_CONSTITUTION, SecurityInvariant, constitution_snapshot
from .authority import AUTHORITY_MATRIX, AuthorityProfile, RuntimePlane, SecurityPlane, authority_snapshot
from .boundaries import ALLOWED_TARGET_FLOW, FORBIDDEN_DIRECT_EDGES, boundary_snapshot
from .status import V6_IMPLEMENTATION_STATUS, implementation_status_snapshot

__all__ = [
    "SECURITY_CONSTITUTION",
    "SecurityInvariant",
    "constitution_snapshot",
    "AUTHORITY_MATRIX",
    "AuthorityProfile",
    "RuntimePlane",
    "SecurityPlane",
    "authority_snapshot",
    "ALLOWED_TARGET_FLOW",
    "FORBIDDEN_DIRECT_EDGES",
    "boundary_snapshot",
    "V6_IMPLEMENTATION_STATUS",
    "implementation_status_snapshot",
]
