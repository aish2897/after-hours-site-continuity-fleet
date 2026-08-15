"""Append-only, hash-chained audit trail.

Storage-agnostic: these records are built and verified here, and persisted by
the Firestore repository. Tamper detection does not depend on the datastore.
"""

from scf.audit.chain import ChainVerification, append, hashable_view, seal, verify_chain

__all__ = [
    "ChainVerification",
    "append",
    "hashable_view",
    "seal",
    "verify_chain",
]
