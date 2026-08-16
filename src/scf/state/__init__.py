"""Durable state, split into two planes.

AUTHORITATIVE control plane -> IncidentRepository on config.AUTHORITATIVE_DATABASE
EXECUTION plane             -> ExecutionStore on config.EXECUTION_DATABASE

The identity able to mutate Cloud Run holds read-only IAM on the first and
append-only IAM on the second, so it cannot rewrite the decision authorizing
its own mutation.
"""

from scf.state.execution_store import ExecutionStore
from scf.state.firestore_repo import (
    DecisionNotFound,
    IncidentNotFound,
    IncidentRepository,
)

__all__ = [
    "DecisionNotFound",
    "ExecutionStore",
    "IncidentNotFound",
    "IncidentRepository",
]
