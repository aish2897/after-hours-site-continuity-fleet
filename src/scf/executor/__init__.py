"""Deterministic remediation execution. No LLM, no prompt text."""

from scf.executor.cloud_run import flip_traffic_to_revision

__all__ = ["flip_traffic_to_revision"]
