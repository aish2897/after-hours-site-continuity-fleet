from __future__ import annotations

import pytest

from scf import config


def test_core_region_is_sydney():
    assert config.CORE_REGION == "australia-southeast1"
    for region in (
        config.CLOUD_RUN_REGION,
        config.FIRESTORE_REGION,
        config.VERTEX_REGION,
        config.ARTIFACT_REGISTRY_REGION,
    ):
        assert region == config.CORE_REGION


def test_model_armor_crosses_to_melbourne_but_stays_in_australia():
    assert config.MODEL_ARMOR_REGION == "australia-southeast2"
    assert config.MODEL_ARMOR_REGION != config.CORE_REGION
    assert config.MODEL_ARMOR_REGION.startswith("australia-")
    assert config.CORE_REGION.startswith("australia-")


def test_global_endpoint_is_not_a_silent_fallback():
    assert config.ALLOW_GLOBAL_ENDPOINT_FALLBACK is False


def test_pubsub_is_excluded_from_the_mvp():
    assert config.USE_PUBSUB is False


def test_model_id_refuses_to_be_claimed_before_gate_a():
    """No model version may be claimed until a real Vertex call has returned."""
    if config.VERIFIED_MODEL_ID is None:
        with pytest.raises(RuntimeError, match="Gate A not passed"):
            config.model_id()
    else:
        assert config.model_id() == config.VERIFIED_MODEL_ID
