from __future__ import annotations

from scf import config


def test_australian_infrastructure_regions():
    assert config.CORE_REGION == "australia-southeast1"
    for region in (
        config.CLOUD_RUN_REGION,
        config.FIRESTORE_REGION,
        config.ARTIFACT_REGISTRY_REGION,
    ):
        assert region == config.CORE_REGION


def test_model_armor_crosses_to_melbourne_but_stays_in_australia():
    assert config.MODEL_ARMOR_REGION == "australia-southeast2"
    assert config.MODEL_ARMOR_REGION != config.CORE_REGION
    assert config.MODEL_ARMOR_REGION.startswith("australia-")


def test_model_inference_location_is_global_by_decision():
    """Gemini 3.7 Flash has no Sydney endpoint; global is the approved primary."""
    assert config.MODEL_LOCATION == "global"


def test_no_fallback_concept_remains():
    """Global is an intentional architecture choice, not a degraded fallback."""
    assert not hasattr(config, "ALLOW_GLOBAL_ENDPOINT_FALLBACK")


def test_infrastructure_is_not_colocated_with_inference():
    """The residency split is real and must stay visible in configuration."""
    assert config.MODEL_LOCATION != config.CORE_REGION


def test_pubsub_is_excluded_from_the_mvp():
    assert config.USE_PUBSUB is False


def test_verified_model_is_backed_by_evidence():
    assert config.VERIFIED_MODEL_ID == "gemini-3.7-flash"
    assert config.model_verified_id() == config.REQUESTED_MODEL_ID
    assert config.MODEL_VERIFIED_AT


def test_model_endpoint_targets_the_global_publisher_path():
    endpoint = config.model_endpoint()
    assert endpoint.startswith("https://aiplatform.googleapis.com/v1/")
    assert "/locations/global/" in endpoint
    assert "/publishers/google/models/gemini-3.7-flash:generateContent" in endpoint
    assert config.PROJECT_ID in endpoint
    # A regional host prefix would silently change the inference location.
    assert "australia-southeast1-aiplatform" not in endpoint


def test_output_budget_accounts_for_thinking_tokens():
    """297 thought tokens vs 7 output tokens: a small budget truncates to nothing."""
    assert config.DEFAULT_MAX_OUTPUT_TOKENS >= 1024
