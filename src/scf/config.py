from __future__ import annotations

from typing import Final

# --- Locked region decisions -------------------------------------------------
# Core stack is single-region Sydney. Model Armor has no Sydney region, so
# security inspection crosses to Melbourne. That hop is deliberate, stays
# inside Australia, and is documented in ARCHITECTURE.md rather than hidden.

CORE_REGION: Final[str] = "australia-southeast1"  # Sydney
MODEL_ARMOR_REGION: Final[str] = "australia-southeast2"  # Melbourne

# Cloud Run, Firestore, Vertex AI, Artifact Registry, Logging, Trace,
# Secret Manager all pin to CORE_REGION.
CLOUD_RUN_REGION: Final[str] = CORE_REGION
FIRESTORE_REGION: Final[str] = CORE_REGION
VERTEX_REGION: Final[str] = CORE_REGION
ARTIFACT_REGISTRY_REGION: Final[str] = CORE_REGION

# The global Gemini endpoint is deliberately NOT a silent fallback. If the
# Sydney regional endpoint cannot serve the model, execution must stop and the
# architecture decision must be escalated.
ALLOW_GLOBAL_ENDPOINT_FALLBACK: Final[bool] = False

# --- Model -------------------------------------------------------------------
# REQUESTED_MODEL_ID is what Gate A must verify. VERIFIED_MODEL_ID stays None
# until a real generate_content call has returned from VERTEX_REGION. Nothing
# in this repo, the README, the video, or the Devpost text may claim a model
# version while VERIFIED_MODEL_ID is None.

REQUESTED_MODEL_ID: Final[str] = "gemini-3.7-flash"
VERIFIED_MODEL_ID: Final[str | None] = None

# --- Targets -----------------------------------------------------------------
DISPATCH_WEB_SERVICE: Final[str] = "dispatch-web"
UNRELATED_SERVICE: Final[str] = "site-directory"  # IAM proof C negative target

# --- Deliberate exclusions ---------------------------------------------------
# Pub/Sub is not used in the MVP. Replay/duplicate proof is performed by
# repeated delivery against Firestore-backed deterministic idempotency.
USE_PUBSUB: Final[bool] = False


def model_id() -> str:
    """Return the model id only once it has been verified against Vertex."""
    if VERIFIED_MODEL_ID is None:
        raise RuntimeError(
            "Gate A not passed: no Gemini model verified in "
            f"{VERTEX_REGION}. Refusing to claim {REQUESTED_MODEL_ID!r}."
        )
    return VERIFIED_MODEL_ID
