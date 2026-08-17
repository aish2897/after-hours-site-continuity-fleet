from __future__ import annotations

from typing import Final

PROJECT_ID: Final[str] = "site-continuity-fleet"

# --- Locked region decisions -------------------------------------------------
# Authoritative operational state, audit records, and privileged execution stay
# on Australian infrastructure. Model inference does not, and cannot: see
# MODEL_LOCATION below. Complete Australian model-processing residency is
# therefore not claimed. ARCHITECTURE.md states the split in full.

CORE_REGION: Final[str] = "australia-southeast1"  # Sydney
MODEL_ARMOR_REGION: Final[str] = "australia-southeast2"  # Melbourne

CLOUD_RUN_REGION: Final[str] = CORE_REGION
FIRESTORE_REGION: Final[str] = CORE_REGION
ARTIFACT_REGISTRY_REGION: Final[str] = CORE_REGION

# --- Model inference location ------------------------------------------------
# Gemini 3.7 Flash publishes inference endpoints for `global`, `us`, and `eu`
# only. Sydney returns 404 NOT_FOUND for this publisher model; verified by a
# real call on 2026-08-15 (docs/evidence/gate-a-vertex-gemini.md). Gemini 3.5
# Flash has no Sydney endpoint either, so downgrading does not avoid this.
#
# `global` is therefore the deliberate, approved primary inference location,
# not a fallback.
#
# Note what is NOT true today: there is no classification or Model Armor step
# between the duty manager's report text and this endpoint. The raw description
# is passed to the routing agent. The trust-level separation protects the
# authorization path, not the model input. See SECURITY.md.

MODEL_LOCATION: Final[str] = "global"
REQUESTED_MODEL_ID: Final[str] = "gemini-3.7-flash"
VERIFIED_MODEL_ID: Final[str | None] = "gemini-3.7-flash"
MODEL_VERIFIED_AT: Final[str] = "2026-08-15T14:40:48Z"

# Regional endpoints are host-prefixed; the global endpoint is not.
VERTEX_HOST: Final[str] = "aiplatform.googleapis.com"

# gemini-3.7-flash is a thinking model. A short prompt spent 297 thought tokens
# against 7 output tokens, so a small maxOutputTokens truncates the answer with
# finishReason=MAX_TOKENS before any visible text is produced.
DEFAULT_MAX_OUTPUT_TOKENS: Final[int] = 2048

# --- Firestore planes --------------------------------------------------------
# Two databases, isolated by per-database IAM conditions. The identity able to
# mutate Cloud Run must be unable to modify the authorization decision that
# permits that mutation.
#
# This is database-level isolation, not collection-level. Firestore IAM cannot
# scope below a database, and SECURITY.md says so rather than implying finer
# granularity than exists.

AUTHORITATIVE_DATABASE: Final[str] = "(default)"
EXECUTION_DATABASE: Final[str] = "execution-state"


def validate_database_config() -> None:
    """Fail closed if the planes are missing, blank, or collapsed into one."""
    for name, value in (
        ("AUTHORITATIVE_DATABASE", AUTHORITATIVE_DATABASE),
        ("EXECUTION_DATABASE", EXECUTION_DATABASE),
    ):
        if not value or not value.strip():
            raise RuntimeError(f"{name} is not configured")
    if AUTHORITATIVE_DATABASE == EXECUTION_DATABASE:
        raise RuntimeError(
            "AUTHORITATIVE_DATABASE and EXECUTION_DATABASE must differ: "
            "collapsing them would let the executor rewrite its own authorization"
        )


# --- Targets -----------------------------------------------------------------
DISPATCH_WEB_SERVICE: Final[str] = "dispatch-web"
UNRELATED_SERVICE: Final[str] = "site-directory"  # IAM proof C negative target

# --- Deliberate exclusions ---------------------------------------------------
# Pub/Sub is not used in the MVP. Replay proof is performed by repeated
# delivery against Firestore-backed deterministic idempotency.
USE_PUBSUB: Final[bool] = False


def model_endpoint(model_id: str | None = None) -> str:
    """Full Vertex generateContent URL for the approved inference location."""
    model = model_id or model_verified_id()
    return (
        f"https://{VERTEX_HOST}/v1/projects/{PROJECT_ID}"
        f"/locations/{MODEL_LOCATION}/publishers/google/models/{model}"
        ":generateContent"
    )


def model_verified_id() -> str:
    """Return the model id only once it has been verified against Vertex."""
    if VERIFIED_MODEL_ID is None:
        raise RuntimeError(
            f"Gate A not passed: no Gemini model verified at {MODEL_LOCATION}. "
            f"Refusing to claim {REQUESTED_MODEL_ID!r}."
        )
    return VERIFIED_MODEL_ID
