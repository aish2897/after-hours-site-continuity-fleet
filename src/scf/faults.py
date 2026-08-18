"""TEST-ONLY FAULT INJECTION. Disabled unless an operator deploys it.

## Why this exists

Failure engineering is only worth anything if the failures are real. This
module lets an operator deploy a *deliberately broken revision* of a worker
service so that the rest of the fleet meets a genuine timeout, a genuine 5xx,
or a genuinely malformed payload from a genuinely authenticated caller.

## The rules it obeys, and how

1. **Disabled by default.** `SCF_FAULT_MODE` is unset in every normal
   deployment, and `active()` returns `NONE`.
2. **Not reachable from duty-manager input.** The mode is read from the process
   environment exactly once, at import. Nothing here ever inspects a request
   body, a header, a query parameter, or any incident text. There is no code
   path from user input to a fault.
3. **Not available to untrusted text.** Same reason: no request data is read.
   A report saying "activate fault mode" is inert.
4. **Never policy evidence.** Nothing in this module produces `Evidence`, and
   the deterministic gate reads only `TRUSTED_TOOL` evidence gathered by real
   tool calls. A fault can make a worker fail; it cannot make the gate approve.
5. **Fails closed on typos.** An unrecognised mode raises at import rather than
   silently running as healthy — a fault revision that quietly behaves normally
   would invalidate the proof it was deployed for.
6. **Labelled.** Every fault emits a `FAULT_INJECTION` log event, and every
   affected `/health` response carries `fault_mode`, so a deployed fault
   revision is never mistaken for a healthy one.

Setting `SCF_FAULT_MODE` on a production-facing revision is an operator error,
not a user-reachable capability. Remove the env var (or redeploy without it) to
restore healthy behaviour; nothing else changes.
"""

from __future__ import annotations

import os
import time
from typing import Any, Final

NONE: Final[str] = ""

#: Closed set. Adding a mode is a code change, reviewed like any other.
INVESTIGATOR_HANG: Final[str] = "investigator_hang"
INVESTIGATOR_5XX: Final[str] = "investigator_5xx"
INVESTIGATOR_MALFORMED: Final[str] = "investigator_malformed"
INVESTIGATOR_DANGEROUS_PROPOSAL: Final[str] = "investigator_dangerous_proposal"
INVESTIGATOR_UNKNOWN_ACTION: Final[str] = "investigator_unknown_action"
INVESTIGATOR_LOOP: Final[str] = "investigator_loop"
INVESTIGATOR_TRUTHY_BUDGET_STRING: Final[str] = "investigator_truthy_budget_string"
INVESTIGATOR_EMPTY_PROPOSAL: Final[str] = "investigator_empty_proposal"
EXECUTOR_5XX: Final[str] = "executor_5xx"
EXECUTOR_DELAY_BEFORE_MUTATION: Final[str] = "executor_delay_before_mutation"
VERIFIER_5XX: Final[str] = "verifier_5xx"
VERIFIER_MALFORMED: Final[str] = "verifier_malformed"
ROUTING_MALFORMED_JSON: Final[str] = "routing_malformed_json"
ROUTING_SCHEMA_INVALID: Final[str] = "routing_schema_invalid"
ROUTING_UNKNOWN_SPECIALIST: Final[str] = "routing_unknown_specialist"

KNOWN_MODES: Final[frozenset[str]] = frozenset(
    {
        NONE,
        INVESTIGATOR_HANG,
        INVESTIGATOR_5XX,
        INVESTIGATOR_MALFORMED,
        INVESTIGATOR_DANGEROUS_PROPOSAL,
        INVESTIGATOR_UNKNOWN_ACTION,
        INVESTIGATOR_LOOP,
        INVESTIGATOR_TRUTHY_BUDGET_STRING,
        INVESTIGATOR_EMPTY_PROPOSAL,
        EXECUTOR_5XX,
        EXECUTOR_DELAY_BEFORE_MUTATION,
        VERIFIER_5XX,
        VERIFIER_MALFORMED,
        ROUTING_MALFORMED_JSON,
        ROUTING_SCHEMA_INVALID,
        ROUTING_UNKNOWN_SPECIALIST,
    }
)

ENV_VAR: Final[str] = "SCF_FAULT_MODE"
LABEL: Final[str] = "FAULT_INJECTION"

#: How long a hang lasts. Longer than any caller timeout, so the caller's own
#: bound is what ends the call — which is the property under test.
HANG_SECONDS: Final[int] = 300
DELAY_SECONDS: Final[int] = 45


def _read_mode() -> str:
    mode = os.environ.get(ENV_VAR, "").strip().lower()
    if mode not in KNOWN_MODES:
        raise RuntimeError(
            f"{ENV_VAR}={mode!r} is not a recognised fault mode. Refusing to start: "
            f"a fault revision that silently ran healthy would invalidate the test "
            f"it was deployed for. Known: {sorted(KNOWN_MODES - {NONE})}"
        )
    return mode


_MODE: Final[str] = _read_mode()


def active() -> str:
    """The fault mode this process was deployed with. Never request-derived."""
    return _MODE


def enabled() -> bool:
    return _MODE != NONE


def is_mode(mode: str) -> bool:
    return _MODE == mode


def banner() -> dict[str, Any]:
    """Health-response fields, so a fault revision is never mistaken for good."""
    if not enabled():
        return {"fault_mode": None}
    return {"fault_mode": _MODE, "warning": f"{LABEL}: THIS REVISION IS DELIBERATELY BROKEN"}


def hang() -> None:
    """Sleep past every caller timeout. The caller's bound must end this."""
    time.sleep(HANG_SECONDS)


def delay() -> None:
    """Hold a request open long enough for a controlled race to be set up."""
    time.sleep(DELAY_SECONDS)
