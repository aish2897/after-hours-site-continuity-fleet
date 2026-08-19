"""What a duty manager is asked, when the system needs a person to decide.

Deterministic text built from the authorized decision. No model output reaches
this: the manager is reading a description of what the deterministic gate has
already pinned, not a sentence an LLM wrote about it.

The audience is the Unlikely Hero — someone who cannot be expected to know what
a revision is, and should not have to. So the prompt answers three questions in
their language: what will happen, how far it reaches, and what cannot happen.
The revision identifiers stay available for the technical view, and out of the
default one.
"""

from __future__ import annotations

from scf.domain.enums import ActionType

#: How long a person has to answer before the pinned decision goes stale. Short
#: on purpose: the approval authorizes a specific revision against evidence
#: gathered at a specific moment, and an outage moves on.
APPROVAL_TTL_SECONDS = 30 * 60

_WHAT_WILL_HAPPEN: dict[ActionType, str] = {
    ActionType.SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE: (
        "Traffic will move to a version of the dispatch service that is "
        "currently answering normally."
    ),
    ActionType.FLIP_TRAFFIC_TO_LAST_GOOD: (
        "Traffic will move back to the version your team previously marked as "
        "known good."
    ),
    ActionType.RESTART_DATABASE_SERVICE: (
        "The dispatch database service will be restarted."
    ),
}

_WHY_YOU_ARE_BEING_ASKED: dict[ActionType, str] = {
    ActionType.SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE: (
        "No version has been marked known good, so the system cannot tell on "
        "its own which one the business should be running. It has checked that "
        "this one responds correctly, but choosing it is your call."
    ),
    ActionType.RESTART_DATABASE_SERVICE: (
        "Restarting the database can interrupt work that is in progress."
    ),
}


def approval_prompt(
    *,
    action_type: ActionType,
    target_ref: str,
    authorized_target_revision: str,
) -> dict[str, object]:
    """The structured prompt a manager-facing surface will render.

    Returned as data rather than a formatted string so the eventual UI decides
    presentation, and so the technical detail stays in a field a manager view
    can leave collapsed.
    """
    return {
        "headline": (
            "Automatic recovery found a higher-impact action that needs your "
            "approval."
        ),
        "what_will_happen": _WHAT_WILL_HAPPEN.get(
            action_type, "A change will be made to the dispatch service."
        ),
        "why_you_are_being_asked": _WHY_YOU_ARE_BEING_ASKED.get(
            action_type,
            "This action carries more risk than the system will take on its own.",
        ),
        "scope": f"The {target_ref} service only.",
        "what_will_not_happen": (
            "No other service at your site can be changed by this action. "
            "No data is deleted, and the change can be reversed."
        ),
        "choices": ["APPROVE RECOVERY", "ESCALATE INSTEAD"],
        # Deliberately separate: a duty manager should never have to read this
        # to make the decision, and a technical responder should never have to
        # go hunting for it.
        "technical_detail": {
            "action_type": action_type.value,
            "target_ref": target_ref,
            "authorized_target_revision": authorized_target_revision,
        },
    }
