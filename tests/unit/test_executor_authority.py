"""The executor must never accept authority from its caller."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from scf.app.executor import EXECUTABLE, ExecuteRequest, _validate
from scf.domain.enums import ActionType, Decision
from scf.domain.ids import derive_execution_id

INCIDENT = "INC-20260815-20ABB8"
DECISION = "DEC-C57E81CD0D"


def good_decision(**overrides):
    base = {
        "decision_id": DECISION,
        "incident_id": INCIDENT,
        "action_type": ActionType.FLIP_TRAFFIC_TO_LAST_GOOD.value,
        "target_ref": "dispatch-web",
        "decision": Decision.AUTO_ALLOWED.value,
        "revoked": False,
        "parameters": {"authorized_target_revision": "dispatch-web-00003-x87"},
    }
    base.update(overrides)
    return base


def request(**overrides):
    payload = {"incident_id": INCIDENT, "decision_id": DECISION}
    payload.update(overrides)
    return ExecuteRequest(**payload)


def test_request_schema_cannot_carry_an_authorization_claim():
    """The structural defence: authority is not expressible in the request."""
    for field, value in [
        ("decision", "AUTO_ALLOWED"),
        ("target_ref", "site-directory"),
        ("action_type", "FLIP_TRAFFIC_TO_LAST_GOOD"),
        ("authorized", True),
        ("policy_decision", "AUTO_ALLOWED"),
        ("attempt_intent", 2),
        ("target_revision", "dispatch-web-00004-jqm"),
    ]:
        with pytest.raises(ValidationError):
            ExecuteRequest(incident_id=INCIDENT, decision_id=DECISION, **{field: value})


def test_valid_stored_decision_passes():
    assert _validate(good_decision(), request()) is None


@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({"incident_id": "INC-19990101-OTHER0"}, "decision_incident_mismatch"),
        ({"revoked": True}, "decision_revoked"),
        ({"decision": "DENIED"}, "decision_not_executable:DENIED"),
        ({"decision": "APPROVAL_REQUIRED"}, "decision_not_executable:APPROVAL_REQUIRED"),
        ({"action_type": "NOT_A_REAL_ACTION"}, "action_type_not_in_closed_enum"),
        ({"action_type": "EXPORT_CREDENTIALS"}, "unsupported_action_type:EXPORT_CREDENTIALS"),
        ({"action_type": "DISABLE_FIREWALL"}, "unsupported_action_type:DISABLE_FIREWALL"),
        ({"target_ref": "not-registered"}, "target_not_registry_approved"),
        ({"parameters": {}}, "missing_authorized_target_revision"),
    ],
)
def test_adversarial_stored_decisions_are_refused(overrides, expected):
    assert _validate(good_decision(**overrides), request()) == expected


def test_only_auto_allowed_and_approved_are_executable():
    assert EXECUTABLE == {Decision.AUTO_ALLOWED.value, "APPROVED"}
    assert Decision.DENIED.value not in EXECUTABLE
    assert Decision.APPROVAL_REQUIRED.value not in EXECUTABLE


def test_a_forged_dangerous_decision_is_still_refused():
    """Even a perfectly forged AUTO_ALLOWED cannot exfiltrate credentials."""
    forged = good_decision(
        action_type=ActionType.EXPORT_CREDENTIALS.value, target_ref="credential-store"
    )
    assert _validate(forged, request()) is not None


def test_replay_of_the_same_decision_derives_the_same_key():
    args = dict(
        incident_id=INCIDENT,
        action_type=ActionType.FLIP_TRAFFIC_TO_LAST_GOOD.value,
        target_ref="dispatch-web",
        decision_id=DECISION,
    )
    assert derive_execution_id(**args) == derive_execution_id(**args)


def test_no_retry_field_exists_on_the_request():
    """A caller must not be able to declare a new attempt."""
    assert "attempt_intent" not in ExecuteRequest.model_fields
    with pytest.raises(ValidationError):
        ExecuteRequest(incident_id=INCIDENT, decision_id=DECISION, attempt_intent=2)


def test_executor_does_not_certify_its_own_success():
    """flip_traffic_to_revision reports acceptance, never recovery."""
    import inspect

    from scf.executor import cloud_run

    source = inspect.getsource(cloud_run)
    assert "accepted" in source
    # Operation polling was removed deliberately; the verifier decides.
    assert "_await_operation" not in source
