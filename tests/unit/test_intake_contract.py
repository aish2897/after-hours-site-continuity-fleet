from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from scf.app.main import IncidentIntake
from scf.domain.enums import IncidentStatus, TrustLevel
from scf.domain.models import Evidence, IncidentDoc, IncidentReport

VALID = "The dispatch screens are showing an error page. Phones and Wi-Fi seem fine."


def test_plain_language_report_is_accepted():
    intake = IncidentIntake(description=VALID)
    assert intake.site_id
    assert intake.reported_by == "duty-manager"


@pytest.mark.parametrize(
    "field",
    ["service", "specialist", "category", "root_cause", "remediation", "action_type"],
)
def test_caller_cannot_supply_diagnosis_or_remediation(field):
    """The duty manager describes symptoms. The system infers everything else."""
    with pytest.raises(ValidationError):
        IncidentIntake(description=VALID, **{field: "systems"})


@pytest.mark.parametrize("description", ["", "short", "   ", "a" * 4001])
def test_malformed_descriptions_are_rejected(description):
    with pytest.raises(ValidationError):
        IncidentIntake(description=description)


def test_report_text_is_recorded_as_untrusted_input():
    """Intake text must never acquire trusted provenance."""
    evidence = Evidence(
        key="duty_manager_report",
        value=VALID,
        supports="incident intake",
        source_agent="intake",
        trust_level=TrustLevel.UNTRUSTED_INPUT,
    )
    assert evidence.trust_level is TrustLevel.UNTRUSTED_INPUT

    from scf.policy import trusted_evidence_map

    assert trusted_evidence_map([evidence]) == {}


def test_incident_serializes_to_a_firestore_safe_document():
    """Firestore stores JSON-native values; datetimes must not leak as objects."""
    doc = IncidentDoc(
        report=IncidentReport(site_id="MEL-WAREHOUSE-01", description=VALID),
        trace_id="7053fac8c3ed3dd7f2543ff7d5581bfd",
    )
    payload = doc.model_dump(mode="json")

    json.dumps(payload)  # raises if any value is not JSON-native
    assert payload["status"] == IncidentStatus.INTAKE.value
    assert isinstance(payload["created_at"], str)
    assert payload["trace_id"] == "7053fac8c3ed3dd7f2543ff7d5581bfd"
    assert payload["schema_version"]


def test_incident_round_trips_through_serialization():
    original = IncidentDoc(
        report=IncidentReport(site_id="MEL-WAREHOUSE-01", description=VALID)
    )
    restored = IncidentDoc.model_validate(original.model_dump(mode="json"))
    assert restored.incident_id == original.incident_id
    assert restored.status == original.status
    assert restored.report.description == original.report.description


def test_trace_id_parsing_from_cloud_run_header():
    from scf.obs import trace_id_from_header

    assert trace_id_from_header("abc123/9876543210;o=1") == "abc123"
    assert trace_id_from_header(None) is None
    assert trace_id_from_header("") is None


def test_structured_logging_redacts_credentials(capsys):
    from scf.obs import log_event

    log_event("test_event", incident_id="INC-1", authorization="Bearer secret-value")
    printed = capsys.readouterr().out
    assert "secret-value" not in printed
    assert "[REDACTED]" in printed
    assert json.loads(printed)["event"] == "test_event"
