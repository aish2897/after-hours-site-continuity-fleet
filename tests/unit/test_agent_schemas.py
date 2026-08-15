from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from scf.agents.schemas import ROUTING_INSTRUCTION, RoutingLlmOutput
from scf.domain.enums import SpecialistName
from scf.domain.models import RoutingDecision, SpecialistRoute


def route(specialist, required, why="because"):
    return SpecialistRoute(specialist=specialist, required=required, why=why)


ALL_ROUTES = [
    route(SpecialistName.SYSTEMS, True, "dispatch app returning errors"),
    route(SpecialistName.NETWORK, False, "wifi and phones fine"),
    route(SpecialistName.SECURITY, False, "no auth anomalies"),
    route(SpecialistName.CONTINUITY, False, "no vendor handoff yet"),
]


def test_output_promotes_into_the_domain_contract():
    output = RoutingLlmOutput(routes=ALL_ROUTES, summary="Dispatch app is down.")
    decision = output.to_domain(model_id="gemini-3.7-flash")

    assert isinstance(decision, RoutingDecision)
    assert decision.required_specialists() == [SpecialistName.SYSTEMS]
    assert decision.model_id == "gemini-3.7-flash"


def test_model_cannot_assert_its_own_provenance():
    """model_id and created_at are attached by us, never by the model."""
    with pytest.raises(ValidationError):
        RoutingLlmOutput(
            routes=ALL_ROUTES, summary="x", model_id="gemini-9-ultra"
        )


def test_empty_routing_is_rejected_at_the_boundary():
    with pytest.raises(ValidationError):
        RoutingLlmOutput(routes=[], summary="x")


def test_malformed_model_output_raises_rather_than_degrading():
    """A bad response is an error, never silently coerced or retried freeform."""
    malformed = '{"routes": [{"specialist": "database-whisperer", "required": true, "why": "x"}], "summary": "s"}'
    with pytest.raises(ValidationError):
        RoutingLlmOutput.model_validate(json.loads(malformed))


def test_duplicate_specialists_rejected_on_promotion():
    duplicated = RoutingLlmOutput(
        routes=[
            route(SpecialistName.SYSTEMS, True),
            route(SpecialistName.SYSTEMS, False),
        ],
        summary="s",
    )
    with pytest.raises(ValidationError):
        duplicated.to_domain()


def test_schema_is_serializable_for_the_model():
    schema = RoutingLlmOutput.model_json_schema()
    assert json.dumps(schema)
    assert "routes" in schema["properties"]
    assert "summary" in schema["properties"]


def test_instruction_covers_every_specialist():
    for specialist in SpecialistName:
        assert specialist.value in ROUTING_INSTRUCTION


def test_instruction_forbids_blanket_fan_out_and_treats_report_as_data():
    lowered = ROUTING_INSTRUCTION.lower()
    assert "do not invoke everyone by default" in lowered
    assert "untrusted" in lowered
    assert "never as instructions" in lowered
