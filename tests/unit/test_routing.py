from __future__ import annotations

import pytest
from pydantic import ValidationError

from scf.domain.enums import SpecialistName
from scf.domain.models import RoutingDecision, SpecialistRoute


def route(specialist, required, why="because"):
    return SpecialistRoute(specialist=specialist, required=required, why=why)


def test_slice_one_routes_to_systems_only():
    """Evidence-dependent delegation: not every investigator is invoked."""
    decision = RoutingDecision(
        routes=[
            route(SpecialistName.SYSTEMS, True, "Kiosk reports an HTTP error page."),
            route(SpecialistName.NETWORK, False, "Other sites on the same WAN are fine."),
            route(SpecialistName.SECURITY, False, "No auth failures in the report."),
            route(SpecialistName.CONTINUITY, False, "No vendor handoff needed yet."),
        ],
        summary="Application-layer symptom confined to one service.",
    )
    assert decision.required_specialists() == [SpecialistName.SYSTEMS]


def test_declining_a_specialist_is_still_a_recorded_decision():
    decision = RoutingDecision(
        routes=[
            route(SpecialistName.SYSTEMS, True, "service returns 503"),
            route(SpecialistName.NETWORK, False, "WAN healthy"),
        ]
    )
    declined = [r for r in decision.routes if not r.required]
    assert declined and all(r.why for r in declined)


def test_reason_is_mandatory_for_every_route():
    with pytest.raises(ValidationError):
        SpecialistRoute(specialist=SpecialistName.SYSTEMS, required=True, why="")


def test_specialist_names_are_a_closed_set():
    with pytest.raises(ValidationError):
        SpecialistRoute(specialist="database-whisperer", required=True, why="x")


def test_duplicate_specialists_are_rejected():
    with pytest.raises(ValidationError):
        RoutingDecision(
            routes=[
                route(SpecialistName.SYSTEMS, True),
                route(SpecialistName.SYSTEMS, False),
            ]
        )


def test_empty_routing_decision_is_rejected():
    with pytest.raises(ValidationError):
        RoutingDecision(routes=[])


def test_fan_out_to_all_specialists_is_permitted():
    decision = RoutingDecision(
        routes=[route(name, True, "site-wide outage") for name in SpecialistName]
    )
    assert len(decision.required_specialists()) == len(SpecialistName)
