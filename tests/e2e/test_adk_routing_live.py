"""Live ADK + Vertex checks. Skipped unless SCF_LIVE=1.

    $env:SCF_LIVE=1; .\\.venv\\Scripts\\python.exe -m pytest tests/e2e -q

Requires Application Default Credentials. Costs real tokens.
"""

from __future__ import annotations

import os

import pytest

from scf.domain.enums import SpecialistName

pytestmark = pytest.mark.skipif(
    os.environ.get("SCF_LIVE") != "1", reason="live Vertex call; set SCF_LIVE=1"
)

APPLICATION_SYMPTOM = (
    "Night duty manager at the Melbourne West site. The dispatch screens in the "
    "loading bay are showing an error page and drivers cannot print run sheets. "
    "Phones and wifi are fine. Nobody has touched anything tonight."
)


@pytest.mark.asyncio
async def test_application_symptom_routes_to_systems_only():
    from scf.agents.routing import route_incident

    decision = await route_incident(APPLICATION_SYMPTOM)

    assert SpecialistName.SYSTEMS in decision.required_specialists()
    assert SpecialistName.NETWORK not in decision.required_specialists()
    assert len(decision.routes) == len(SpecialistName)
    assert all(route.why for route in decision.routes)
    assert decision.summary


@pytest.mark.asyncio
async def test_every_specialist_is_reasoned_about():
    from scf.agents.routing import route_incident

    decision = await route_incident(APPLICATION_SYMPTOM)
    considered = {route.specialist for route in decision.routes}
    assert considered == set(SpecialistName)
