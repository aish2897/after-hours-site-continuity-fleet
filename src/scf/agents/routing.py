from __future__ import annotations

import json
import os
from typing import Final

from google.adk.agents import LlmAgent
from google.adk.runners import InMemoryRunner
from google.genai import types
from pydantic import ValidationError

from scf import config, faults
from scf.agents.schemas import ROUTING_INSTRUCTION, RoutingLlmOutput
from scf.domain.models import RoutingDecision

APP_NAME = "scf-orchestrator"


def configure_vertex_env() -> None:
    """Point the GenAI SDK at Vertex and the approved inference location.

    Uses Application Default Credentials. No API key is read or set.
    """
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "TRUE"
    os.environ["GOOGLE_CLOUD_PROJECT"] = config.PROJECT_ID
    os.environ["GOOGLE_CLOUD_LOCATION"] = config.MODEL_LOCATION


def build_routing_agent() -> LlmAgent:
    """Smallest real ADK agent: constrained routing, no tools, typed output."""
    configure_vertex_env()
    return LlmAgent(
        name="orchestrator_router",
        model=config.model_verified_id(),
        instruction=ROUTING_INSTRUCTION,
        output_schema=RoutingLlmOutput,
        output_key="routing_decision",
        generate_content_config=types.GenerateContentConfig(
            temperature=0.1,
            max_output_tokens=config.DEFAULT_MAX_OUTPUT_TOKENS,
        ),
    )


#: Retry budget for model output. Zero, deliberately.
#:
#: A model that emitted unparseable structure once will happily do it again,
#: and each attempt costs an outage more time. There is no back-off loop, no
#: "ask it to try again in JSON", and no freeform salvage: a response that does
#: not satisfy the typed contract is a categorised failure with a human
#: handover, not a prompt to keep going.
MODEL_PARSE_RETRIES: Final[int] = 0


class ModelContractError(RuntimeError):
    """The model's output did not satisfy the typed routing contract."""


def _injected_payload() -> str | None:
    """TEST ONLY. Model-equivalent payloads, fed through the REAL parser.

    Reads only the process fault mode — never a request, never report text.
    The value returned here goes through exactly the same validation as a live
    model response, which is the point: the parser boundary is what is on test.
    """
    if faults.is_mode(faults.ROUTING_MALFORMED_JSON):
        return '{"routes": [{"specialist": "systems", "required": true,'  # truncated
    if faults.is_mode(faults.ROUTING_SCHEMA_INVALID):
        # Valid JSON, wrong shape: no summary, routes is not a list.
        return '{"routes": "everything looks fine to me"}'
    if faults.is_mode(faults.ROUTING_UNKNOWN_SPECIALIST):
        # Valid JSON, right shape, specialist outside the closed enum.
        return (
            '{"routes": [{"specialist": "database_wizard", "required": true, '
            '"why": "FAULT INJECTION"}], "summary": "FAULT INJECTION"}'
        )
    return None


async def route_incident(report_text: str) -> RoutingDecision:
    """Run the ADK agent and promote its output into the domain contract.

    The report is passed as untrusted data. A response that does not satisfy
    RoutingLlmOutput raises rather than being retried as freeform text.
    """
    injected = _injected_payload()
    if injected is not None:
        return _parse(injected)

    agent = build_routing_agent()
    runner = InMemoryRunner(agent=agent, app_name=APP_NAME)
    session = await runner.session_service.create_session(
        app_name=APP_NAME, user_id="duty-manager"
    )

    message = types.Content(
        role="user",
        parts=[types.Part(text=f"<untrusted_incident_report>\n{report_text}\n</untrusted_incident_report>")],
    )

    payload: str | None = None
    async for event in runner.run_async(
        user_id="duty-manager", session_id=session.id, new_message=message
    ):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    payload = part.text

    if payload is None:
        raise ModelContractError("the model returned no content")

    return _parse(payload)


def _parse(payload: str) -> RoutingDecision:
    """The one place model output becomes a domain object.

    Every rejection is the same kind of event regardless of how the output was
    wrong — unparseable, wrong shape, or naming a specialist that does not
    exist. None of them is retried.
    """
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ModelContractError(f"model output is not valid JSON: {exc.msg}") from exc
    try:
        parsed = RoutingLlmOutput.model_validate(decoded)
    except ValidationError as exc:
        raise ModelContractError(
            f"model output does not satisfy the routing contract "
            f"({exc.error_count()} violation(s))"
        ) from exc
    return parsed.to_domain(model_id=config.model_verified_id())
