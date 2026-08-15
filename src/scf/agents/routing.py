from __future__ import annotations

import json
import os

from google.adk.agents import LlmAgent
from google.adk.runners import InMemoryRunner
from google.genai import types

from scf import config
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


async def route_incident(report_text: str) -> RoutingDecision:
    """Run the ADK agent and promote its output into the domain contract.

    The report is passed as untrusted data. A response that does not satisfy
    RoutingLlmOutput raises rather than being retried as freeform text.
    """
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
        raise RuntimeError("ADK agent returned no content")

    parsed = RoutingLlmOutput.model_validate(json.loads(payload))
    return parsed.to_domain(model_id=config.model_verified_id())
