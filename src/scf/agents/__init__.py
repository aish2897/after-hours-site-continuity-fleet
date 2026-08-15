"""ADK agents. LLM-backed, propose-only, no authorization authority."""

from scf.agents.schemas import ROUTING_INSTRUCTION, RoutingLlmOutput

__all__ = ["ROUTING_INSTRUCTION", "RoutingLlmOutput", "build_routing_agent", "route_incident"]


def __getattr__(name: str):
    # Defer the google.adk import so schema-only tests do not require the SDK.
    if name in {"build_routing_agent", "route_incident"}:
        from scf.agents import routing

        return getattr(routing, name)
    raise AttributeError(name)
