"""Gate A / ADK proof: run a real ADK agent against Gemini 3.7 Flash.

Writes sanitized evidence to docs/evidence/. Uses Application Default
Credentials; no API key and no service-account key file.

    .\\.venv\\Scripts\\python.exe tools\\gate_a_adk.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scf import config  # noqa: E402
from scf.agents.routing import route_incident  # noqa: E402

REPORT = (
    "Im the night duty manager at the Melbourne West site. The dispatch "
    "screens in the loading bay are all showing an error page and the drivers "
    "cant print run sheets. Phones and the wifi seem fine. Nobody has touched "
    "anything tonight."
)


async def main() -> int:
    started = datetime.now(timezone.utc)
    print(f"model:     {config.model_verified_id()}")
    print(f"location:  {config.MODEL_LOCATION}")
    print(f"project:   {config.PROJECT_ID}")
    print(f"started:   {started.isoformat()}")
    print("--- report (untrusted) ---")
    print(REPORT)

    decision = await route_incident(REPORT)

    print("--- routing decision (typed) ---")
    for route in decision.routes:
        mark = "REQUIRED" if route.required else "declined"
        print(f"  {route.specialist.value:<11} {mark:<9} {route.why}")
    print(f"summary:   {decision.summary}")
    print(f"model_id:  {decision.model_id}")
    required = [s.value for s in decision.required_specialists()]
    print(f"required:  {required}")

    out = {
        "model": config.model_verified_id(),
        "location": config.MODEL_LOCATION,
        "project": config.PROJECT_ID,
        "started_utc": started.isoformat(),
        "report": REPORT,
        "routes": [
            {"specialist": r.specialist.value, "required": r.required, "why": r.why}
            for r in decision.routes
        ],
        "summary": decision.summary,
        "required_specialists": required,
    }
    dest = Path(__file__).resolve().parents[1] / "docs" / "evidence" / "gate-a-adk-routing.json"
    dest.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"evidence:  {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
