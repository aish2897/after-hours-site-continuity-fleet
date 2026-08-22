"""Fire one incident at the deployed orchestrator and print only what matters.

A demo harness, not part of the fleet. It holds no authority: it posts a report
the way a duty manager would and reads the response back. Keeping it out of
`src/` is deliberate — nothing here may become a code path the system depends on.

    python tools/probe_incident.py "<report text>" [--label NAME]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request


def _run(cmd: list[str]) -> str:
    # `gcloud` is a .cmd shim on Windows, so it needs the shell to resolve.
    out = subprocess.run(" ".join(cmd), capture_output=True, text=True, shell=True)
    return out.stdout.strip().splitlines()[-1] if out.stdout.strip() else ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("description")
    parser.add_argument("--label", default="")
    parser.add_argument("--json", action="store_true", help="dump the whole body")
    args = parser.parse_args()

    url = os.environ.get("SCF_ORCH_URL") or _run(
        ["gcloud", "run", "services", "describe", "scf-orchestrator",
         "--region=australia-southeast1", "--format=value(status.url)"])
    token = os.environ.get("SCF_ID_TOKEN") or _run(
        ["gcloud", "auth", "print-identity-token"])

    request = urllib.request.Request(
        f"{url}/incidents",
        data=json.dumps({"description": args.description}).encode(),
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            body = json.load(response)
    except urllib.error.HTTPError as err:
        print(f"HTTP {err.code}: {err.read()[:400].decode(errors='replace')}")
        return 1

    if args.json:
        print(json.dumps(body, indent=1))
        return 0

    remediation = body.get("remediation") or {}
    routes = body.get("routes") or []
    if args.label:
        print(f"### {args.label}")
    print(f"incident    {body.get('incident_id')}   {body.get('status')}")
    print(f"required    {body.get('required_specialists')}")
    for route in routes:
        mark = "YES" if route.get("required") else "no "
        print(f"  {mark} {route.get('specialist'):<11} {route.get('why', '')[:90]}")
    print(f"consulted   {remediation.get('specialists_consulted')}")
    if remediation.get("specialists_withheld_by_registry"):
        print(f"withheld    {remediation['specialists_withheld_by_registry']}")
    if remediation.get("secondary_delegation"):
        print(f"delegation  {json.dumps(remediation['secondary_delegation'])}")
    for key in ("proposal", "decision", "reason_code", "final_status",
                "mutated_infrastructure", "failure_category"):
        if key in remediation:
            print(f"{key:<11} {remediation[key]}")
    approval = remediation.get("approval") or {}
    if approval:
        print(f"approval    {approval.get('approval_id')} {approval.get('state')} "
              f"role={approval.get('required_approval_role')}")
    status = remediation.get("manager_status") or {}
    if status:
        print(f"manager     {status.get('headline')}")
        for line in status.get("what_we_found", []):
            print(f"            - {line}")
        print(f"            next: {status.get('what_happens_next')}")
        print(f"            who:  {status.get('who_checked')}")
    if body.get("screening"):
        print(f"screening   {json.dumps(body['screening'])[:200]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
