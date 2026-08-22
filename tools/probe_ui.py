"""Submit an incident through the deployed Director console, as the browser does.

Same endpoint, same shape, same identity token. This is the browser path, not a
backend shortcut — if it works here it works when a person clicks the button.

    python tools/probe_ui.py "<report>" [--image path] [--label NAME]
"""

from __future__ import annotations

import argparse
import base64
import json
import mimetypes
import os
import sys
import urllib.error
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("description")
    parser.add_argument("--image", default="")
    parser.add_argument("--label", default="")
    parser.add_argument("--raw", action="store_true")
    args = parser.parse_args()

    ui = os.environ["SCF_UI_URL"].rstrip("/")
    token = os.environ["SCF_ID_TOKEN"]

    payload: dict[str, object] = {"description": args.description}
    if args.image:
        data = open(args.image, "rb").read()
        payload["image_base64"] = base64.b64encode(data).decode()
        payload["image_media_type"] = mimetypes.guess_type(args.image)[0] or "image/png"

    request = urllib.request.Request(
        f"{ui}/api/incidents",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            body = json.load(response)
    except urllib.error.HTTPError as err:
        print(f"HTTP {err.code}: {err.read()[:300].decode(errors='replace')}")
        return 1

    if args.raw:
        print(json.dumps(body, indent=1))
        return 0

    remediation = body.get("remediation") or {}
    if args.label:
        print(f"### {args.label}")
    print(f"incident    {body['incident_id']}   {body['status']}")
    print(f"image sent  {body.get('image_attached')}")
    if body.get("observed_text"):
        print(f"read from image  {body['observed_text'][:150]!r}")
    print(f"required    {body['required_specialists']}")
    for route in body.get("routes", []):
        mark = "YES" if route["required"] else "no "
        print(f"  {mark} {route['specialist']:<11} {route['why'][:78]}")
    print(f"consulted   {remediation.get('specialists_consulted')}")
    for key in ("decision", "reason_code", "failure_category",
                "mutated_infrastructure", "final_status"):
        if key in remediation:
            print(f"{key:<11} {remediation[key]}")
    if body.get("screening"):
        print(f"screening   {json.dumps(body['screening'])[:160]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
