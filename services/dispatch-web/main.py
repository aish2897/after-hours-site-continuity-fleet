"""Synthetic site dispatch application — the real remediation target.

Health is decided by the SERVICE_MODE environment variable, which is baked
into a Cloud Run revision at deploy time. Health therefore belongs to the
revision itself, not to any in-memory flag an orchestrator could flip. The
only way to change what this service returns is a genuine Cloud Run traffic
migration between revisions.

Standard library only, so the buildpack has nothing to install.
"""

from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVICE_MODE = os.environ.get("SERVICE_MODE", "healthy").strip().lower()
REVISION = os.environ.get("K_REVISION", "local")

HEALTHY_BODY = b"dispatch service healthy\n"
BROKEN_BODY = b"dispatch service unavailable\n"


class DispatchHandler(BaseHTTPRequestHandler):
    server_version = "dispatch-web"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if SERVICE_MODE == "broken":
            status, body = 503, BROKEN_BODY
        else:
            status, body = 200, HEALTHY_BODY

        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Service-Mode", SERVICE_MODE)
        self.send_header("X-Revision", REVISION)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"dispatch-web mode={SERVICE_MODE} revision={REVISION} {fmt % args}")


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer.allow_reuse_address = True
    with ThreadingHTTPServer(("", port), DispatchHandler) as httpd:
        print(f"dispatch-web listening on {port} mode={SERVICE_MODE}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
