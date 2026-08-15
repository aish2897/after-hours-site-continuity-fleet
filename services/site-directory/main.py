"""Unrelated Cloud Run service.

Exists solely to prove the Remediation Executor's blast radius is bounded to
dispatch-web. It is never a remediation target; attempting the same Cloud Run
administrative mutation against it must be refused by Google IAM.
"""

from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"site directory ok\n"


class DirectoryHandler(BaseHTTPRequestHandler):
    server_version = "site-directory"

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer.allow_reuse_address = True
    with ThreadingHTTPServer(("", port), DirectoryHandler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
