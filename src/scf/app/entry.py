"""Single entrypoint that selects a runtime by SCF_ROLE.

One source tree, four Cloud Run services, four distinct service accounts. The
role only chooses which FastAPI app is served; it grants nothing. Authority
comes from the runtime identity Cloud Run attaches, not from this variable.
"""

from __future__ import annotations

import os

SCF_ROLE = os.environ.get("SCF_ROLE", "orchestrator").strip().lower()

if SCF_ROLE == "investigator":
    from scf.app.investigator import app
elif SCF_ROLE == "executor":
    from scf.app.executor import app
elif SCF_ROLE == "verifier":
    from scf.app.verifier import app
else:
    from scf.app.main import app

__all__ = ["app", "SCF_ROLE"]
