"""Single entrypoint that selects a runtime by SCF_ROLE.

One source tree, seven Cloud Run services, seven distinct service accounts. The
role only chooses which FastAPI app is served; it grants nothing. Authority
comes from the runtime identity Cloud Run attaches, not from this variable.
"""

from __future__ import annotations

import os

SCF_ROLE = os.environ.get("SCF_ROLE", "orchestrator").strip().lower()

if SCF_ROLE == "investigator":
    from scf.app.investigator import app
elif SCF_ROLE == "network":
    from scf.app.specialists import network_app as app
elif SCF_ROLE == "security":
    from scf.app.specialists import security_app as app
elif SCF_ROLE == "continuity":
    from scf.app.continuity import app
elif SCF_ROLE == "approval":
    from scf.app.approval import app
elif SCF_ROLE == "executor":
    from scf.app.executor import app
elif SCF_ROLE == "verifier":
    from scf.app.verifier import app
else:
    from scf.app.main import app

__all__ = ["app", "SCF_ROLE"]
