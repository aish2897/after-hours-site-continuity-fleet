from __future__ import annotations

from scf.models import ActionRequest, Decision, PolicyDecision


class PolicyEngine:
    def evaluate(
        self,
        action: ActionRequest,
        evidence: dict[str, object],
    ) -> PolicyDecision:
        if evidence.get("prompt_injection_detected") is True:
            return PolicyDecision(
                decision=Decision.DENIED,
                reason="Untrusted incident content contains prompt-injection markers.",
            )

        if action.action == "export_credentials":
            return PolicyDecision(
                decision=Decision.DENIED,
                reason="Credential export is never allowed.",
            )

        if action.action == "disable_firewall":
            return PolicyDecision(
                decision=Decision.DENIED,
                reason="Firewall disabling is outside autonomous authority.",
            )

        if action.action == "restart_database_service":
            return PolicyDecision(
                decision=Decision.APPROVAL_REQUIRED,
                reason="Production database restart requires human approval.",
                required_approval_role="incident_commander",
            )

        if action.action == "restart_application_service":
            required = {
                "service_stopped": True,
                "server_reachable": True,
                "prompt_injection_detected": False,
            }
            missing = [
                key for key, expected in required.items() if evidence.get(key) != expected
            ]
            if missing:
                return PolicyDecision(
                    decision=Decision.DENIED,
                    reason=f"Missing required evidence for auto remediation: {missing}",
                )
            return PolicyDecision(
                decision=Decision.AUTO_ALLOWED,
                reason="Low-risk restart allowed for stopped non-critical web service.",
            )

        return PolicyDecision(
            decision=Decision.DENIED,
            reason=f"Unknown or unsupported action: {action.action}",
        )

