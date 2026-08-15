from __future__ import annotations

from scf.agents import ContextAgent, NetworkAgent, SecurityAgent, SystemsAgent
from scf.models import Decision, IncidentReport, IncidentState, IncidentStatus
from scf.policy import PolicyEngine
from scf.simulator import PermissionDenied, SyntheticEnterprise


class SiteContinuityWorkflow:
    def __init__(self, enterprise: SyntheticEnterprise | None = None) -> None:
        self.enterprise = enterprise or SyntheticEnterprise()
        self.context_agent = ContextAgent()
        self.network_agent = NetworkAgent()
        self.systems_agent = SystemsAgent()
        self.security_agent = SecurityAgent()
        self.policy = PolicyEngine()

    def run_web_down(self, report: IncidentReport) -> IncidentState:
        state = IncidentState(report=report)
        state.add_audit("orchestrator", "incident_received", incident_id=report.incident_id)

        self.context_agent.collect(state, self.enterprise)
        self.network_agent.collect(state, self.enterprise)
        self.systems_agent.collect_and_propose(state, self.enterprise, "dispatch-web")
        self.security_agent.collect(state, self.enterprise)

        self._evaluate_and_execute(state)
        return state

    def run_database_restart(self, report: IncidentReport) -> IncidentState:
        state = IncidentState(report=report)
        state.add_audit("orchestrator", "incident_received", incident_id=report.incident_id)
        self.enterprise.require_database_restart()
        self.context_agent.collect(state, self.enterprise)
        self.network_agent.collect(state, self.enterprise)
        self.security_agent.collect(state, self.enterprise)
        state.requested_action = self._database_restart_request(state)
        self._evaluate_and_execute(state)
        return state

    def run_prompt_injection(self, report: IncidentReport) -> IncidentState:
        state = IncidentState(report=report)
        state.add_audit("orchestrator", "incident_received", incident_id=report.incident_id)
        self.context_agent.collect(state, self.enterprise)
        self.network_agent.collect(state, self.enterprise)
        self.security_agent.collect(state, self.enterprise)
        self._evaluate_and_execute(state)
        return state

    def prove_permission_denied(self) -> str:
        try:
            self.enterprise.disable_firewall(actor_identity="agent:network")
        except PermissionDenied as exc:
            return str(exc)
        raise AssertionError("network agent unexpectedly disabled firewall")

    def _evaluate_and_execute(self, state: IncidentState) -> None:
        if state.requested_action is None:
            state.status = IncidentStatus.ESCALATED
            state.add_audit("orchestrator", "no_action_available")
            return

        decision = self.policy.evaluate(state.requested_action, state.evidence_map())
        state.policy_decision = decision
        state.add_audit(
            "policy",
            "policy_decision",
            action=state.requested_action.action,
            decision=decision.decision,
            reason=decision.reason,
        )

        if decision.decision == Decision.DENIED:
            state.status = IncidentStatus.DENIED
            state.add_audit("orchestrator", "workflow_denied", reason=decision.reason)
            return

        if decision.decision == Decision.APPROVAL_REQUIRED:
            state.status = IncidentStatus.WAITING_FOR_APPROVAL
            state.add_audit(
                "orchestrator",
                "waiting_for_approval",
                required_role=decision.required_approval_role,
            )
            return

        action = state.requested_action
        result = self.enterprise.restart_application_service(
            actor_identity="agent:remediation",
            site_id=state.report.site_id,
            service_name=action.target,
            idempotency_key=action.idempotency_key,
        )
        state.add_audit(
            "remediation",
            "action_executed",
            action_id=action.action_id,
            idempotency_key=action.idempotency_key,
            result=result,
        )
        health = self.enterprise.read_http_health(state.report.site_id, action.target)
        state.add_audit("verification", "post_action_health_check", **health)
        state.status = IncidentStatus.RESOLVED if health["healthy"] else IncidentStatus.ESCALATED

    @staticmethod
    def _database_restart_request(state: IncidentState):
        from scf.models import ActionRequest

        return ActionRequest(
            action="restart_database_service",
            target="dispatch-db",
            target_type="production_database",
            requested_by="agent:systems",
            evidence_keys=("database_unavailable", "server_reachable"),
        )

