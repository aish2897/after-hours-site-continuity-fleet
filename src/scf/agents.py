from __future__ import annotations

from scf.models import ActionRequest, Evidence, IncidentState
from scf.security import detect_prompt_injection
from scf.simulator import SyntheticEnterprise


class ContextAgent:
    name = "context"

    def collect(self, state: IncidentState, enterprise: SyntheticEnterprise) -> None:
        profile = enterprise.read_site_profile(state.report.site_id)
        state.add_evidence(
            Evidence(
                source_agent=self.name,
                key="site_profile",
                value=profile,
                supports="site criticality and business impact",
            )
        )
        state.add_evidence(
            Evidence(
                source_agent=self.name,
                key="recent_change_count",
                value=len(enterprise.read_change_log(state.report.site_id)),
                supports="change-related root cause check",
            )
        )
        state.add_audit(self.name, "context_collected", site=profile["name"])


class NetworkAgent:
    name = "network"

    def collect(self, state: IncidentState, enterprise: SyntheticEnterprise) -> None:
        network = enterprise.read_network_status(state.report.site_id)
        state.add_evidence(
            Evidence(
                source_agent=self.name,
                key="server_reachable",
                value=network["wan_up"] and network["gateway_reachable"],
                supports="whether systems remediation is plausible",
            )
        )
        state.add_evidence(
            Evidence(
                source_agent=self.name,
                key="dns_ok",
                value=network["dns_ok"],
                supports="network and DNS health",
            )
        )
        state.add_audit(self.name, "network_checked", **network)


class SystemsAgent:
    name = "systems"

    def collect_and_propose(
        self,
        state: IncidentState,
        enterprise: SyntheticEnterprise,
        service_name: str = "dispatch-web",
    ) -> None:
        status = enterprise.read_service_status(state.report.site_id, service_name)
        service_stopped = not status["running"]
        state.add_evidence(
            Evidence(
                source_agent=self.name,
                key="service_stopped",
                value=service_stopped,
                supports="service restart eligibility",
            )
        )
        state.add_evidence(
            Evidence(
                source_agent=self.name,
                key="service_status",
                value=status,
                supports="root cause and verification baseline",
            )
        )
        if service_stopped:
            state.requested_action = ActionRequest(
                action="restart_application_service",
                target=service_name,
                target_type=status["target_type"],
                requested_by=f"agent:{self.name}",
                evidence_keys=("service_stopped", "server_reachable", "no_prompt_injection"),
            )
        state.add_audit(self.name, "systems_checked", service=service_name, stopped=service_stopped)


class SecurityAgent:
    name = "security"

    def collect(self, state: IncidentState, enterprise: SyntheticEnterprise) -> None:
        detected = detect_prompt_injection(state.report.description)
        state.add_evidence(
            Evidence(
                source_agent=self.name,
                key="prompt_injection_detected",
                value=detected,
                supports="untrusted incident text screening",
            )
        )
        state.add_evidence(
            Evidence(
                source_agent=self.name,
                key="security_event_count",
                value=len(enterprise.read_security_events(state.report.site_id)),
                supports="security context",
            )
        )
        if detected:
            state.requested_action = ActionRequest(
                action="export_credentials",
                target="credential-store",
                target_type="secret",
                requested_by=f"agent:{self.name}",
                evidence_keys=("prompt_injection_detected",),
            )
        state.add_audit(self.name, "security_screened", prompt_injection_detected=detected)

