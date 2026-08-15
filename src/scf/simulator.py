from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any


class PermissionDenied(RuntimeError):
    pass


@dataclass
class Service:
    name: str
    target_type: str
    running: bool
    http_status: int | None = None
    response_ms: int | None = None


@dataclass
class SyntheticSite:
    site_id: str = "MEL-WAREHOUSE-01"
    profile: dict[str, Any] = field(
        default_factory=lambda: {
            "name": "Melbourne West Distribution Site",
            "business_function": "after-hours dispatch",
            "criticality": "high",
            "users_impacted": 42,
        }
    )
    network: dict[str, Any] = field(
        default_factory=lambda: {
            "wan_up": True,
            "gateway_reachable": True,
            "dns_ok": True,
            "packet_loss_percent": 0,
        }
    )
    services: dict[str, Service] = field(
        default_factory=lambda: {
            "dispatch-web": Service(
                name="dispatch-web",
                target_type="non_critical_web_service",
                running=False,
                http_status=503,
                response_ms=None,
            ),
            "dispatch-db": Service(
                name="dispatch-db",
                target_type="production_database",
                running=True,
            ),
        }
    )
    change_log: list[dict[str, Any]] = field(default_factory=list)
    security_events: list[dict[str, Any]] = field(default_factory=list)


class SyntheticEnterprise:
    """A deterministic enterprise simulator for repeatable judging demos."""

    def __init__(self) -> None:
        self.site = SyntheticSite()
        self._executed_idempotency_keys: set[str] = set()

    def clone(self) -> "SyntheticEnterprise":
        cloned = SyntheticEnterprise()
        cloned.site = deepcopy(self.site)
        cloned._executed_idempotency_keys = set(self._executed_idempotency_keys)
        return cloned

    def read_site_profile(self, site_id: str) -> dict[str, Any]:
        self._assert_site(site_id)
        return deepcopy(self.site.profile)

    def read_network_status(self, site_id: str) -> dict[str, Any]:
        self._assert_site(site_id)
        return deepcopy(self.site.network)

    def read_change_log(self, site_id: str) -> list[dict[str, Any]]:
        self._assert_site(site_id)
        return deepcopy(self.site.change_log)

    def read_security_events(self, site_id: str) -> list[dict[str, Any]]:
        self._assert_site(site_id)
        return deepcopy(self.site.security_events)

    def read_service_status(self, site_id: str, service_name: str) -> dict[str, Any]:
        self._assert_site(site_id)
        service = self._service(service_name)
        return {
            "service": service.name,
            "target_type": service.target_type,
            "running": service.running,
            "http_status": service.http_status,
            "response_ms": service.response_ms,
        }

    def read_http_health(self, site_id: str, service_name: str) -> dict[str, Any]:
        status = self.read_service_status(site_id, service_name)
        return {
            "service": service_name,
            "healthy": status["running"] and status["http_status"] == 200,
            "http_status": status["http_status"],
            "response_ms": status["response_ms"],
        }

    def restart_application_service(
        self,
        *,
        actor_identity: str,
        site_id: str,
        service_name: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._assert_site(site_id)
        if actor_identity != "agent:remediation":
            raise PermissionDenied(
                f"PERMISSION_DENIED: {actor_identity} cannot restart services"
            )
        if idempotency_key in self._executed_idempotency_keys:
            return {"changed": False, "reason": "duplicate_idempotency_key"}

        service = self._service(service_name)
        service.running = True
        service.http_status = 200
        service.response_ms = 143
        self._executed_idempotency_keys.add(idempotency_key)
        return {"changed": True, "service": service_name, "http_status": 200}

    def disable_firewall(self, *, actor_identity: str) -> None:
        raise PermissionDenied(
            f"PERMISSION_DENIED: {actor_identity} cannot disable firewall controls"
        )

    def require_database_restart(self) -> None:
        service = self._service("dispatch-db")
        service.running = False

    def _assert_site(self, site_id: str) -> None:
        if site_id != self.site.site_id:
            raise KeyError(f"unknown synthetic site: {site_id}")

    def _service(self, service_name: str) -> Service:
        try:
            return self.site.services[service_name]
        except KeyError as exc:
            raise KeyError(f"unknown synthetic service: {service_name}") from exc

