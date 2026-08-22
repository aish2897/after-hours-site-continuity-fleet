"""Network Investigator evidence. Read-only, and real.

This does not simulate a network. It resolves the target's hostname through the
system resolver, opens a TCP connection to it, completes a TLS handshake, and
measures how long each took — from a Cloud Run service in Sydney, over the
public internet, to the actual dispatch host.

Why that matters for this fleet: it is what separates "the site is unreachable"
from "the site is reachable and the application is broken". A duty manager
cannot tell those apart, and they lead to completely different work. Nothing
here can change anything; it only describes what the network looks like from
where this agent sits.
"""

from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse

from scf.domain.enums import TrustLevel
from scf.domain.models import Evidence

AGENT = "network"

#: Bounded like every other probe in this fleet. A hanging DNS lookup or a
#: half-open TCP connection must not become the caller's problem.
RESOLVE_TIMEOUT_SECONDS = 5.0
CONNECT_TIMEOUT_SECONDS = 5.0


def _ev(key: str, value: object, supports: str) -> Evidence:
    return Evidence(
        key=key,
        value=value,
        supports=supports,
        source_agent=AGENT,
        trust_level=TrustLevel.TRUSTED_TOOL,
    )


def _host_of(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or ""


def resolve(host: str) -> tuple[list[str], float, str | None]:
    """Resolve a hostname. Returns (addresses, ms, error)."""
    started = time.perf_counter()
    try:
        socket.setdefaulttimeout(RESOLVE_TIMEOUT_SECONDS)
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        addresses = sorted({info[4][0] for info in infos})
        return addresses, (time.perf_counter() - started) * 1000, None
    except socket.gaierror as exc:
        # The distinctive failure: a name that does not resolve. This is the
        # signature of the DNS outage a manager describes as "the site is gone".
        return [], (time.perf_counter() - started) * 1000, f"dns_error:{exc.errno}"
    except OSError as exc:
        return [], (time.perf_counter() - started) * 1000, f"resolve_failed:{type(exc).__name__}"


def tcp_and_tls(host: str, port: int = 443) -> tuple[bool, bool, float, str | None]:
    """(tcp_open, tls_ok, ms, error) — connection reachability, not app health."""
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_SECONDS) as raw:
            tcp_ms = (time.perf_counter() - started) * 1000
            context = ssl.create_default_context()
            try:
                with context.wrap_socket(raw, server_hostname=host):
                    return True, True, tcp_ms, None
            except ssl.SSLError as exc:
                return True, False, tcp_ms, f"tls_error:{type(exc).__name__}"
    except OSError as exc:
        return False, False, (time.perf_counter() - started) * 1000, (
            f"tcp_error:{type(exc).__name__}"
        )


def gather_evidence(target_url: str) -> list[Evidence]:
    """Connectivity facts about the target, from this agent's vantage point.

    Deliberately says nothing about whether the application is working. A
    perfectly reachable host serving HTTP 503 produces `network_reachable=True`
    here, and that combination is exactly what tells the orchestrator the
    problem belongs to Systems rather than to the network.
    """
    host = _host_of(target_url)
    addresses, resolve_ms, resolve_error = resolve(host)
    resolved = bool(addresses)

    if resolved:
        tcp_open, tls_ok, connect_ms, connect_error = tcp_and_tls(host)
    else:
        tcp_open, tls_ok, connect_ms, connect_error = False, False, 0.0, "not_resolved"

    return [
        _ev("network_target_host", host, "the hostname this agent tested"),
        _ev("dns_resolves", resolved, "whether the name resolves at all"),
        _ev("dns_addresses", addresses[:4], "addresses returned by the resolver"),
        _ev("dns_latency_ms", round(resolve_ms, 1), "how long resolution took"),
        _ev("dns_error", resolve_error, "resolver error, if any"),
        _ev("tcp_connect_ok", tcp_open, "whether a TCP connection could be opened"),
        _ev("tls_handshake_ok", tls_ok, "whether TLS completed"),
        _ev("connect_latency_ms", round(connect_ms, 1), "time to connect"),
        _ev("connect_error", connect_error, "connection error, if any"),
        # The load-bearing conclusion, and the only one the orchestrator reads
        # when deciding whether another specialist is needed.
        _ev(
            "network_reachable",
            bool(resolved and tcp_open and tls_ok),
            "name resolves, TCP connects and TLS completes — says nothing about "
            "whether the application behind it is healthy",
        ),
    ]
