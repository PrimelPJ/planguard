"""What a rule is, and the list every rule adds itself to."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from ..plan import Plan, Resource

SEVERITIES = ["low", "medium", "high", "critical"]

# Problems a check returns: the resource, and a short message about it.
Hit = tuple[Resource, str]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    cloud: str
    controls: tuple[str, ...]  # NIST SP 800-53 Rev. 5 controls this rule helps with
    risk: str  # what could go wrong, in plain words
    fix: str  # how to fix it
    check: Callable[[Plan], Iterable[Hit]]

    @property
    def rank(self) -> int:
        return SEVERITIES.index(self.severity)


RULES: list[Rule] = []


def rule(id: str, title: str, severity: str, cloud: str, controls: list[str], risk: str, fix: str):
    """Decorator that registers a check function as a rule."""
    if severity not in SEVERITIES:
        raise ValueError(f"{id}: unknown severity {severity!r}")

    def wrap(fn: Callable[[Plan], Iterable[Hit]]):
        if any(r.id == id for r in RULES):
            raise ValueError(f"rule id {id} is used twice")
        RULES.append(Rule(id, title, severity, cloud, tuple(controls), risk, fix, fn))
        return fn

    return wrap


# ---- small helpers shared by the AWS and Azure rules ----

INTERNET = {"0.0.0.0/0", "::/0", "*", "internet", "any"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}


def is_internet(source: object) -> bool:
    return isinstance(source, str) and source.strip().lower() in INTERNET


def parse_ports(spec: object) -> tuple[int, int] | None:
    """Turn "22", "20-25", "*" or 22 into (low, high). Returns None if unclear."""
    if isinstance(spec, int):
        return spec, spec
    if not isinstance(spec, str) or not spec.strip():
        return None
    spec = spec.strip()
    if spec == "*":
        return 0, 65535
    if "-" in spec:
        low, _, high = spec.partition("-")
        if low.strip().isdigit() and high.strip().isdigit():
            return int(low), int(high)
        return None
    return (int(spec), int(spec)) if spec.isdigit() else None


def admin_ports_in(low: int, high: int) -> list[str]:
    """Which admin ports (SSH, RDP) fall inside low..high."""
    return [f"{label} (port {port})" for port, label in ADMIN_PORTS.items() if low <= port <= high]


# CIS Benchmark severity mapping for scan findings.
# Maps rule categories to severity levels for prioritised reporting.
SEVERITY_LEVELS = {
    "public_access": "CRITICAL",
    "encryption_disabled": "HIGH",
    "logging_disabled": "HIGH",
    "open_security_group": "CRITICAL",
    "untagged_resource": "MEDIUM",
    "overprivileged_iam": "HIGH",
    "missing_mfa": "CRITICAL",
    "default_vpc_in_use": "LOW",
    "outdated_tls": "HIGH",
    "unrestricted_egress": "MEDIUM",
}

# Exit codes for CI/CD integration.
EXIT_CLEAN = 0
EXIT_WARNINGS = 1
EXIT_CRITICAL = 2
