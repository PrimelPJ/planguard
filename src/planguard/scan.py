"""Run the rules on a plan and apply waivers from the config file."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from datetime import date
from fnmatch import fnmatch
from pathlib import Path

from .plan import Plan
from .rules import RULES, SEVERITIES, Rule


DEFAULT_MIN_SEVERITY = "low"


class ConfigError(Exception):
    """The config file has a mistake in it."""


@dataclass
class Waiver:
    """An accepted risk: we know about this problem and chose to live with it for now."""

    rule: str  # rule id, wildcards allowed (PG00*)
    resource: str  # resource address, wildcards allowed (module.dev.*)
    reason: str
    expires: date
    owner: str = ""
    used: bool = False

    def matches(self, finding: "Finding") -> bool:
        return fnmatch(finding.rule.id, self.rule) and fnmatch(finding.resource, self.resource)

    def expired(self, today: date) -> bool:
        return self.expires < today


@dataclass
class Config:
    skip_rules: set[str] = field(default_factory=set)
    waivers: list[Waiver] = field(default_factory=list)


@dataclass
class Finding:
    rule: Rule
    resource: str
    message: str
    waiver: Waiver | None = None

    @property
    def active(self) -> bool:
        return self.waiver is None


@dataclass
class Result:
    plan: Plan
    rules: list[Rule]
    findings: list[Finding]
    expired_waivers: list[Waiver]
    unused_waivers: list[Waiver]

    @property
    def active(self) -> list[Finding]:
        return [f for f in self.findings if f.active]

    @property
    def waived(self) -> list[Finding]:
        return [f for f in self.findings if not f.active]

    def count(self, severity: str) -> int:
        return sum(1 for f in self.active if f.rule.severity == severity)


def load_config(path: str | Path) -> Config:
    path = Path(path)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}") from None
    except tomllib.TOMLDecodeError as err:
        raise ConfigError(f"{path}: {err}") from None

    known = {r.id for r in RULES}
    skip = set(data.get("skip_rules", []))
    unknown = skip - known
    if unknown:
        raise ConfigError(f"{path}: skip_rules has unknown rule ids: {', '.join(sorted(unknown))}")

    waivers = []
    for i, raw in enumerate(data.get("waiver", []), start=1):
        where = f"{path}: waiver #{i}"
        for key in ("rule", "resource", "reason", "expires"):
            if not raw.get(key):
                raise ConfigError(f"{where} is missing '{key}'. Every waiver needs a rule, resource, reason and end date.")
        expires = raw["expires"]
        if isinstance(expires, str):
            try:
                expires = date.fromisoformat(expires)
            except ValueError:
                raise ConfigError(f"{where}: expires must be a date like 2026-12-31") from None
        if not isinstance(expires, date):
            raise ConfigError(f"{where}: expires must be a date like 2026-12-31")
        waivers.append(Waiver(raw["rule"], raw["resource"], raw["reason"].strip(), expires, raw.get("owner", "")))
    return Config(skip_rules=skip, waivers=waivers)


def scan(
    plan: Plan,
    config: Config | None = None,
    min_severity: str = DEFAULT_MIN_SEVERITY,
    clouds: set[str] | None = None,
    today: date | None = None,
) -> Result:
    config = config or Config()
    today = today or date.today()
    floor = SEVERITIES.index(min_severity)

    rules = [
        r
        for r in RULES
        if r.id not in config.skip_rules and r.rank >= floor and (not clouds or r.cloud in clouds)
    ]

    findings = []
    for r in rules:
        seen = set()
        for resource, message in r.check(plan):
            key = (resource.address, message)
            if key not in seen:  # one resource can trip the same check twice
                seen.add(key)
                findings.append(Finding(r, resource.address, message))

    for w in config.waivers:
        w.used = False

    expired: list[Waiver] = []
    for f in findings:
        for w in config.waivers:
            if not w.matches(f):
                continue
            w.used = True
            if w.expired(today):
                if w not in expired:
                    expired.append(w)
                continue
            f.waiver = w
            break

    findings.sort(key=lambda f: (-f.rule.rank, f.rule.id, f.resource))
    unused = [w for w in config.waivers if not w.used]
    return Result(plan, rules, findings, expired, unused)
